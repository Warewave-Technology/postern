// Package sshd implements the inbound (server-side) half of the bastion:
// listener, handshake, authentication and channel dispatch.
package sshd

import (
	"context"
	"errors"
	"fmt"
	"github.com/warewave/postern/internal/sshalg"
	"log/slog"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/ca"
	"github.com/warewave/postern/internal/config"
	"github.com/warewave/postern/internal/events"
	"github.com/warewave/postern/internal/proxy"
	"github.com/warewave/postern/internal/record"
	"github.com/warewave/postern/internal/store"
)

// oobTimeout, tarayıcı onayı için üst sınır. Çok kısa olursa insan
// yetişemez (telefonda MFA var), çok uzun olursa yarım denemeler handshake
// goroutine'lerini bekletir.
const oobTimeout = 2 * time.Minute

// Server accepts inbound SSH connections on behalf of the bastion.
type Server struct {
	cfg    *config.Config
	signer ssh.Signer // bastion'ın kendi host key'i
	logger *slog.Logger

	rStore *record.Store
	db     *store.Store

	authority *ca.CA

	// logins nil değilse keyboard-interactive OOB girişi açık: anahtarı
	// olmayan insanlar tarayıcıda OIDC ile girer. Public key yolu her
	// durumda çalışmaya devam eder (makineler/otomasyon).
	logins     *auth.Logins
	oobTimeout time.Duration

	// groups, OOB girişinde kullanılacak grup kaynağı. httpapi ile AYNI
	// olmalı: iki kapı aynı yetkiyi vermeli.
	groups auth.GroupSource

	// freshenRoles, oturum açılışında yetkiyi tazeleyen fonksiyon.
	// nil ise tazeleme yapılmaz (bkz. proxy.Deps.FreshenRoles).
	freshenRoles func(context.Context, string) error

	// bus nil ise canlı olay akışı kapalı.
	bus events.Publisher

	// limiter, eşzamanlı bağlantı sınırları (limits.go).
	limiter *connLimiter

	// Çözülmüş sınır değerleri. Config'te 0 "varsayılan" demek olduğu
	// için ham değeri değil çözüleni saklıyoruz.
	handshakeTimeout time.Duration
	maxAuthTries     int
	maxChannels      int

	// publicKeyLogin, anahtarla girişin açık olup olmadığı
	// (auth.public_key_login). Kapalıysa PublicKeyCallback hiç
	// kurulmuyor — bkz. serverConfig.
	publicKeyLogin bool
}

// Records, kayıt deposunu döner.
//
// httpapi ile PAYLAŞILIR: panel kayıtları AYNI depodan okumalı, yoksa
// "hangi dizin" sorusunun iki cevabı olur.
func (s *Server) Records() *record.Store { return s.rStore }

// UseGroupSource, grup kaynağını değiştirir (LDAP için).
// Dinlemeye başlamadan ÖNCE çağrılmalı.
func (s *Server) UseGroupSource(src auth.GroupSource) { s.groups = src }

// UseEventBus, canlı izleme akışını bağlar. Çağrılmazsa olay yayınlanmaz.
func (s *Server) UseEventBus(p events.Publisher) { s.bus = p }

// publish, olay yayınını nil-güvenli sarar.
//
// ⚠️ Publish BLOKLAMAZ (bkz. events.Bus): burası kimlik doğrulama
// yolu ve izleyen bir panel, giren kullanıcıyı bekletemez.
func (s *Server) publish(kind events.Kind, user, source, detail string) {
	if s.bus == nil {
		return
	}
	s.bus.Publish(events.Event{Kind: kind, User: user, Source: source, Detail: detail})
}

// ProxyDeps, oturum akışının ihtiyaç duyduğu altyapıyı döner.
//
// httpapi ile PAYLAŞILIR: web terminali ve SSH aynı store'u, aynı kayıt
// dizinini ve aynı CA'yı kullanmalı — iki kapı, tek gerçek.
// UseRoleRefresher, oturum açılışında yetkiyi tazeleyen fonksiyonu
// bildirir. Dinlemeye başlamadan ÖNCE çağrılmalı: alan kilitsiz.
//
// Aynı fonksiyon web terminaline de gidiyor (ProxyDeps paylaşılıyor) —
// iki kapı tek kuralı uyguluyor.
func (s *Server) UseRoleRefresher(fn func(context.Context, string) error) {
	s.freshenRoles = fn
}

func (s *Server) ProxyDeps() proxy.Deps {
	return proxy.Deps{
		Store:        s.db,
		FreshenRoles: s.freshenRoles,
		Records:      s.rStore,
		Authority:    s.authority,
		Logger:       s.logger,
		RecordInput:  s.cfg.Recording.RecordInput,
		Requests:     proxy.RequestPolicy{AcceptEnv: s.cfg.Session.AcceptEnv},

		// Oturum sınırları buradan geçiyor, dolayısıyla web terminali de
		// (EnableTerminal aynı Deps'i alıyor) aynı sınırlara tabi.
		IdleTimeout: s.cfg.Session.IdleTimeout,
		MaxLifetime: s.cfg.Session.MaxLifetime,

		// Tanıma da paylaşılıyor: web terminalinden açılan oturum
		// hedefte komut çalıştırmıyorsa, aynı hedef hakkında iki kapıdan
		// iki farklı bilgi birikirdi.
		Probe: proxy.ProbePolicy{
			Enabled: s.cfg.TargetProbe.Enabled,
			Refresh: s.cfg.TargetProbe.RefreshOrDefault(),
			Timeout: s.cfg.TargetProbe.TimeoutOrDefault(),
		},

		// Olay akışı da paylaşılıyor: web terminalinden açılan bir
		// oturum canlı izlemede görünmezse, "iki kapı tek gerçek"
		// sözleşmesi tam orada bozulurdu.
		Events: s.bus,
	}
}

// EnableOOB, tarayıcı destekli girişi açar. serve, config'te oidc+http
// varsa çağırır; testler ve OIDC'siz kurulumlar hiç çağırmaz.
// timeout 0 ise varsayılan (oobTimeout) kullanılır — testler kısaltabilir.
//
// Dinlemeye başlamadan ÖNCE çağrılmalı: alanlar kilitsiz, eşzamanlı
// handshake'lerle yarışmamalı.
func (s *Server) EnableOOB(logins *auth.Logins, timeout time.Duration) {
	if timeout <= 0 {
		timeout = oobTimeout
	}
	s.logins = logins
	s.oobTimeout = timeout
}

// New prepares the server.
func New(cfg *config.Config, db *store.Store, logger *slog.Logger) (*Server, error) {
	// ⚠️ İZİN KONTROLÜ OKUMADAN ÖNCE.
	//
	// Host özel anahtarı, bastion'ın kendi kimliği: onu ele geçiren
	// biri bastion'ı taklit edip kullanıcıların oturumlarını araya
	// girerek toplayabilir (istemciler host key'i pinliyor, ama
	// çalınan anahtar o pini de sağlar). CA anahtarı ve mühür anahtarı
	// için bu kontrol vardı, host anahtarı için YOKTU — grup/dünya
	// okunabilir bir dosya sessizce kabul ediliyordu.
	info, err := os.Stat(cfg.HostKey)
	if err != nil {
		return nil, fmt.Errorf("sshd.New: %w", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("sshd.New: host key %s is group/world readable (%04o); chmod 600 it",
			cfg.HostKey, perm)
	}

	// #nosec G304 -- yol config'teki host_key; operatör girdisi
	data, err := os.ReadFile(cfg.HostKey)
	if err != nil {
		return nil, fmt.Errorf("sshd.New: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("sshd.New: %w", err)
	}

	recStore, err := record.NewStore(cfg.Recording.Dir)
	if err != nil {
		return nil, fmt.Errorf("sshd.New: %w", err)
	}

	caAuthority, err := ca.Load(cfg.CA.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("sshd.New: %w", err)
	}

	return &Server{
		cfg: cfg, signer: signer, logger: logger,
		rStore: recStore, db: db, authority: caAuthority,
		groups: auth.ClaimGroups{},

		limiter: newConnLimiter(
			cfg.Listen.MaxConnsOrDefault(),
			cfg.Listen.MaxConnsPerIPOrDefault(),
		),
		handshakeTimeout: cfg.Listen.HandshakeTimeoutOrDefault(),
		maxAuthTries:     cfg.Listen.MaxAuthTriesOrDefault(),
		maxChannels:      cfg.Listen.MaxChannelsOrDefault(),
		publicKeyLogin:   cfg.Auth.PublicKeyLoginEnabled(),
	}, nil
}

// ListenAndServe listens on cfg.Listen.Addr and hands the listener to Serve.
func (s *Server) ListenAndServe(ctx context.Context) error {
	l, err := net.Listen("tcp", s.cfg.Listen.Addr)
	if err != nil {
		return err
	}

	return s.Serve(ctx, l)
}

// Serve accepts connections from l until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	stopped := make(chan struct{})
	defer close(stopped)

	go func() {
		select {
		case <-ctx.Done():
			l.Close()
		case <-stopped:
		}
	}()

	// backoff, geçici Accept hatalarından sonraki bekleme. Sıfırdan
	// başlar, her hatada ikiye katlanır, başarıda sıfırlanır.
	var backoff time.Duration

	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			// GEÇİCİ hatada ölme, yük at.
			//
			// Bu kontrol olmadan dosya tanıtıcısı tükenmesi (EMFILE) tam
			// bir kesinti demekti: Accept hatayı döner, Serve döner,
			// serve komutu döner, süreç biter. Üstelik fd tükenmesi tam
			// olarak sınırsız eşzamanlılığın ürettiği şey — yani
			// sınırlayıcının önlemeye çalıştığı durumun kendisi
			// bastion'ı öldürüyordu.
			if isTemporaryAcceptErr(err) {
				backoff = nextBackoff(backoff)
				s.logger.Error("accept temporarily failed; backing off",
					"error", err, "backoff", backoff)

				select {
				case <-time.After(backoff):
				case <-ctx.Done():
					return nil
				}
				continue
			}

			return err
		}
		backoff = 0

		// Sınır kontrolü ACCEPT GOROUTINE'İNDE, goroutine açılmadan
		// önce: reddedilen bağlantıyı kuyruğa almak, tükenmeyi bir
		// katman içeri taşımak olurdu.
		ip := remoteIP(conn.RemoteAddr())
		release, reason := s.limiter.acquire(ip)
		if release == nil {
			total, _ := s.limiter.stats()
			s.logger.Warn("connection refused by limit",
				"remote", ip, "reason", reason, "total", total)
			conn.Close()
			continue
		}

		go s.handleConn(ctx, conn, release)
	}
}

// isTemporaryAcceptErr, Accept hatasının geçici olup olmadığını söyler.
//
// net.Error.Temporary() kullanımdan kalktığı için syscall'lar açıkça
// eşleniyor: bunlar "kaynak şu an yok" der, "dinleyici bozuldu" demez.
func isTemporaryAcceptErr(err error) bool {
	return errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.ENOMEM)
}

// nextBackoff, katlanan bekleme süresini üst sınırla döner.
func nextBackoff(current time.Duration) time.Duration {
	const (
		min = 5 * time.Millisecond
		max = time.Second
	)
	if current == 0 {
		return min
	}
	if next := current * 2; next < max {
		return next
	}
	return max
}

// handleConn runs the SSH handshake and (from S1.5 on) dispatches channels.
func (s *Server) handleConn(ctx context.Context, nConn net.Conn, release func()) {
	// release, sınırlayıcıdaki yeri geri verir. Kapatmayla AYNI defer
	// zincirinde: başarısız handshake'ler de yeri bırakmalı, yoksa
	// tarayıcı trafiği bastion'ı zamanla max_conns'ta kilitler.
	defer release()
	defer nConn.Close()

	scfg, err := s.serverConfig(nConn)
	if err != nil {
		s.logger.Error("handleConn.serverConfig", "err", err)
		return
	}

	// Handshake son tarihi. Kimliği doğrulanmamış bir istemcinin bizi
	// meşgul edebileceği süre burada bitiyor.
	if s.handshakeTimeout > 0 {
		nConn.SetDeadline(time.Now().Add(s.handshakeTimeout))
	}

	sshConn, chans, reqs, err := ssh.NewServerConn(nConn, scfg)
	if err != nil {
		s.logger.Warn("handleConn.NewServerConn", "err", err)
		return
	}

	// ⚠️ Son tarihi TEMİZLEMEK şart. net.Conn son tarihleri kalıcıdır ve
	// x/crypto'nun okuma goroutine'i oturum boyunca okumaya devam eder:
	// unutulursa HER oturum tam olarak handshake_timeout'ta ölür.
	// Handshake testleri bunu göstermez, oturumu süreden uzun açık tutan
	// bir test gösterir.
	nConn.SetDeadline(time.Time{})

	s.logger.Info("ssh handshake ok",
		"user", sshConn.User(),
		"postern_user", sshConn.Permissions.Extensions["postern-user"],
		"remote", sshConn.RemoteAddr(),
	)
	s.publish(events.AuthOK,
		sshConn.Permissions.Extensions["postern-user"],
		sshConn.RemoteAddr().String(),
		"ssh handshake as "+sshConn.User())

	// ⚠️ OTURUMLAR BAĞLANTIYA BAĞLANIYOR.
	//
	// Kapatılan sızıntı: oturum bağlamı sunucu bağlamından türüyordu,
	// yani istemci ortadan kaybolduğunda (ağ koptu, istemci öldürüldü)
	// ve hedef de sessizse hiçbir şey oturumu bitirmiyordu. Broker'ın
	// beklediği üç goroutine de HEDEFTEN okuyor; hedef susuyorsa
	// üçü de asılı kalıyordu.
	//
	// Kalıcı olarak sızan şeyler: hedefe açık bir SSH+TCP bağlantısı
	// (kullanıcının sertifika principal'ıyla), açık bir .cast dosya
	// tanıtıcısı (kapanmadığı için tamponlanan kuyruk hiç yazılmıyor)
	// ve sessions tablosunda ended_at'i NULL kalan bir satır — yani
	// denetim kaydı "bu oturum hâlâ açık" demeye devam ediyordu.
	//
	// Aşağıdaki döngü bağlantı ölünce biter; connCancel de o an bu
	// bağlantının bütün oturumlarını kapatır.
	connCtx, connCancel := context.WithCancelCause(ctx)
	defer connCancel(errConnectionClosed)

	go ssh.DiscardRequests(reqs)

	// Kanal sayacı: bu kümedeki TEK kimlik doğrulama sonrası sınır.
	// Her kabul edilen kanal bir hedef bağlantısı, bir .cast dosyası ve
	// bir denetim satırı demek; bugün sayıyı sınırlayan tek şey
	// istemcinin ne kadar hızlı istek gönderebildiğiydi.
	var (
		chanMu    sync.Mutex
		chanCount int
	)

	for newChan := range chans {
		chanMu.Lock()
		over := s.maxChannels > 0 && chanCount >= s.maxChannels
		if !over {
			chanCount++
		}
		chanMu.Unlock()

		if over {
			// Prohibited DEĞİL ResourceShortage: bu bir politika kararı
			// değil kapasite sınırı, log da öyle demeli.
			newChan.Reject(ssh.ResourceShortage, "too many channels")
			s.logger.Warn("channel refused by limit",
				"postern_user", sshConn.Permissions.Extensions["postern-user"],
				"remote", sshConn.RemoteAddr(),
				"limit", s.maxChannels)
			continue
		}

		go func(nc ssh.NewChannel) {
			defer func() {
				chanMu.Lock()
				chanCount--
				chanMu.Unlock()
			}()
			s.handleChannel(connCtx, sshConn, nc)
		}(newChan)
	}
}

// serverConfig builds the ssh.ServerConfig used for handshakes.
func (s *Server) serverConfig(nConn deadlineSetter) (*ssh.ServerConfig, error) {
	cfg := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-postern",

		// x/crypto'nun varsayılanı 6. Düşürüyoruz çünkü her deneme bir
		// veritabanı sorgusu (UserByPublicKey) ve OOB yolunda bir
		// bekleme daha demek.
		MaxAuthTries: s.maxAuthTries,

		// Taşıma algoritmaları açıkça: varsayılanlar SHA-1 taşıyor
		// (bkz. algorithms.go).
		Config: ssh.Config{
			KeyExchanges: sshalg.KeyExchanges,
			Ciphers:      sshalg.Ciphers,
			MACs:         sshalg.MACs,
		},
	}

	// ⚠️ KAPALIYSA CALLBACK HİÇ KURULMUYOR.
	//
	// Kurup içeride reddetmek DEĞİL: x/crypto, callback varsa publickey
	// yöntemini istemciye TEKLİF EDİYOR. O zaman istemci anahtarlarını
	// tek tek dener, her deneme MaxAuthTries'tan bir hak yakar ve
	// kullanıcı "çok fazla deneme" ile kapı dışında kalır — üstelik
	// kurumun anahtar girişini kapattığı dışarıdan hiç anlaşılmaz.
	// Teklif edilmeyen bir yöntem, istemcinin doğrudan
	// keyboard-interactive'e geçmesini sağlıyor.
	if s.publicKeyLogin {
		cfg.PublicKeyCallback = s.publicKeyCallback
	}
	if s.logins != nil {
		// nil kaldıkça istemciye bu yöntem hiç sunulmaz — OIDC'siz
		// kurulum eskisi gibi yalnızca public key konuşur.
		cfg.KeyboardInteractiveCallback = s.keyboardInteractiveCallbackFor(nConn)
	}
	cfg.AddHostKey(s.signer)
	return cfg, nil
}

// errConnectionClosed, istemci bağlantısı bittiğinde oturumları
// kapatan sebep.
var errConnectionClosed = errors.New("sshd: client connection closed")
