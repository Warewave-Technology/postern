package proxy

// Oturumun yaşam döngüsü: yetki → bağlantı → kayıt → denetim → broker.
//
// Bu dosyanın varlık sebebi TEK KAYNAK. SSH (sshd/channel.go) ve web
// terminali (httpapi/terminal.go) aynı oturumu iki farklı kapıdan açıyor;
// aradaki tek fark istemci tarafındaki kanalın ne olduğu. Akışı her iki
// kapıda ayrı ayrı yazsaydık, "kayıt açılamazsa oturum reddedilir" ya da
// "denetim satırı kapanmalı" gibi kararlar iki kopyada yaşar ve er geç
// ayrışırdı — kimlik/yetki için verdiğimiz tek-kaynak kararının aynısı.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/ca"
	"github.com/warewave/postern/internal/model"
	"github.com/warewave/postern/internal/policy"
	"github.com/warewave/postern/internal/record"
	"github.com/warewave/postern/internal/store"
	"github.com/warewave/postern/internal/upstream"
)

var (
	// ErrAccessDenied: kimlik ya da yetki reddi — bir arıza DEĞİL,
	// güvenlik olayı. Çağıran bunu istemciye "access denied" olarak
	// yansıtır (SSH reject sebebi / HTTP 403).
	ErrAccessDenied = errors.New("proxy: access denied")

	// ErrUnavailable: hedefe ulaşılamadı, kayıt açılamadı, veritabanı
	// erişilemiyor. Kullanıcının suçu değil; birinin müdahale etmesi
	// gerekir. Çağıran "connection failed" / HTTP 503 der.
	ErrUnavailable = errors.New("proxy: session unavailable")
)

// Deps, oturum açmak için gereken altyapı. Hem sshd.Server hem
// httpapi.Server bunu kurar.
type Deps struct {
	Store       *store.Store
	Records     *record.Store
	Authority   *ca.CA
	Logger      *slog.Logger
	RecordInput bool

	// Requests, oturum kanalı request'lerinin süzgeci (requests.go).
	// Sıfır değeri kullanılabilir: env whitelist'i varsayılana düşer,
	// tip listeleri zaten sabit.
	Requests RequestPolicy
}

// Request, açılacak oturumun kim/nereye bilgisi.
type Request struct {
	// Username, DOĞRULANMIŞ postern kullanıcı adıdır — istemcinin iddia
	// ettiği değil. SSH tarafında Permissions'tan, web tarafında oturum
	// kaydından gelir; ikisi de kimliği kendi kapısında doğrulamış olur.
	Username   string
	TargetName string
	SrcIP      string
}

// Session, açılmış ama henüz sürülmemiş bir oturum: hedefe bağlanılmış,
// kayıt dosyası açılmış, denetim satırı yazılmıştır. Run ile sürülür,
// Close ile kapatılır.
type Session struct {
	// ID, denetim satırının ve .cast dosyasının ortak anahtarı.
	ID string

	// OSUser, policy'nin verdiği karar — çağıran log'a yazsın diye açık.
	OSUser string

	// Log, oturumun alanları bağlanmış logger'ı (user, target, session_id,
	// record_path). Çağıran kendi olaylarını bununla yazsın ki satırlar
	// aynı oturumda birleşsin.
	Log *slog.Logger

	deps Deps

	conn *upstream.Conn
	up   ssh.Channel
	upR  <-chan *ssh.Request
	rec  *record.Writer

	start  time.Time
	closed bool
}

// Open, yetkiyi denetler ve oturumu hedefe kadar kurar.
//
// Hata döndüğünde HİÇBİR ŞEY açık kalmaz: kısmi kurulum kendi içinde
// temizlenir ve dönen Session nil'dir — çağıranın Close çağırmasına
// gerek yoktur.
func Open(ctx context.Context, deps Deps, req Request) (*Session, error) {
	log := deps.Logger.With("user", req.Username, "target", req.TargetName)

	target, err := deps.Store.Target(ctx, req.TargetName)
	if err != nil {
		// Ret ile arıza AYRI olaylardır: birini diğerinin adıyla
		// loglamak denetimi yanıltır (bkz. channel.go'daki aynı ayrım).
		if errors.Is(err, store.ErrNotFound) {
			log.Warn("target not found")
			return nil, fmt.Errorf("proxy.Open: %w", ErrAccessDenied)
		}
		log.Error("target lookup failed", "error", err)
		return nil, fmt.Errorf("proxy.Open: %w", ErrUnavailable)
	}

	u, err := deps.Store.User(ctx, req.Username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			log.Warn("user not found")
			return nil, fmt.Errorf("proxy.Open: %w", ErrAccessDenied)
		}
		log.Error("user lookup failed", "error", err)
		return nil, fmt.Errorf("proxy.Open: %w", ErrUnavailable)
	}

	d := policy.Authorize(u, target, "")
	if !d.Allowed {
		// Reason politikanın kendi cümlesi; denetimde "neden reddedildi"
		// sorusunun cevabı bu. İstemciye gitmez, yalnızca log'a.
		log.Warn("access denied by policy", "reason", d.Reason)
		return nil, fmt.Errorf("proxy.Open: %w", ErrAccessDenied)
	}

	// Buradan sonrası kaynak açıyor. Yedi ayrı hata dalına yedi ayrı
	// temizlik yazmamak için tek bir geri sarma noktası: opened yalnızca
	// en sonda true olur, o zamana kadar her erken dönüş buradan geçer.
	var (
		opened bool
		conn   *upstream.Conn
		rec    *record.Writer
		id     string
	)
	defer func() {
		if opened {
			return
		}
		if rec != nil {
			_ = rec.Close()
		}
		if conn != nil {
			_ = conn.Close()
		}
		if id != "" {
			// Denetim satırı yazıldıysa kapat: yarıda kalan kurulum
			// sonsuza dek "running" bir kayıt bırakmamalı.
			if err := deps.Store.EndSession(context.WithoutCancel(ctx), id, time.Now()); err != nil &&
				!errors.Is(err, store.ErrNotFound) {
				log.Error("end session failed", "error", err)
			}
		}
	}()

	conn, err = upstream.DialWithCert(ctx, target, upstream.Identity{
		PosternUser: req.Username,
		OSUser:      d.OSUser,
	}, deps.Authority)
	if err != nil {
		log.Error("target dial failed", "error", err, "os_user", d.OSUser)
		return nil, fmt.Errorf("proxy.Open: %w", ErrUnavailable)
	}

	up, upR, err := conn.OpenSession()
	if err != nil {
		log.Error("upstream session open failed", "error", err)
		return nil, fmt.Errorf("proxy.Open: %w", ErrUnavailable)
	}

	id, err = record.NewSessionID()
	if err != nil {
		log.Error("session id generation failed", "error", err)
		return nil, fmt.Errorf("proxy.Open: %w", ErrUnavailable)
	}

	f, path, err := deps.Records.Create(id)
	if err != nil {
		log.Error("recording file create failed", "error", err)
		return nil, fmt.Errorf("proxy.Open: %w", ErrUnavailable)
	}

	// TERM pty-req ile gelir, yani başlık yazılırken henüz bilinmiyor.
	// Boyut 80x24 varsayılanıyla başlar; broker pty-req'i görünce Resize
	// ile düzeltir.
	rec, err = record.NewWriter(f, 80, 24, nil)
	if err != nil {
		log.Error("recorder init failed", "error", err)
		return nil, fmt.Errorf("proxy.Open: %w", ErrUnavailable)
	}

	log = log.With("session_id", id, "record_path", path)
	start := time.Now()

	err = deps.Store.StartSession(ctx, store.SessionStart{
		ID: id, Username: req.Username, TargetName: target.Name,
		OSUser: d.OSUser, SrcIP: req.SrcIP, StartedAt: start,
		RecordingPath: path,
	})
	if err != nil {
		log.Error("start session failed", "error", err)
		// id set edildi ama satır yazılmadı: defer'daki EndSession
		// ErrNotFound alıp sessizce geçecek (yukarıda öyle yazıldı).
		return nil, fmt.Errorf("proxy.Open: %w", ErrUnavailable)
	}

	opened = true
	return &Session{
		ID: id, OSUser: d.OSUser, Log: log,
		deps: deps, conn: conn, up: up, upR: upR, rec: rec, start: start,
	}, nil
}

// Run, istemci kanalını hedefe bağlar ve oturum bitene kadar sürer.
//
// down/downR istemci tarafı: SSH'ta kabul edilmiş ssh.Channel, web'de
// WebSocket'i ssh.Channel gibi giydiren adaptör. Broker ikisini ayırt
// etmez — arayüz sözleşmesinin bütün faydası bu.
func (s *Session) Run(ctx context.Context, down ssh.Channel, downR <-chan *ssh.Request) error {
	s.Log.Info("session started", "os_user", s.OSUser)
	err := New(down, downR, s.up, s.upR, s.rec, s.deps.RecordInput, s.deps.Requests, s.deps.Logger).Run(ctx)
	s.Log.Info("session ended", "os_user", s.OSUser, "duration", time.Since(s.start))
	return err
}

// Close, oturumu kapatır: kayıt dosyası, denetim satırı, hedef bağlantısı.
// İkinci çağrı no-op — çağıran defer'la koyabilsin diye.
func (s *Session) Close(ctx context.Context) {
	if s == nil || s.closed {
		return
	}
	s.closed = true

	// Kayıt önce: Err() ancak Close'dan SONRA anlamlıdır — yapışkan hata
	// oturum boyunca birikir ve adaptörler kayıt arızasını yutup oturumu
	// yaşatır. Bu satır olmazsa bozuk kayıt tamamen sessiz kalır.
	if cerr := s.rec.Close(); cerr != nil {
		s.Log.Error("recording close failed", "error", cerr)
	}
	if rerr := s.rec.Err(); rerr != nil {
		s.Log.Error("recording degraded, session not fully captured", "error", rerr)
	}

	// ⚠️ WithoutCancel: oturum bittiğinde çağıranın ctx'i de iptal olur.
	// İptal edilmiş ctx ile yapılan kapanış, denetim satırını sonsuza dek
	// "running" bırakır.
	if serr := s.deps.Store.EndSession(context.WithoutCancel(ctx), s.ID, time.Now()); serr != nil {
		s.Log.Error("end session failed", "error", serr)
	}

	if s.conn != nil {
		_ = s.conn.Close()
	}
}

// unusedModel, model paketini import listesinde tutar (Target tipi
// store'dan geliyor ama okuyucu için burada anılması yararlı).
var _ = model.Target{}
