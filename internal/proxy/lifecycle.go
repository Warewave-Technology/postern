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
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/ca"
	"github.com/warewave/postern/internal/events"
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

	// ErrIdleTimeout / ErrMaxLifetime: oturumu KAPATAN sınırlar.
	// Hata olarak çağırana dönmezler — context.Cause ile okunup denetim
	// kaydına yazılırlar (bkz. idle.go).
	ErrIdleTimeout = errors.New("proxy: session idle timeout")
	ErrMaxLifetime = errors.New("proxy: session max lifetime")

	// ErrRecordingFailed: kayıt yazımı oturum ortasında bozuldu.
	// Oturum KAPATILIR — kayıtsız oturum yok.
	ErrRecordingFailed = errors.New("proxy: recording failed")

	// ErrUnavailable: hedefe ulaşılamadı, kayıt açılamadı, veritabanı
	// erişilemiyor. Kullanıcının suçu değil; birinin müdahale etmesi
	// gerekir. Çağıran "connection failed" / HTTP 503 der.
	ErrUnavailable = errors.New("proxy: session unavailable")
)

/*
 * ErrDirectoryRefused, kimlik kaynağının bu kullanıcı için oturumu
 * reddettiği: dizinde YOK ya da hesap KAPATILMIŞ.
 *
 * Arızadan ayrı bir hata olması şart. "Cevap veremedim" ile "bu kişi
 * artık burada değil" aynı yola düşerse, bir dizin kesintisi ya herkesi
 * dışarıda bırakır ya da kapatılmış hesapları içeri alır — hangi tarafa
 * eğdiğimize bakmaksızın yanlış.
 */
var ErrDirectoryRefused = errors.New("proxy: the directory no longer vouches for this user")

// Deps, oturum açmak için gereken altyapı. Hem sshd.Server hem
// httpapi.Server bunu kurar.
type Deps struct {
	Store   *store.Store
	Records *record.Store
	/*
	 * RecordMinFree, altına inildiğinde YENİ oturumun reddedildiği boş
	 * alan. 0 kapalı. Gerekçesi Open'daki kullanım yerinde.
	 */
	RecordMinFree uint64
	Authority     *ca.CA
	Logger        *slog.Logger
	RecordInput   bool

	// Requests, oturum kanalı request'lerinin süzgeci (requests.go).
	// Sıfır değeri kullanılabilir: env whitelist'i varsayılana düşer,
	// tip listeleri zaten sabit.
	Requests RequestPolicy

	// IdleTimeout, iki yönde de bayt akmayan oturumun kapatılma süresi.
	// 0 = kapalı (bkz. config.SessionConfig.IdleTimeout).
	IdleTimeout time.Duration

	// MaxLifetime, oturumun mutlak ömrü. 0 = kapalı.
	MaxLifetime time.Duration

	// Probe, hedefte KOMUT ÇALIŞTIRARAK tanıma. Sıfır değeri KAPALI —
	// yani hiçbir şey çağırmadıkça postern hedefte kullanıcının oturumu
	// dışında bir şey çalıştırmaz.
	Probe ProbePolicy

	/*
	 * FreshenRoles, oturum AÇILIRKEN kullanıcının rollerini aktif kimlik
	 * kaynağından tazeler. nil ise tazeleme yapılmaz.
	 *
	 * ⚠️ NEDEN BURADA: iki kapı (SSH kanalı ve web terminali) tek
	 * fonksiyondan geçiyor, yani kural ikisine birden uygulanıyor —
	 * "iki kapı, tek gerçek". Kimlik doğrulama geri çağrısında değil,
	 * çünkü orası el sıkışmanın içi: bir handshake'te birden çok kez
	 * çağrılıyor ve orada ağ isteği yapmak, kimliği doğrulanmamış bir
	 * bağlantıyı dizine karşı bir yükseltici hâline getirirdi.
	 *
	 * ErrDirectoryRefused dönerse oturum REDDEDİLİR; başka bir hata
	 * yalnızca loglanır ve saklanan rollerle devam edilir (dizin arızası
	 * yetki yokluğu değildir).
	 */
	FreshenRoles func(ctx context.Context, username string) error

	// Events, canlı izleme akışı. nil ise olay yayınlanmaz.
	//
	// ⚠️ Publish BLOKLAMAZ (bkz. events.Bus): burası bir oturumun açılış
	// ve kapanış yolu ve izleyen bir panel, izlediği oturumu
	// bekletemez.
	Events events.Publisher
}

/*
 * ProbePolicy, tanımanın açık olup olmadığı ve sınırları.
 *
 * Sıfır değeri KAPALI ve bu kasıtlı: yapıyı sıfır değeriyle kuran her
 * çağıran (testler dahil) hedefe dokunmayan davranışı alır.
 */
type ProbePolicy struct {
	Enabled bool
	Refresh time.Duration
	Timeout time.Duration
}

/*
 * maybeProbe, hedefi tanımayı dener.
 *
 * ⚠️ OTURUM BUNU BEKLEMEZ. Ayrı bir goroutine'de, kullanıcının
 * bağlantısı üzerinde çalışıyor; kullanıcı kabuğunu çoktan almış olur.
 * Bekletseydik, tanıma süresi her oturumun açılış gecikmesine eklenirdi.
 *
 * ⚠️ HER KOŞU DENETİME YAZILIYOR. Komutlar hedefin günlüklerinde
 * BAĞLANAN KULLANICININ adına görünüyor — kullanıcının yazmadığı
 * komutlar, kullanıcının hesabında. Bunun izini bırakmamak kabul
 * edilemez olurdu.
 */
func maybeProbe(ctx context.Context, deps Deps, log *slog.Logger, conn *upstream.Conn, targetName, byUser string) {
	if !deps.Probe.Enabled {
		return
	}

	// Bağlam oturumla birlikte iptal oluyor; tanıma kullanıcı çıkınca
	// yarıda kalmasın diye ayrılıyor, ama kendi süre sınırı var.
	ctx = context.WithoutCancel(ctx)

	// Her oturumda sormuyoruz: hedefin günlüklerini postern'in
	// gürültüsüyle doldurmak, özelliğin faydasından çok zararı olurdu.
	if f, err := deps.Store.TargetFacts(ctx, targetName); err == nil {
		if !f.ProbedAt.IsZero() && time.Since(f.ProbedAt) < deps.Probe.Refresh {
			return
		}
	}

	go func() {
		ctx, cancel := context.WithTimeout(ctx, deps.Probe.Timeout)
		defer cancel()

		p, err := conn.Probe(ctx)
		if err != nil {
			log.Warn("target probe failed", "error", err)
			return
		}
		if err := deps.Store.RecordTargetProbe(ctx, targetName, p); err != nil {
			log.Warn("target probe not recorded", "error", err)
			return
		}

		// Denetim satırı: kimin bağlantısında, hangi hedefte, ne
		// çalıştırıldı. Komut listesi de yazılıyor — "hangi komutlar"
		// sorusunun cevabı kaynağa bakmayı gerektirmemeli.
		if err := deps.Store.LogAdmin(ctx, store.AdminLogEntry{
			Actor: byUser, Via: "probe", Action: "target.probe",
			Entity: targetName,
			Details: fmt.Sprintf("ran on this user's connection: %s",
				strings.Join(upstream.ProbeCommands, "; ")),
		}); err != nil {
			log.Warn("target probe not audited", "error", err)
		}
		log.Info("target probed", "os", p.OSName, "kernel", p.Kernel)
	}()
}

/*
 * recordTargetOutcome, hedef hakkında el sıkışmada öğrenilenleri yazar.
 *
 * ⚠️ HATASI YUTULUYOR ve bu ayrım kasıtlı: bu bir GÖZLEM kaydı, denetim
 * kaydı değil. sessions/admin_log yazılamazsa oturum düşer (denetim
 * öncelikli politika); "hedefin SSH afişi neydi" yazılamazsa kullanıcının
 * oturumunu kesmek için bir sebep yok.
 *
 * ⚠️ context.WithoutCancel: çağıran bağlam oturumla birlikte iptal
 * oluyor ve yazma tam o anda düşerdi.
 */
func recordTargetOutcome(
	ctx context.Context, deps Deps, log *slog.Logger,
	targetName string, facts model.TargetFacts, dialErr error,
) {
	ctx = context.WithoutCancel(ctx)

	var err error
	if dialErr != nil {
		err = deps.Store.RecordTargetError(ctx, targetName, dialErr.Error())
	} else {
		err = deps.Store.RecordTargetSeen(ctx, targetName, facts)
	}
	if err != nil {
		log.Warn("target facts not recorded", "error", err)
	}
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

	// user/target/src, olay yayını için: Log'un alanlarından geri
	// okunamıyor ve Run'ın elinde başka türlü yok.
	user   string
	target string
	src    string
}

// publish, olay yayınını nil-güvenli sarar.
func (s *Session) publish(kind events.Kind, detail string) {
	if s.deps.Events == nil {
		return
	}
	s.deps.Events.Publish(events.Event{
		Kind:   kind,
		User:   s.user,
		Target: s.target,
		Source: s.src,
		Detail: detail,
	})
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

	/*
	 * ⚠️ YETKİ TAZELİĞİ BURADA SAĞLANIYOR.
	 *
	 * Eskiden bunu sağlayan şey bir REDDETMEYDİ: SSO'ya bağlı kullanıcı
	 * anahtarla giremiyordu, çünkü anahtar kapısı kimlik sağlayıcıya
	 * bakmıyor ve roller yalnızca SSO girişinde tazeleniyordu. SSH'ın
	 * anahtara sabitlenmesiyle o reddetme, dizin kullanıcılarının SSH'ını
	 * tamamen kapatır hâle geldi.
	 *
	 * Yerine tazeliği buraya taşıdık: kimlik ZATEN doğrulanmış, kanal
	 * sayısı sınırlı (listen.max_channels_per_conn), ve bir oturum açmak
	 * insan hızında bir olay. Yani ne kimliksiz bir yükseltici ne de
	 * sıcak bir yol.
	 *
	 * Hata oturumu düşürmüyor: tazeleyemedik diye erişimi kesmek, dizin
	 * arızasını yetki kaybına çevirmek olurdu. Tazeleme fonksiyonunun
	 * kendisi "bulamadım" ile "cevap veremedim"i ayırt ediyor.
	 */
	/*
	 * ⚠️ KOŞUL "SSO'ya bağlı mı" DEĞİL, "DİZİNE bağlı mı".
	 *
	 * Ölçüldü: yetkisi dizin grubundan gelen bir yönetici demo
	 * veritabanında sso_only=false ile duruyordu — yani dizine karşı
	 * HİÇ yeniden sorulmuyordu ve dizinde kapatılsa bile anahtarıyla
	 * oturum açardı. Tam da yetkisi en yüksek ve kontrolü en gerekli
	 * olan kişi, kontrolün dışında kalıyordu.
	 */
	if (u.SSOOnly || u.DirBound) && deps.FreshenRoles != nil {
		ferr := deps.FreshenRoles(ctx, u.Name)
		switch {
		case errors.Is(ferr, ErrDirectoryRefused):
			/*
			 * ⚠️ OTURUM REDDEDİLİYOR, ROL SİLİNMİYOR.
			 *
			 * Kaynak bu hesabı ya tanımıyor ya da kapatmış. İkisi de
			 * "bu kişi artık burada değil" demek ve anahtar kapısında
			 * bunu yok saymak, hesabı devre dışı bırakmayı — işten
			 * ayrılmanın İLK adımını — etkisiz kılardı.
			 *
			 * Hiçbir şey YAZMIYORUZ: iptal, patlama yarıçapı
			 * korumaları olan senkronizasyon döngüsünün işi. Burada
			 * yalnızca bu oturuma hayır deniyor, ki bu bir arızada
			 * geri alınabilir bir karardır.
			 */
			log.Warn("session refused: directory no longer vouches for this user",
				"reason", ferr)
			return nil, fmt.Errorf("proxy.Open: %w", ErrAccessDenied)
		case ferr != nil:
			log.Warn("role refresh failed; continuing with stored roles", "error", ferr)
		default:
			if refreshed, rerr := deps.Store.User(ctx, u.Name); rerr == nil {
				u = refreshed
			} else {
				log.Error("user reload after refresh failed", "error", rerr)
			}
		}
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
		// Başarısız denemeyi hedefin üstüne işaretle: paneldeki hedef
		// sayfasında "en son ne zaman çalıştı" ile "en son neden
		// çalışmadı" ayrı ayrı duruyor.
		recordTargetOutcome(ctx, deps, log, req.TargetName, model.TargetFacts{}, err)
		/*
		 * ⚠️ SEBEP SARMALANARAK TAŞINIYOR.
		 *
		 * Eskiden yalnızca ErrUnavailable dönüyordu ve neden
		 * bağlanamadığımız SADECE günlükte kalıyordu. Web terminali
		 * bunu kullanıcıya "[disconnected]" diye gösteriyordu — yani
		 * hedefi bu bastion'a güvenecek şekilde yapılandırmamış bir
		 * operatör, ekranda yapması gerekeni söyleyen hiçbir şey
		 * görmüyordu. Çağıran artık upstream sınıflarını
		 * (ErrRefused / ErrUnreachable / ErrHostKeyMismatch)
		 * errors.Is ile ayırt edebiliyor.
		 */
		return nil, fmt.Errorf("proxy.Open: %w: %w", ErrUnavailable, err)
	}
	recordTargetOutcome(ctx, deps, log, req.TargetName, conn.Facts(), nil)
	maybeProbe(ctx, deps, log, conn, req.TargetName, req.Username)

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

	/*
	 * ⚠️ DİSK EŞİĞİ, KAYIT AÇMADAN ÖNCE.
	 *
	 * Sıra önemli. Disk gerçekten dolduğunda Create zaten başarısız
	 * oluyor ve oturum reddediliyor — ama o noktada AÇIK oturumlar da
	 * ölüyor (aşağıdaki ErrRecordingFailed yolu), yani dolu disk
	 * yalnızca yeni girişleri değil çalışan işleri de kesiyor.
	 *
	 * Eşik aynı reddi daha erken veriyor: yeni oturum girmiyor,
	 * çalışanlar yaşamaya devam ediyor ve operatörün yer açacak zamanı
	 * oluyor. Sebep AYRI bir hata: "disk doldu" ile "kayıt dosyası
	 * açılamadı" farklı sorunlar ve tek mesaja toplamak, operatörü
	 * yanlış yerde arattırırdı.
	 */
	if err := deps.Records.CheckSpace(deps.RecordMinFree); err != nil {
		log.Error("refusing session: recording space is low", "error", err)
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
		user: req.Username, target: req.TargetName, src: req.SrcIP,
	}, nil
}

// Run, istemci kanalını hedefe bağlar ve oturum bitene kadar sürer.
//
// down/downR istemci tarafı: SSH'ta kabul edilmiş ssh.Channel, web'de
// WebSocket'i ssh.Channel gibi giydiren adaptör. Broker ikisini ayırt
// etmez — arayüz sözleşmesinin bütün faydası bu.
func (s *Session) Run(ctx context.Context, down ssh.Channel, downR <-chan *ssh.Request) error {
	s.Log.Info("session started", "os_user", s.OSUser)
	s.publish(events.SessionStarted, "os user "+s.OSUser)

	ctx, guard, stop := bound(ctx, s.deps.IdleTimeout, s.deps.MaxLifetime)
	defer stop()

	// ⚠️ KAYIT BOZULURSA OTURUM BİTER.
	//
	// Açılışta politika zaten buydu (kayıt açılamazsa proxy.Open
	// ErrUnavailable döner). Oturum ORTASINDA aynı arıza sessizce
	// yutuluyordu: akış devam ediyor, oturum kayıtsız sürüyordu. Yani
	// "kayıtsız oturum yok" kuralı yarım uygulanıyordu ve diski
	// doldurabilen bir kullanıcı denetimi fiilen kapatabiliyordu.
	recFailed := make(chan error, 1)
	if s.rec != nil {
		s.rec.OnFailure(func(err error) {
			select {
			case recFailed <- err:
			default:
			}
		})
	}

	recCtx, recCancel := context.WithCancelCause(ctx)
	defer recCancel(nil)
	ctx = recCtx

	go func() {
		select {
		case err := <-recFailed:
			s.Log.Error("session closed: recording failed mid-session", "error", err)
			recCancel(ErrRecordingFailed)
		case <-recCtx.Done():
		}
	}()

	// ⚠️ Broker s.Log alıyor, deps.Logger DEĞİL.
	//
	// s.Log oturumun alanları bağlanmış hâli (user, target, session_id,
	// record_path). Broker'ın yazdığı satırların en önemlisi "session
	// request denied" — yani "kim sftp/x11/agent forwarding denedi"
	// sorusunun cevabı. Ham logger'la o satırlar KİMİN olduğunu
	// söylemiyordu ve denetim açısından işe yaramıyordu.
	b := New(down, downR, s.up, s.upR, s.rec, s.deps.RecordInput, s.deps.Requests, s.Log)
	b.idle = guard

	/*
	 * SFTP denetimi yalnızca kanal AÇIKKEN kuruluyor.
	 *
	 * ⚠️ Sıra tersine çevrilemez: süzgeç kapalıyken `subsystem sftp`
	 * zaten reddediliyor, o yüzden burada günlükçü kurmak boşuna bir
	 * goroutine olurdu. Açıkken ise kurulmaması, kanalı denetimsiz
	 * açmak demek olurdu — kanalın var olma koşulu bu günlükçü.
	 */
	var journal *sftpJournal
	if s.deps.Requests.AllowSFTP {
		journal = newSFTPJournal(s.deps.Store, s.ID, s.Log, func(err error) {
			b.abortAudit(err)
		})
		b.WithSFTP(journal)
	}

	err := b.Run(ctx)

	if journal != nil {
		if n := journal.Close(); n > 0 {
			s.Log.Info("sftp file events recorded", "events", n)
		}
	}

	// Oturumun NEDEN bittiğini logla. "Kullanıcı çıktı", "boşta kaldı" ve
	// "ömrü doldu" denetim kaydında ayrı olaylar; hepsini "session ended"
	// diye yazmak, sınırların çalışıp çalışmadığını sonradan
	// anlaşılamaz kılardı.
	var closedBy string
	if cause := context.Cause(ctx); cause != nil {
		switch {
		case errors.Is(cause, ErrIdleTimeout):
			closedBy = "idle_timeout"
		case errors.Is(cause, ErrMaxLifetime):
			closedBy = "max_lifetime"
		case errors.Is(cause, ErrRecordingFailed):
			closedBy = "recording_failed"
		}
	}

	fields := []any{"os_user", s.OSUser, "duration", time.Since(s.start)}
	if closedBy != "" {
		fields = append(fields, "closed_by", closedBy)
	}
	s.Log.Info("session ended", fields...)

	// Kapanış sebebi olaya da giriyor: canlı bakan operatör için
	// "kullanıcı çıktı" ile "boşta kaldığı için kesildi" aynı şey değil.
	detail := "duration " + time.Since(s.start).Round(time.Second).String()
	if closedBy != "" {
		detail += ", closed by " + closedBy
	}
	s.publish(events.SessionEnded, detail)

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
