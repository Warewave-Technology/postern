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
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/ca"
	"github.com/Warewave-Technology/postern/internal/events"
	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/policy"
	"github.com/Warewave-Technology/postern/internal/record"
	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/upstream"
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

	// Live, akan oturumların defteri: yöneticinin kesme düğmesi buradan
	// çalışıyor. nil olabilir — o zaman kayıt tutulmuyor ve hiçbir
	// oturum kesilemiyor (Live'ın bütün metotları nil-güvenli).
	Live *Live
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
// probeWriteTimeout, yoklamanın denetim ve gözlem yazmalarının üst
// sınırı. Yoklamanın kendi süresinden BAĞIMSIZ: yazmalar veritabanına
// gidiyor, hedefe değil.
const probeWriteTimeout = 10 * time.Second

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
		/*
		 * ⚠️ YOKLAMANIN SÜRESİ YAZMALARI KAPSAMIYOR — VE KAPSADIĞI HÂLİ
		 * ÖLÇÜLDÜ.
		 *
		 * Tek bir bağlam hepsini sarıyordu. Süre dolduğunda Probe'un
		 * düşmesi zaten beklenen şey; ama AYNI bağlam denetim yazmasına
		 * da geçtiği için satır da yazılamıyordu. Yani "yoklama zaman
		 * aşımına uğradı" durumu, tam olarak kaydedilmesi gereken durum
		 * olduğu hâlde, kendi kaydını da imkânsız kılıyordu.
		 *
		 * Dış bağlam zaten iptal edilemez (WithoutCancel); yazmalar
		 * kendi kısa süreleriyle ondan türüyor.
		 */
		probeCtx, cancel := context.WithTimeout(ctx, deps.Probe.Timeout)
		defer cancel()

		p, perr := conn.Probe(probeCtx)

		/*
		 * ⚠️ DENETİM SATIRI DENEMEYE YAZILIYOR, BAŞARIYA DEĞİL — VE
		 * TERSİ ÖLÇÜLDÜ.
		 *
		 * Satır eskiden Probe ve RecordTargetProbe'un ikisi de
		 * başarılı olduktan SONRA yazılıyordu. Komutlar ise
		 * bağlantının kendisinde, kullanıcının kimliğiyle ZATEN
		 * çalışmış oluyordu: hedefin kendi günlüklerinde o kişinin
		 * hesabı altında görünüyorlar.
		 *
		 * Yani kullanıcının yazmadığı komutlar hedefte koşuyor ve
		 * kullanılabilir çıktı üretmeyen her koşuda denetim yüzeyi
		 * "hiçbir şey olmadı" diyordu. README'nin operatöre güvenmesini
		 * söylediği `via = probe` süzgeci, tam da ALIŞILMADIK davranan
		 * makineleri — yani bir araştırmacının arayacağı makineleri —
		 * eksik raporluyordu. Özelliğin bu çizgiyi geçme gerekçesi,
		 * kodun tutmadığı bir denetim sözüydü.
		 */
		detail := fmt.Sprintf("ran on this user's connection: %s",
			strings.Join(upstream.ProbeCommands, "; "))
		if perr != nil {
			detail += "; target answered nothing: " + perr.Error()
		}
		writeCtx, wcancel := context.WithTimeout(ctx, probeWriteTimeout)
		defer wcancel()

		if err := deps.Store.LogAdmin(writeCtx, store.AdminLogEntry{
			Actor: byUser, Via: "probe", Action: "target.probe",
			Entity: targetName, Details: detail,
		}); err != nil {
			log.Warn("target probe not audited", "error", err)
		}

		if perr != nil {
			log.Warn("target probe failed", "error", perr)
			return
		}
		if err := deps.Store.RecordTargetProbe(writeCtx, targetName, p); err != nil {
			log.Warn("target probe not recorded", "error", err)
			return
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
	Username string

	/*
	 * AccountID, bağlantının bağlı olduğu users.id.
	 *
	 * ⚠️ AD DEĞİL KİMLİK, VE BOŞ GEÇİLEMİYOR. Ad yeniden
	 * kullanılabiliyor (purge onu serbest bırakıyor), kimlik kalıcı.
	 * Bunu kapıda çözüp buraya taşımak, kanal açılırken "bu bağlantı
	 * HÂLÂ o kişiye mi ait" sorusunun sorulabilmesinin tek yolu.
	 */
	AccountID string

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

	// endDetail, Run'ın hesapladığı kapanış cümlesi. Yayını
	// Close yapıyor: olay, ended_at yazıldıktan SONRA gitmeli.
	endDetail string

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

	/*
	 * ⚠️ BAĞLANTI HER KANALDA YENİDEN SORULUYOR — VE SORULMADIĞI HÂLİ
	 * ÖLÇÜLDÜ.
	 *
	 * Kimlik yalnızca el sıkışmada denetleniyordu. Bir kez kurulmuş SSH
	 * bağlantısı (bir `ssh -N`, ya da pek çok kurumsal ssh_config'de
	 * varsayılan olan ControlMaster) süresiz açık kalabiliyor ve her
	 * yeni kanal buraya geliyor. İki ölçülmüş sonuç:
	 *
	 *  1. HESABI KAPATMAK SSH'I KAPATMIYORDU. `state = deleted` —
	 *     kayıtlı oturumu olan gerçek bir kullanıcı için TEK işten
	 *     çıkarma kolu, çünkü DeleteUser onları reddediyor — kurulu
	 *     bağlantıyı hiç etkilemiyordu: silinmiş hesap her kanalda
	 *     yeni imzalı sertifika almaya devam ediyordu.
	 *
	 *  2. AD SERBEST BIRAKILINCA BAĞLANTI YENİ SAHİBE ÇÖZÜLÜYORDU.
	 *     Bağlantı yalnızca AD taşıyordu; purge adı bıraktıktan sonra
	 *     aynı metin başka bir gerçek insanın satırına çözülüyor,
	 *     ayrılan kişinin bağlantısı yeni kişinin os_user'ı ve
	 *     rolleriyle çalışıyor ve açtığı her oturum denetim defterine
	 *     ONUN adına yazılıyordu. Denetim önceliği olan bir üründe
	 *     yanlış insana yazılmış bir kayıt, eksik olandan daha kötü:
	 *     yüzeyinde şüpheli olduğunu gösteren hiçbir şey yok.
	 *
	 * Kimliğe bakan tek bir sorgu ikisini birden kapatıyor: purge, adı
	 * ancak ZATEN 'deleted' olan bir satırdan bırakabiliyor
	 * (PurgeAccount o koşulu dayatıyor), yani "bağlı olduğum satır
	 * silinmiş mi" sorusu hem kapatmayı hem ad devrini görüyor.
	 *
	 * ⚠️ 'inactive' BURADA REDDEDİLMİYOR — anahtar kapısının aksine.
	 * Orası el sıkışma: hesabın o an doğrulanmış olmasını istemek
	 * doğru. Burası kurulmuş bir oturumun içi ve pasifleşme "kaynak
	 * bir süredir doğrulamadı" demek; onunla canlı bir oturumu düşürmek
	 * durgunluk taramasını oturum katiline çevirirdi. Panelin
	 * accountStillOpen'ı da aynı çizgiyi çekiyor.
	 */
	if req.AccountID == "" {
		// Kapılardan biri kimliği bağlamayı unutmuş: bu bir programlama
		// hatası ve doğru cevap reddetmek — ada düşmek, yukarıdaki iki
		// arızayı geri getirirdi.
		log.Error("session refused: request is not bound to an account id")
		return nil, fmt.Errorf("proxy.Open: %w", ErrAccessDenied)
	}
	if err := deps.Store.RefuseIfDeletedByID(ctx, req.AccountID); err != nil {
		if errors.Is(err, store.ErrAccessDenied) || errors.Is(err, store.ErrNotFound) {
			log.Warn("session refused: the account this connection belongs to is gone",
				"account_id", req.AccountID)
			return nil, fmt.Errorf("proxy.Open: %w", ErrAccessDenied)
		}
		log.Error("account state lookup failed", "error", err)
		return nil, fmt.Errorf("proxy.Open: %w", ErrUnavailable)
	}

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
		f      *os.File
		path   string
	)
	defer func() {
		if opened {
			return
		}
		if rec != nil {
			_ = rec.Close()
		} else if f != nil {
			// rec kurulamadıysa dosyayı kimse kapatmıyordu.
			_ = f.Close()
		}

		/*
		 * ⚠️ YARIM KALAN KAYIT DOSYASI SİLİNİYOR.
		 *
		 * ÖLÇÜLEN ARIZA: Records.Create dosyayı açtıktan sonra
		 * NewWriter ya da StartSession başarısız olursa, diskte
		 * yalnızca asciicast başlığı içeren ve HİÇBİR OTURUMA AİT
		 * OLMAYAN bir .cast kalıyordu. Hiçbir sorgu onu tanımıyor,
		 * hiçbir şey temizlemiyordu.
		 *
		 * Arşivleme bunu görünür bir soruna çeviriyor: budayıcının
		 * kapısı varsayılan olarak reddediyor, yani kimliği
		 * çözülemeyen bu dosyalar sonsuza dek tutulur ve diski
		 * doldururdu. Kanıt kaybı yok: oturum hiç başlamadı.
		 */
		if path != "" {
			if rmErr := os.Remove(path); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
				log.Warn("could not remove the abandoned recording file",
					"path", path, "error", rmErr)
			}
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

	f, path, err = deps.Records.Create(id)
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

	/*
	 * ⚠️ KESİLEBİLİRLİK, SINIRLARLA AYNI MEKANİZMA.
	 *
	 * Yönetici kesmesi burada üçüncü bir kapanış sebebi olarak
	 * ekleniyor; boşta kalma ve ömür sınırı zaten aynı yoldan
	 * çalışıyor ve o yol TestIdleSessionIsClosedAndRecorded ile uçtan
	 * uca kanıtlı: Broker.Run ctx.Done()'da uyanıyor, yarım SFTP
	 * transferlerini yazıyor, iki kanalı da kapatıyor; Close ise kaydı
	 * kapatıp denetim satırına ended_at yazıyor. Yani kesme, yeni bir
	 * yıkım yolu icat etmiyor — kanıtlanmış olanı kullanıyor.
	 *
	 * ⚠️ DEFTERE YAZMA bound()'dan SONRA: iptal zinciri yukarıdan
	 * aşağı kuruluyor ve deftere en içteki cancel verilmeli, yoksa
	 * kesme sınırların kurduğu katmanları atlar ve Cause() sebebi
	 * kaybolurdu.
	 *
	 * ⚠️ VE Open'A TAŞINAMAZ. Open ile Run arasında oturumun listede
	 * görünüp kesilemediği kısa bir pencere var; onu kapatmak için
	 * kaydı Open'a almak CAZİP ama YANLIŞ: web kapısı Run'a
	 * context.WithoutCancel'lı ayrı bir ağaç veriyor
	 * (httpapi/terminal.go). Open'ın ctx'inden türeyen bir cancel
	 * deftere girer, Terminate true döner ve kimsenin izlemediği bir
	 * bağlamı iptal ederdi — yani düğme SSH'ta çalışıp web
	 * terminalinde sessizce yalan söylerdi.
	 */
	ctx, terminate := context.WithCancelCause(ctx)
	defer terminate(nil)
	s.deps.Live.add(s.ID, terminate)

	/*
	 * ⚠️ DEFTERDEN DÜŞME BURADA DEĞİL, Close'DA — ÇÜNKÜ DEFTER KAPANIŞIN
	 * "BİTTİ Mİ" SİNYALİ.
	 *
	 * Burada `defer s.deps.Live.remove(s.ID)` vardı ve Run döner dönmez
	 * çalışıyordu. Close ise ÇAĞIRANIN defer'inde, yani Run'dan SONRA
	 * (sshd/channel.go ve httpapi/terminal.go, ikisi de aynı desende).
	 * Aradaki pencerede defter BOŞ ama Close hâlâ çalışıyor: denetim
	 * satırı kapatılmamış, kayıt arşiv kuyruğuna yazılmamış olabiliyor.
	 *
	 * Kapanış tam olarak o defteri "her şey bitti mi" diye sorguluyor
	 * (sshd: waitForSessionsToClose). Süreçte Serve'in dönmesi main'in
	 * çıkması ve veritabanının kapanması demek — o pencerede yarım
	 * kalan yazma "sql: database is closed" ile düşüyor ve kayıt hiç
	 * yüklenmiyor, "arşivlenmemiş budanmaz" kuralı gereği diskte
	 * kalıyor.
	 *
	 * Kayıt Close'a taşındığında defter girdisi Close'u DA kapsıyor ve
	 * soru doğru cevabı veriyor.
	 *
	 * ⚠️ SÖZLEŞME: Run'ı çağıran Close'u da çağırmak ZORUNDA. İki kapı
	 * da Close'u Run'dan ÖNCE defer ediyor, yani sıra yapısal olarak
	 * garanti. Yeni bir kapı eklenirse aynı deseni izlemeli, yoksa
	 * oturum defterde sonsuza kadar "akıyor" görünür.
	 */

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
	var closedBy, terminatedBy string
	if cause := context.Cause(ctx); cause != nil {
		switch {
		case errors.Is(cause, ErrIdleTimeout):
			closedBy = "idle_timeout"
		case errors.Is(cause, ErrMaxLifetime):
			closedBy = "max_lifetime"
		case errors.Is(cause, ErrRecordingFailed):
			closedBy = "recording_failed"
		case errors.Is(cause, ErrTerminated):
			// ⚠️ JETON SABİT, AKTÖR AYRI ALANDA. cause.Error() burada
			// ham iç metni ("proxy: session terminated by an
			// administrator: admin") hem log alanına hem panelin canlı
			// akışına basardı. closed_by makine tarafından okunan bir
			// jeton; "kim" ayrı bir alan olarak duruyor ki ikisi de
			// kendi işini yapsın.
			closedBy = "terminated"
			terminatedBy, _ = TerminatedBy(cause)
		}
	}

	fields := []any{"os_user", s.OSUser, "duration", time.Since(s.start)}
	if closedBy != "" {
		fields = append(fields, "closed_by", closedBy)
	}
	if terminatedBy != "" {
		fields = append(fields, "terminated_by", terminatedBy)
	}
	s.Log.Info("session ended", fields...)

	// Kapanış sebebi olaya da giriyor: canlı bakan operatör için
	// "kullanıcı çıktı" ile "boşta kaldığı için kesildi" aynı şey değil.
	detail := "duration " + time.Since(s.start).Round(time.Second).String()
	if closedBy != "" {
		detail += ", closed by " + closedBy
	}
	if terminatedBy != "" {
		// ⚠️ Olay akışında "kim" ŞART. events.Event'in oturum kimliği
		// alanı yok (bus.go); ikinci bir yönetici akışa bakarken
		// "birinin oturumu kesildi" ile "yönetici X kesti" arasındaki
		// farkı başka hiçbir yerden okuyamaz.
		detail += " (" + terminatedBy + ")"
	}

	/*
	 * ⚠️ OLAY BURADAN DEĞİL, Close'DAN YAYINLANIYOR.
	 *
	 * ÖLÇÜLEN SIRA HATASI: publish burada yapılıyordu ama ended_at'i
	 * çağıranın `defer sess.Close(ctx)`i yazıyor — yani olay HER ZAMAN
	 * satır kapanmadan önce gidiyordu. Paneli olayla tazeleyen yönetici,
	 * bir veritabanı gidiş-dönüşü boyunca oturumu hâlâ "running"
	 * görüyordu. Kesme düğmesinde bu, "bastım ve hiçbir şey olmadı"
	 * diye okunurdu.
	 *
	 * Detay burada hesaplanıyor (süre ve sebep yalnızca burada belli),
	 * yayın Close'da yapılıyor.
	 */
	s.endDetail = detail

	return err
}

// Close, oturumu kapatır: kayıt dosyası, denetim satırı, hedef bağlantısı.
// İkinci çağrı no-op — çağıran defer'la koyabilsin diye.
func (s *Session) Close(ctx context.Context) {
	if s == nil || s.closed {
		return
	}
	s.closed = true

	// ⚠️ DEFTERDEN DÜŞME EN SONDA (bkz. Run'daki not): girdi, denetim
	// satırı kapanıp kayıt arşiv kuyruğuna yazılana kadar durmalı.
	// Kapanış "her şey bitti mi" sorusunu o deftere soruyor.
	defer s.deps.Live.remove(s.ID)

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
	closeCtx := context.WithoutCancel(ctx)
	if serr := s.deps.Store.EndSession(closeCtx, s.ID, time.Now()); serr != nil {
		s.Log.Error("end session failed", "error", serr)
	}

	/*
	 * ⚠️ ARŞİV KUYRUĞUNA YAZMA — VE BU BİR VERİTABANI SATIRI, AĞ DEĞİL.
	 *
	 * Oturum yolunun yükleme ile TEK teması burası. Yükleyicinin
	 * kendisi (internal/archive) proxy.Deps'in üyesi değil: Open ona
	 * ulaşamıyor, dolayısıyla nesne deposunun bir kesintisi oturumu
	 * reddedemez. Buraya bir S3 çağrısı koymak, bastion'ı bulut
	 * sağlayıcısının çalışma süresine zincirlemek olurdu.
	 *
	 * Hata YUTULMUYOR ama oturumu da ETKİLEMİYOR: satır yazılamazsa
	 * kayıt yerelde kalıyor ve budayıcı ona dokunmuyor (varsayılan
	 * reddetme). Yani en kötü hâl "yüklenmedi", "kayboldu" değil.
	 */
	if qerr := s.deps.Store.QueueArchive(closeCtx, s.ID); qerr != nil {
		s.Log.Error("could not queue the recording for archiving", "error", qerr)
	}

	if s.conn != nil {
		_ = s.conn.Close()
	}

	// ⚠️ YAYIN EN SONDA: yukarıdaki EndSession satırı kapattı. Olayla
	// tetiklenen her tazeleme artık kapanmış bir satır okuyor.
	//
	// Run hiç çalışmadıysa (ör. web terminalinde upgrade başarısız)
	// endDetail boş: SessionStarted da yayınlanmamıştı, dolayısıyla
	// karşılığı olmayan bir "ended" olayı üretmiyoruz.
	if s.endDetail != "" {
		s.publish(events.SessionEnded, s.endDetail)
	}
}

// unusedModel, model paketini import listesinde tutar (Target tipi
// store'dan geliyor ama okuyucu için burada anılması yararlı).
var _ = model.Target{}
