// Package config defines postern's YAML configuration schema and loading.
//
// SÖZLEŞME (S3): config yalnızca ALTYAPI taşır — dinleme adresi, anahtar
// yolları, veritabanı ve kayıt dizini. Kimlik ve yetki verisi (kullanıcı,
// rol, hedef) burada YAŞAMAZ: tek kaynağı veritabanıdır ve yalnızca
// yetkili kanallardan (bastion hostundaki postern CLI; ileride OIDC'li
// API) değiştirilir. YAML'a kullanıcı yazmak diye bir şey yoktur.
package config

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Listen   ListenConfig   `yaml:"listen"`
	HostKey  string         `yaml:"host_key"` // path to the bastion's own host private key
	CA       CAConfig       `yaml:"ca"`
	Database DatabaseConfig `yaml:"database"`
	Session  SessionConfig  `yaml:"session"`
	Sync     SyncConfig     `yaml:"sync"`

	// Auth, bastion'ın KABUL ETTİĞİ giriş yolları.
	Auth AuthConfig `yaml:"auth"`

	// TargetProbe, hedefe bağlanıldığında makineyi TANIMA denemesi.
	// VARSAYILAN KAPALI — bkz. TargetProbeConfig.
	TargetProbe TargetProbeConfig `yaml:"target_probe"`

	// SecretKeyFile, veritabanındaki şifreli ayarları açan ana anahtar
	// (`postern secret init` üretir). Boş bırakılabilir: o zaman şifreli
	// ayar okunamaz/yazılamaz ama bastion'ın geri kalanı çalışır.
	//
	// ⚠️ Bu dosya veritabanıyla AYNI yerde durmamalı: ikisi birlikte
	// sızarsa şifrelemenin tek faydası (yedek/kopya senaryosu) kaybolur.
	SecretKeyFile string          `yaml:"secret_key_file"`
	Recording     RecordingConfig `yaml:"recording"`

	// HTTP ve OIDC birlikte OOB girişini açar (S3.3). İkisi de boş
	// bırakılabilir: o zaman bastion yalnızca public key kabul eder —
	// mevcut kurulumlar hiçbir şey değiştirmeden çalışmaya devam eder.
	HTTP HTTPConfig `yaml:"http"`
	OIDC OIDCConfig `yaml:"oidc"`
}

/*
 * AuthConfig, bastion'a girişin kabul edilen yolları.
 *
 * ⚠️ Sıfır değeri "anahtar girişi AÇIK" olmalı — bu yüzden alan
 * `PublicKeyLogin *bool`, düz bool değil. Düz bool olsaydı yapılandırma
 * dosyasında satırı olmayan her mevcut kurulum, yükseltmeden sonra
 * anahtarla giremez hale gelirdi: sessizce herkesi kapı dışında
 * bırakan bir varsayılan.
 */
type AuthConfig struct {
	/*
	 * PublicKeyLogin, kullanıcıların kendi anahtarlarıyla girmesine
	 * izin verir. Yazılmazsa AÇIK.
	 *
	 * NEDEN KAPATILABİLİR: iki bacak var ve karıştırılıyor. Kullanıcının
	 * anahtarı GELEN bacakta, "postern'e kim olduğunu kanıtlama" işi;
	 * sertifika GİDEN bacakta, "hedefe bu kullanıcı adına açabilirim"
	 * işi. Tamamen SSO ile çalışan bir kurumda gelen bacaktaki anahtar
	 * kapısı hiç kullanılmıyor ama açık duruyor — ve o kapı IdP'ye
	 * BAKMIYOR. Kullanılmayan bir kapıyı kapatmak, saldırı yüzeyini
	 * kullanıldığı kadarına indirir.
	 *
	 * ⚠️ Kapatıldığında PublicKeyCallback HİÇ KURULMUYOR: sunucu
	 * publickey yöntemini teklif bile etmiyor. Kabul edip reddetmek,
	 * istemcinin deneme hakkını yakması ve duruşun dışarıdan
	 * görünmemesi demekti.
	 */
	PublicKeyLogin *bool `yaml:"public_key_login"`
}

// PublicKeyLoginEnabled, yazılmamış alan için varsayılan (açık).
func (a AuthConfig) PublicKeyLoginEnabled() bool {
	if a.PublicKeyLogin == nil {
		return true
	}
	return *a.PublicKeyLogin
}

/*
 * TargetProbeConfig, hedefte KOMUT ÇALIŞTIRARAK yapılan tanıma.
 *
 * ⚠️ VARSAYILAN KAPALI VE ÖYLE KALMALI. Kapalıyken postern hedefte
 * kullanıcının oturumu dışında hiçbir şey çalıştırmaz; hedef hakkında
 * bildiği her şey el sıkışmadan gelir (SSH afişi, anahtar türü, süre).
 * Bu, bir bastion'ın taşıyabileceği en dar yetki ve birçok kurumun
 * denetim politikası tam olarak bunu şart koşuyor.
 *
 * Açıldığında ne değişir, açıkça:
 *
 *   1. postern, kullanıcının AÇTIĞI BAĞLANTI üzerinde ek bir exec kanalı
 *      açar ve sabit birkaç okuma komutu çalıştırır. Komutlar hedefin
 *      kendi günlüklerinde O KULLANICININ adına görünür — kullanıcının
 *      yazmadığı komutlar, kullanıcının hesabında.
 *   2. Bu yüzden her koşu admin_log'a yazılır: kimin bağlantısında,
 *      hangi hedefte, ne çalıştırıldı.
 *
 * ⚠️ KOMUT LİSTESİ YAPILANDIRILAMAZ ve bu kasıtlı. Operatörün komut
 * yazabildiği bir alan, config dosyasına erişebilen herkese denetim
 * altındaki HER MAKİNEDE uzaktan komut çalıştırma yetkisi verirdi —
 * yani bastion'ı tam da engellemek için var olduğu şeye çevirirdi.
 * Çalışanlar upstream.ProbeCommands içinde, salt okunur ve sabit.
 */
type TargetProbeConfig struct {
	// Enabled, tanımayı açar. Varsayılan false.
	Enabled bool `yaml:"enabled"`

	// Refresh, aynı hedefin ne kadar sonra yeniden sorulacağı.
	// Yazılmazsa 24 saat. Her oturumda sormak, hedefin günlüklerini
	// postern'in gürültüsüyle doldururdu.
	Refresh time.Duration `yaml:"refresh"`

	// Timeout, tanıma komutlarının tamamı için üst sınır.
	// Yazılmazsa 5 saniye.
	//
	// ⚠️ Kısa olması ŞART: tanıma kullanıcının oturumuyla aynı TCP
	// bağlantısını paylaşıyor ve asılı bir komut o bağlantıyı meşgul
	// eder. Oturumun kendisi hiçbir koşulda tanımayı BEKLEMEZ.
	Timeout time.Duration `yaml:"timeout"`
}

// RefreshOrDefault, yazılmamış Refresh için varsayılan.
func (c TargetProbeConfig) RefreshOrDefault() time.Duration {
	if c.Refresh <= 0 {
		return 24 * time.Hour
	}
	return c.Refresh
}

// TimeoutOrDefault, yazılmamış Timeout için varsayılan.
func (c TargetProbeConfig) TimeoutOrDefault() time.Duration {
	if c.Timeout <= 0 {
		return 5 * time.Second
	}
	return c.Timeout
}

// HTTPConfig, tarayıcıya bakan uçların dinleyicisi.
type HTTPConfig struct {
	// Addr, dinlenecek adres (":8088" gibi).
	Addr string `yaml:"addr"`

	// ExternalURL, KULLANICININ tarayıcısından erişilen kök
	// ("https://bastion.warewave.io:8088" gibi). Login linkleri ve OIDC
	// redirect_url bununla kurulur — Addr'dan türetilemez: bastion NAT/
	// proxy arkasında olabilir, ":8088" dış dünyada bir anlam taşımaz.
	ExternalURL string `yaml:"external_url"`

	// TrustedProxies, X-Forwarded-For'una güvenilecek kaynak adresler
	// ("10.0.0.0/8", "127.0.0.1"). BOŞ = başlık hiç okunmuyor.
	//
	// ⚠️ TLS için ters vekil ŞART koştuğumuz hâlde bu alan yoktu ve
	// sonucu ölçüldü: vekil arkasında bütün istemciler tek adrese
	// çöküyor, parola tahmini gecikmesi hesap bazına iniyor ve
	// kimliği doğrulanmamış biri "admin" hesabını beş dakikada bir
	// istekle panelden süresiz kilitleyebiliyordu. Ayrıntı ve ölçüm
	// httpapi/trustedproxy.go'da.
	//
	// ⚠️ YALNIZCA GERÇEKTEN ÖNÜNDEKİ VEKİLİ YAZ. Buraya geniş bir
	// aralık yazmak, o aralıktaki herkese kendi hız sınırı anahtarını
	// seçtirmek olur.
	TrustedProxies []string `yaml:"trusted_proxies"`

	// TerminalEnabled, tarayıcıdaki web terminalini açar. VARSAYILAN
	// KAPALI ve bu bilinçli bir güvenlik kararı: web terminali, SPA'daki
	// herhangi bir XSS'i hedef makinede komut çalıştırma yetkisine
	// çevirir. Bugün aynı XSS yalnızca API'yi kullanabilir — sınırlı bir
	// zarar. Terminale ihtiyacı olmayan kurulum o yüzeyi hiç taşımasın;
	// kod var diye kapı açık olmak zorunda değil.
	//
	// Açan kurulum için şartlar: HTTPS (external_url https), sıkı CSP
	// (securityHeaders zaten kuruyor) ve WS upgrade'inde Origin kontrolü.
	TerminalEnabled bool `yaml:"terminal_enabled"`
}

// OIDCConfig, kimlik sağlayıcısı. auth.OIDCConfig'e birebir taşınır.
type OIDCConfig struct {
	IssuerURL string `yaml:"issuer_url"`
	ClientID  string `yaml:"client_id"`

	// ClientSecret public client'ta boş — PKCE onun yerini tutuyor.
	ClientSecret string `yaml:"client_secret"`
}

// CAConfig, sertifika otoritesi.
//
// key_file, `postern ca init` ile üretilen özel anahtar. serve her oturumda
// bununla sertifika kesecek; ca.Load izin kontrolünü kendisi yapıyor.
type CAConfig struct {
	KeyFile string `yaml:"key_file"`
}

// DatabaseConfig, kalıcı durumun tutulduğu PostgreSQL bağlantısı.
//
// S3'ten itibaren kullanıcılar, roller, hedefler ve oturum denetim kaydı
// burada. Yönetimi paket doc'undaki sözleşmeye tabi: CLI ya da API,
// config değil.
type DatabaseConfig struct {
	// DSN, PostgreSQL bağlantı dizesi. İki biçim de kabul edilir:
	//
	//	postgres://postern:parola@db.local:5432/postern?sslmode=verify-full
	//	host=db.local user=postern dbname=postern sslmode=verify-full
	//
	// sslmode yazılmamışsa store.Open "verify-full" varsayar. libpq'nun
	// varsayılanı olan "prefer" TLS kurulamazsa düz metne SESSİZCE
	// düşer; bir bastion'ın kimlik verisi için bu kabul edilemez.
	//
	// ⚠️ Bu dize PAROLA taşır. Config dosyasına yazmak yerine
	// POSTERN_DATABASE_DSN ortam değişkenini kullanmak tercih edilir —
	// dolu olduğunda buradaki değerin yerine geçer. Şemadaki diğer
	// sırların aksine bu, veritabanının KENDİSİNE ulaşmak için gerekli
	// olduğundan settings tablosuna konulamıyor.
	DSN string `yaml:"dsn"`
}

type ListenConfig struct {
	Addr string `yaml:"addr"` // e.g. ":2222"

	/*
	 * ExternalAddr, KULLANICININ ssh ile bağlandığı adres
	 * ("bastion.warewave.io:2222" gibi).
	 *
	 * ⚠️ Addr'dan TÜRETİLEMEZ — http.external_url'in var olma
	 * gerekçesinin aynısı: ":2222" dış dünyada bir şey ifade etmiyor,
	 * "0.0.0.0" hiç etmiyor, ve bastion NAT ya da yük dengeleyici
	 * arkasında olabilir.
	 *
	 * Yazılmazsa panel şunu türetiyor: host'u http.external_url'den,
	 * portu Addr'dan. Kurulumların çoğunda doğru olan bu; olmadığı yerde
	 * burası yazılır. Bu değer yalnızca panelin GÖSTERDİĞİ komutu
	 * etkiliyor — hiçbir erişim kararına girmiyor.
	 */
	ExternalAddr string `yaml:"external_addr"`

	// --- Sınırlar ---
	//
	// Hepsinde 0 (yazılmamış) = varsayılan, -1 = BİLEREK sınırsız.
	// Varsayılanlar burada değil kullanan yerde çözülüyor; Validate saf
	// kalsın ve "yazılmadı" ile "sıfır yazıldı" ayrılabilsin diye.
	//
	// ⚠️ Bu sınırlar dağıtık bir saldırıyı DURDURMAZ. Yaptıkları şey
	// kesintiyi bozulmaya çevirmek: bastion ölmek yerine yük atar.

	// MaxConns, eşzamanlı SSH bağlantısı üst sınırı (varsayılan 256).
	MaxConns int `yaml:"max_conns"`

	// MaxConnsPerIP, tek kaynaktan eşzamanlı bağlantı (varsayılan 8).
	//
	// ⚠️ L4 yük dengeleyici ya da TCP vekil ARKASINDA kapatılmalı (-1):
	// orada bütün kullanıcılar dengeleyicinin IP'siyle görünür ve bu
	// sınır 9. kullanıcıda kesintiye döner. postern PROXY protokolü
	// konuşmuyor.
	MaxConnsPerIP int `yaml:"max_conns_per_ip"`

	// HandshakeTimeout, kimlik doğrulanana kadar tanınan süre
	// (varsayılan 30s).
	//
	// Kapattığı açık somut: SSH sürüm satırı bayt bayt okunuyor, yani
	// saatte bir bayt gönderen bir istemci kimliğini hiç doğrulamadan
	// bir goroutine ve bir dosya tanıtıcısı tutabiliyordu.
	//
	// Tarayıcı girişi (OOB) bu süreden UZUN sürer ve süre onay
	// beklenirken ayrıca uzatılır — bkz. internal/sshd/limits.go.
	// Yani buraya oobTimeout'tan kısa bir değer yazmak girişi bozmaz.
	HandshakeTimeout time.Duration `yaml:"handshake_timeout"`

	// MaxAuthTries, bağlantı başına kimlik doğrulama denemesi
	// (varsayılan 4; x/crypto'nun kendi varsayılanı 6).
	//
	// ⚠️ Çok düşürmeyin: OpenSSH doğru anahtarı bulana kadar ajandaki
	// TÜM anahtarları sırayla sunar, yani 5 anahtarı olan bir geliştirici
	// 4'te "too many authentication failures" alır. Çözüm istemci
	// tarafında IdentitiesOnly=yes.
	MaxAuthTries int `yaml:"max_auth_tries"`

	// MaxChannelsPerConn, bağlantı başına eşzamanlı oturum kanalı
	// (varsayılan 10).
	//
	// Bu kümedeki TEK kimlik doğrulama SONRASI sınır: her kanal bir
	// hedef bağlantısı, bir .cast dosyası ve bir denetim satırı demek.
	MaxChannelsPerConn int `yaml:"max_channels_per_conn"`

	// MaxPendingLogins, aynı anda onay bekleyen tarayıcı girişi
	// (varsayılan 32).
	MaxPendingLogins int `yaml:"max_pending_logins"`
}

// Sınırların çözülmüş değerleri. Varsayılanı burada vermek, "0 =
// varsayılan" sözleşmesinin tek yerde durmasını sağlıyor.
func resolveLimit(v, def int) int {
	switch {
	case v == 0:
		return def
	case v < 0:
		return 0 // sınırsız
	default:
		return v
	}
}

func (c ListenConfig) MaxConnsOrDefault() int      { return resolveLimit(c.MaxConns, 256) }
func (c ListenConfig) MaxConnsPerIPOrDefault() int { return resolveLimit(c.MaxConnsPerIP, 8) }
func (c ListenConfig) MaxAuthTriesOrDefault() int  { return resolveLimit(c.MaxAuthTries, 4) }
func (c ListenConfig) MaxChannelsOrDefault() int   { return resolveLimit(c.MaxChannelsPerConn, 10) }
func (c ListenConfig) MaxPendingLoginsOrDefault() int {
	return resolveLimit(c.MaxPendingLogins, 32)
}

func (c ListenConfig) HandshakeTimeoutOrDefault() time.Duration {
	if c.HandshakeTimeout == 0 {
		return 30 * time.Second
	}
	if c.HandshakeTimeout < 0 {
		return 0 // sınırsız
	}
	return c.HandshakeTimeout
}

// SessionConfig, oturum kanalının davranış sınırları.
type SessionConfig struct {
	// AcceptEnv, kullanıcıdan hedefe geçmesine izin verilen ortam
	// değişkeni adları. Sondaki * joker: "LC_*" tüm LC_ ile
	// başlayanları kapsar.
	//
	// Yazılmazsa varsayılan LANG ve LC_* (OpenSSH'ın yaygın AcceptEnv
	// yapılandırmasıyla aynı). BOŞ LİSTE yazmak "hiçbiri" demek —
	// "yazmamak" ile "boş yazmak" farklı şeyler.
	//
	// ⚠️ Buraya PATH, LD_PRELOAD, BASH_ENV gibi bir ad eklemek hedefte
	// NE ÇALIŞACAĞINI kullanıcının eline verir. Whitelist'in var olma
	// sebebi tam olarak bu.
	AcceptEnv []string `yaml:"accept_env"`

	// IdleTimeout, iki yönde de hiç bayt akmayan oturumun kapatılma
	// süresi. VARSAYILAN KAPALI (0).
	//
	// Kapalı olması bilinçli: "boşta" tanımı bayt akışıdır, tuş vuruşu
	// değil. Bir saat süren `make -j` çıktı üretmediği anda ölmemeli.
	// Makul görünen bir varsayılan koymak, o derlemeyi ortasından kesmek
	// demek olurdu.
	//
	// ÖLÜ EŞE KARŞI DEĞİL: TCP keepalive onu zaten ~2,5 dakikada fark
	// ediyor. Bunun gerekçesi denetim — üretim makinesinde unutulmuş
	// root kabuğu.
	IdleTimeout time.Duration `yaml:"idle_timeout"`

	/*
	 * SFTP, `subsystem sftp` kanalını açar. VARSAYILAN KAPALI.
	 *
	 * ⚠️ Kapalı olması bilinçli. Bu kanal uzun süre HİÇ yoktu ve
	 * gerekçesi ölçülmüştü: transfer terminal kaydına ham ikili olarak
	 * düşüyor, "kim hangi dosyayı aldı" cevapsız kalıyordu. Artık
	 * dosya seviyesinde denetleniyor (internal/sftpaudit) — ama
	 * varsayılan açık gelseydi, yükseltme yapan bir operatör hiçbir
	 * şey yapmadan yeni bir veri ÇIKIŞ yolu kazanırdı. Yeni bir çıkış
	 * yolu, açıkça istenerek açılır.
	 *
	 * Açıkken her dosya olayı session_files tablosuna yazılıyor;
	 * yazılamıyorsa oturum kapanıyor.
	 */
	SFTP bool `yaml:"sftp"`

	// MaxLifetime, oturumun mutlak ömrü. VARSAYILAN KAPALI (0).
	//
	// Gerekçesi somut: süreli rol atamaları (AssignRole expiresAt)
	// oturum ORTASINDA yeniden denetlenmiyor. Süresi dolmadan bir dakika
	// önce açılan bir oturum, bugün kendi yetkisinden sonsuza kadar uzun
	// yaşıyor.
	MaxLifetime time.Duration `yaml:"max_lifetime"`
}

type RecordingConfig struct {
	Dir string `yaml:"dir"` // session recordings root

	// RecordInput defaults to false on purpose: keystrokes include
	// passwords. See postern-PLAN.md S1.7, design note 4.
	RecordInput bool `yaml:"record_input"`

	/*
	 * Retain, kayıtların saklanma süresi ("90d", "2160h").
	 *
	 * ⚠️ VARSAYILAN "HİÇ SİLME" ve bu bilinçli. Budama denetim kanıtı
	 * silmek demek; ayarı yazmayan bir kurulumda postern'in kendi
	 * başına kanıt silmesi, sakladığı şeyin ne olduğunu anlamamak
	 * olurdu. Operatör süreyi SÖYLEYENE kadar hiçbir şey silinmiyor.
	 *
	 * Sınırsız büyümenin cevabı bu ayar DEĞİL: cevabı MinFree, ve o
	 * varsayılan olarak açık.
	 */
	Retain string `yaml:"retain"`

	/*
	 * MinFree, yeni oturum açmayı reddetmeye başladığımız boş alan
	 * ("2GiB"). Boş bırakılırsa varsayılan kullanılıyor; "0" kapatıyor.
	 *
	 * ⚠️ VARSAYILAN AÇIK, ve gerekçesi dolu diskin bugün ne yaptığı:
	 * postern kayıt tutamayınca oturumu reddediyor (denetim öncelikli
	 * politika, doğru karar) ama proxy AÇIK oturumları da kapatıyor.
	 * Yani disk dolduğunda yalnızca yeni girişler durmuyor, çalışan
	 * işler de kesiliyor.
	 *
	 * Eşik aynı reddi DAHA ERKEN veriyor: yeni oturum reddediliyor,
	 * çalışanlar yaşamaya devam ediyor ve operatörün yer açmak için
	 * zamanı oluyor. "Reddetmeye başlamak" bir kayıp değil; kayıp,
	 * onu diskin kendisinin haber vermesini beklemek.
	 */
	MinFree string `yaml:"min_free"`
}

// DefaultRecordingMinFree, MinFree boş bırakıldığında geçerli olan.
//
// 1 GiB: birkaç uzun oturumu rahat karşılayacak ve operatöre yer açması
// için zaman bırakacak kadar; boş bir diskte kimseyi rahatsız etmeyecek
// kadar küçük.
const DefaultRecordingMinFree = 1 << 30

// SyncConfig, periyodik dizin senkronizasyonu.
//
// ⚠️ VARSAYILAN KAPALI. Açıldığında bu döngü OTOMATİK OLARAK YETKİ
// İPTAL EDER; yanlış yapılandırılmış bir dizin ya da fark edilmeyen bir
// kesinti, kimsenin giremediği bir bastion demek.
//
// Tavanlar neden config'te, settings tablosunda değil: bunlar kimlik
// verisi değil, otomatik toplu iptalin ÜST SINIRI. Onu yükseltebilmek
// için host'a erişmek gerekmeli — admin bayrağının yalnızca CLI'dan
// verilebilmesiyle aynı gerekçe. (LDAP'ın BAĞLANTI ayarları settings
// tablosunda kalıyor; panelden düzenlenmesi gereken onlar.)
type SyncConfig struct {
	Enabled bool `yaml:"enabled"`

	// Interval, koşular arası süre (varsayılan 15m).
	Interval time.Duration `yaml:"interval"`

	// Grace, kullanıcı dizinde bulunamadıktan sonra iptal için beklenen
	// süre (varsayılan 1h). Kısa bir çoğaltma gecikmesi ya da bakım
	// penceresi yetkileri silmesin diye.
	Grace time.Duration `yaml:"grace"`

	// Timeout, tek bir koşunun üst sınırı (varsayılan 5m).
	Timeout time.Duration `yaml:"timeout"`

	// --- patlama yarıçapı tavanları ---
	//
	// MaxZeroFraction ve MinZeroFloor BİRLİKTE aşılmalı: küçük
	// kurumlarda oran tek kişiyle aşılır, büyüklerinde taban tek başına
	// anlamsız kalır.
	MaxZeroFraction    float64 `yaml:"max_zero_fraction"`    // varsayılan 0.10
	MinZeroFloor       int     `yaml:"min_zero_floor"`       // varsayılan 3
	MaxUnknownFraction float64 `yaml:"max_unknown_fraction"` // varsayılan 0.25
	MaxRevokePerRun    int     `yaml:"max_revoke_per_run"`   // varsayılan 25

	// DryRun, kararları hesaplar ve raporlar ama HİÇBİR ŞEY YAZMAZ.
	// Açmadan önce bir süre bununla koşturmak doğru yol.
	DryRun bool `yaml:"dry_run"`
}

func (c SyncConfig) IntervalOrDefault() time.Duration {
	if c.Interval <= 0 {
		return 15 * time.Minute
	}
	return c.Interval
}

func (c SyncConfig) GraceOrDefault() time.Duration {
	if c.Grace <= 0 {
		return time.Hour
	}
	return c.Grace
}

func (c SyncConfig) TimeoutOrDefault() time.Duration {
	if c.Timeout <= 0 {
		return 5 * time.Minute
	}
	return c.Timeout
}

func (c SyncConfig) MaxZeroFractionOrDefault() float64 {
	if c.MaxZeroFraction <= 0 {
		return 0.10
	}
	return c.MaxZeroFraction
}

func (c SyncConfig) MinZeroFloorOrDefault() int {
	if c.MinZeroFloor <= 0 {
		return 3
	}
	return c.MinZeroFloor
}

func (c SyncConfig) MaxUnknownFractionOrDefault() float64 {
	if c.MaxUnknownFraction <= 0 {
		return 0.25
	}
	return c.MaxUnknownFraction
}

func (c SyncConfig) MaxRevokePerRunOrDefault() int {
	if c.MaxRevokePerRun <= 0 {
		return 25
	}
	return c.MaxRevokePerRun
}

/*
 * RetainDuration, kayıt saklama süresini çözer.
 *
 * ⚠️ ÇÖZÜLEMEYEN DEĞER HATA, "varsayılana dön" DEĞİL. "90gun" yazan
 * operatör, sessizce "hiç silme"ye düşerse diskinin neden dolduğunu
 * anlamaz; tersi daha kötü olurdu — yanlış çözülen bir süre, olması
 * gerekenden fazlasını siler.
 */
func (r RecordingConfig) RetainDuration() (time.Duration, error) {
	v := strings.TrimSpace(r.Retain)
	if v == "" || v == "0" {
		return 0, nil
	}
	if rest, ok := strings.CutSuffix(v, "d"); ok {
		days, err := strconv.Atoi(rest)
		if err != nil || days < 0 {
			return 0, fmt.Errorf("recording.retain: %q is not a number of days", v)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("recording.retain: %q is not a duration", v)
	}
	return d, nil
}

/*
 * MinFreeBytes, eşiği bayta çevirir.
 *
 * "2GiB", "500MiB", "1073741824" kabul ediliyor. Boş bırakmak
 * VARSAYILANI seçiyor; açıkça "0" yazmak KAPATIYOR — ikisi ayrı
 * niyetler ve aynı değere düşmemeleri gerekiyor.
 */
func (r RecordingConfig) MinFreeBytes() (uint64, error) {
	v := strings.TrimSpace(r.MinFree)
	if v == "" {
		return DefaultRecordingMinFree, nil
	}
	if v == "0" {
		return 0, nil
	}

	mult := uint64(1)
	for suffix, m := range map[string]uint64{
		"KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40,
	} {
		if rest, ok := strings.CutSuffix(v, suffix); ok {
			v, mult = strings.TrimSpace(rest), m
			break
		}
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("recording.min_free: %q is not a size "+
			"(try 2GiB, 500MiB or a number of bytes)", r.MinFree)
	}
	return n * mult, nil
}

/*
 * SSHEndpoint, kullanıcıya GÖSTERİLECEK ssh adresi.
 *
 * ⚠️ NEDEN VAR: panel "ssh kullanıcı:hedef@bastion" komutunu
 * kopyalatıyor ve <bastion> yerine gerçek bir adres yazması gerekiyor.
 * Yer tutucu bırakmak, kopyalanan komutu yapıştırıldığı anda bozuk
 * yapardı; dinleme adresini olduğu gibi vermek ise ":2222" ya da
 * "0.0.0.0:2222" gibi dışarıda anlamsız bir şey verirdi.
 *
 * Sıra: açıkça yazılmış listen.external_addr; yoksa host'u
 * http.external_url'den (operatörün ZATEN beyan ettiği dış kimlik),
 * portu listen.addr'dan.
 *
 * Çözülemezse boş host dönüyor ve panel kopyalama seçeneğini hiç
 * göstermiyor — çalışmayacak bir komut vermektense hiç vermemek.
 */
func (c Config) SSHEndpoint() (host string, port int) {
	port = addrPort(c.Listen.Addr)

	if ext := strings.TrimSpace(c.Listen.ExternalAddr); ext != "" {
		h, p, err := net.SplitHostPort(ext)
		if err != nil {
			// Portsuz yazılmış: adresin tamamı host, port dinlemeden.
			return ext, port
		}
		if n, cerr := strconv.Atoi(p); cerr == nil {
			port = n
		}
		return h, port
	}

	if c.HTTP.ExternalURL != "" {
		if u, err := url.Parse(c.HTTP.ExternalURL); err == nil && u.Hostname() != "" {
			return u.Hostname(), port
		}
	}
	return "", port
}

// addrPort, "host:port" ya da ":port" biçiminden portu çıkarır.
// Çözülemezse SSH'ın varsayılanı (22) dönüyor.
func addrPort(addr string) int {
	if _, p, err := net.SplitHostPort(strings.TrimSpace(addr)); err == nil {
		if n, cerr := strconv.Atoi(p); cerr == nil && n > 0 {
			return n
		}
	}
	return 22
}
