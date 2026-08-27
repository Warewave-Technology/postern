package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
)

// DatabaseDSNEnv, database.dsn'i geçersiz kılan ortam değişkeni.
//
// Ayrı bir değişken olmasının sebebi işlemsel: bağlantı dizesi parola
// taşır ve config dosyaları sürüm kontrolüne, yedeklere, hata ayıklama
// paketlerine girer.
const DatabaseDSNEnv = "POSTERN_DATABASE_DSN"

// Load reads, parses and validates the config file at path.
func Load(path string) (*Config, error) {
	// #nosec G304 -- yol --config bayrağından gelir; operatör girdisi
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}

	var cfg Config

	err = yaml.UnmarshalWithOptions(data, &cfg, yaml.Strict())
	if err != nil {
		// ⚠️ HATA METNİ OLDUĞU GİBİ AKTARILMIYOR.
		//
		// goccy/go-yaml, ayrıştırma hatasına KAYNAK SATIRLARINI
		// ekliyor — ve config'in kaynak satırlarında veritabanı
		// parolası (database.dsn) ile OIDC istemci sırrı var. Bu hata
		// açılışta stderr'e düşüyor, oradan journald'a, log
		// toplayıcıya ve destek paketine gidiyor. (Ölçüldü: iki sır da
		// hata metninde göründü.)
		//
		// FormatError(inclSource=false) satır/sütun bilgisini ve
		// sebebi koruyor, kaynağı atıyor — teşhis için yeterli.
		return nil, fmt.Errorf("config %s: %s", path, yaml.FormatError(err, false, false))
	}

	base := filepath.Dir(path)
	if cfg.HostKey != "" && !filepath.IsAbs(cfg.HostKey) {
		cfg.HostKey = filepath.Join(base, cfg.HostKey)
	}

	if cfg.Recording.Dir != "" && !filepath.IsAbs(cfg.Recording.Dir) {
		cfg.Recording.Dir = filepath.Join(base, cfg.Recording.Dir)
	}

	if cfg.CA.KeyFile != "" && !filepath.IsAbs(cfg.CA.KeyFile) {
		cfg.CA.KeyFile = filepath.Join(base, cfg.CA.KeyFile)
	}

	if cfg.SecretKeyFile != "" && !filepath.IsAbs(cfg.SecretKeyFile) {
		cfg.SecretKeyFile = filepath.Join(base, cfg.SecretKeyFile)
	}

	// Ortam değişkeni config dosyasının ÜSTÜNE yazar. Sıra bu yönde:
	// parolayı dosyada tutmamak istenen davranış, dolayısıyla ortamdan
	// gelen değerin kazanması gerekiyor.
	if env := os.Getenv(DatabaseDSNEnv); env != "" {
		cfg.Database.DSN = env
	}

	err = cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}

	return &cfg, nil
}

// Validate checks the config for missing fields and nonexistent files.
// It reports the first problem found; the error message names the
// offending field or path.
func (c *Config) Validate() error {
	if c.Listen.Addr == "" {
		return fmt.Errorf("listen.addr empty")
	}

	if c.HostKey == "" {
		return fmt.Errorf("host_key empty")
	}

	if _, err := os.Stat(c.HostKey); err != nil {
		return fmt.Errorf("host_key: %w", err)
	}

	if c.CA.KeyFile == "" {
		return fmt.Errorf("ca.key_file is empty")
	}

	// Bağlanabilirlik BURADA sınanmıyor, yalnızca dizenin verilmiş
	// olması: Validate saf bir fonksiyon ve ağ çağrısı yapmamalı.
	// Bağlantı hatası store.Open'dan gelir.
	if c.Database.DSN == "" {
		return fmt.Errorf("database.dsn is empty (or set %s)", DatabaseDSNEnv)
	}

	if c.Recording.Dir == "" {
		return fmt.Errorf("recording.dir is empty")
	}

	// Sınırlar: yalnızca ANLAMSIZ olanı reddet. Varsayılan atamak
	// Validate'in işi değil — "yazılmadı" ile "sıfır yazıldı" ayrımı
	// kullanan yerde çözülüyor (bkz. ListenConfig accessor'ları).
	if c.Listen.HandshakeTimeout < 0 && c.Listen.HandshakeTimeout != -1 {
		return fmt.Errorf("listen.handshake_timeout is negative (use -1 for unlimited)")
	}
	if c.Listen.HandshakeTimeout > 0 && c.Listen.HandshakeTimeout < 5*time.Second {
		// 5 saniyeden kısa bir süre yavaş bir ağdaki meşru istemciyi de
		// keser; sınırın amacı asılı kalanı atmak, yavaş olanı değil.
		return fmt.Errorf("listen.handshake_timeout %s is too short (minimum 5s)", c.Listen.HandshakeTimeout)
	}
	if c.Listen.MaxConns > 0 && c.Listen.MaxConnsPerIP > c.Listen.MaxConns {
		return fmt.Errorf("listen.max_conns_per_ip (%d) exceeds listen.max_conns (%d)",
			c.Listen.MaxConnsPerIP, c.Listen.MaxConns)
	}
	if c.Session.IdleTimeout < 0 {
		return fmt.Errorf("session.idle_timeout is negative")
	}
	if c.Session.MaxLifetime < 0 {
		return fmt.Errorf("session.max_lifetime is negative")
	}
	// Senkronizasyon: yalnızca ANLAMSIZ olanı reddet.
	if c.Sync.Enabled {
		if !c.OOBEnabled() {
			// Senkronizasyon LDAP'a bağlı ve LDAP ayarları OIDC'li
			// kurulumla birlikte geliyor. OIDC'siz bir kurulumda döngü
			// hiçbir zaman bir dizin bulamaz ve her koşuda "skipped"
			// yazardı — açıkça reddetmek daha dürüst.
			return fmt.Errorf("sync.enabled requires oidc and http to be configured")
		}
		if c.Sync.Interval < 0 || c.Sync.Grace < 0 || c.Sync.Timeout < 0 {
			return fmt.Errorf("sync durations must not be negative")
		}
		if c.Sync.Interval > 0 && c.Sync.Interval < time.Minute {
			return fmt.Errorf("sync.interval %s is too short (minimum 1m)", c.Sync.Interval)
		}
		if c.Sync.MaxZeroFraction < 0 || c.Sync.MaxZeroFraction > 1 {
			return fmt.Errorf("sync.max_zero_fraction must be between 0 and 1")
		}
		if c.Sync.MaxUnknownFraction < 0 || c.Sync.MaxUnknownFraction > 1 {
			return fmt.Errorf("sync.max_unknown_fraction must be between 0 and 1")
		}
		// Grace bir koşudan kısaysa hiçbir zaman "bekletme" yaşanmaz:
		// kullanıcı ilk bulunamadığı koşunun ardından gelen ikinci
		// koşuda iptal edilir. Bu, penceresiz çalışmak demek.
		if c.Sync.GraceOrDefault() < c.Sync.IntervalOrDefault() {
			return fmt.Errorf("sync.grace (%s) is shorter than sync.interval (%s); "+
				"the grace window would never apply",
				c.Sync.GraceOrDefault(), c.Sync.IntervalOrDefault())
		}
	}

	if c.Session.IdleTimeout > 0 && c.Session.MaxLifetime > 0 &&
		c.Session.MaxLifetime < c.Session.IdleTimeout {
		// Ömür sınırı boşta kalma sınırından kısaysa ikincisi hiç
		// tetiklenemez: sessizce ölü bir ayar olurdu.
		return fmt.Errorf("session.max_lifetime (%s) is shorter than session.idle_timeout (%s)",
			c.Session.MaxLifetime, c.Session.IdleTimeout)
	}

	// OOB girişi ya TAM açık ya tam kapalı. Yarım yapılandırma (issuer
	// var, http yok gibi) en kötü ihtimalle çalışıyor GÖRÜNÜR: linkler
	// üretilemez ama public key yolu işlediği için kimse fark etmez.
	oobFields := map[string]string{
		"http.addr":         c.HTTP.Addr,
		"http.external_url": c.HTTP.ExternalURL,
		"oidc.issuer_url":   c.OIDC.IssuerURL,
		"oidc.client_id":    c.OIDC.ClientID,
	}
	var missing, present []string
	for name, v := range oobFields {
		if v == "" {
			missing = append(missing, name)
		} else {
			present = append(present, name)
		}
	}
	if len(present) > 0 && len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("incomplete OIDC login config: %s set but %s missing",
			strings.Join(present, ", "), strings.Join(missing, ", "))
	}

	// Terminal, OOB/web yapılandırması olmadan anlamsızdır: linkleri ve
	// oturumu o katman kuruyor.
	if c.HTTP.TerminalEnabled && !c.OOBEnabled() {
		return fmt.Errorf("http.terminal_enabled requires the oidc and http sections")
	}

	// ⚠️ HTTPS KURALI TERMİNALE DEĞİL, WEB YÜZEYİNİN TAMAMINA BAĞLI.
	//
	// Kural eskiden yalnızca terminal_enabled iken uygulanıyordu. Ama
	// terminal KAPALIYKEN de aynı kaynak üzerinden şunlar servis
	// ediliyor: oturum çerezi, OIDC kod değişimi, admin API'si (kullanıcı
	// ve rol yönetimi), denetim kaydı ve OTURUM KAYITLARININ TAMAMI.
	// Düz HTTP'de bunların hepsi ağda açık gidiyor ve çerez de Secure
	// olamıyor — yani panele giren herkesin oturumu, aynı ağdaki birine
	// açık.
	//
	// Terminalin kapalı olması bu yüzeyi güvenli yapmıyor, yalnızca bir
	// parçasını kaldırıyor.
	if c.OOBEnabled() && !isLoopbackURL(c.HTTP.ExternalURL) &&
		!strings.HasPrefix(strings.ToLower(c.HTTP.ExternalURL), "https://") {
		return fmt.Errorf("http.external_url must be https (got %q) — the session "+
			"cookie, the admin API and every session recording are served from it",
			c.HTTP.ExternalURL)
	}

	return nil
}

// isLoopbackURL, adresin yerel geliştirme adresi olup olmadığını söyler.
func isLoopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" {
		return true
	}
	// net.IP: "127.0.0.1" kadar "127.1" ve "::ffff:127.0.0.1" de
	// loopback'tir; üç yazımı elle listelemek hem eksik hem kırılgan.
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// OOBEnabled, OIDC destekli tarayıcı girişinin yapılandırılıp
// yapılandırılmadığını söyler (Validate tam/boş garantisini verdi).
func (c *Config) OOBEnabled() bool { return c.OIDC.IssuerURL != "" }
