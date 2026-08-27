package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

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
		return nil, fmt.Errorf("config %s: %w", path, err)
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

	// Terminal açıkken düz HTTP, oturum cookie'sini ve terminal trafiğini
	// ağa açık bırakır. Loopback geliştirme için serbest; başka her adres
	// için reddediyoruz — "sonra HTTPS ekleriz" diye açılan bir bastion
	// öyle kalır.
	if c.HTTP.TerminalEnabled && !isLoopbackURL(c.HTTP.ExternalURL) &&
		!strings.HasPrefix(c.HTTP.ExternalURL, "https://") {
		return fmt.Errorf("http.terminal_enabled requires an https external_url (got %q)", c.HTTP.ExternalURL)
	}

	return nil
}

// isLoopbackURL, adresin yerel geliştirme adresi olup olmadığını söyler.
func isLoopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// OOBEnabled, OIDC destekli tarayıcı girişinin yapılandırılıp
// yapılandırılmadığını söyler (Validate tam/boş garantisini verdi).
func (c *Config) OOBEnabled() bool { return c.OIDC.IssuerURL != "" }
