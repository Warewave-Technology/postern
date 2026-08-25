package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"
)

// Load reads, parses and validates the config file at path.
func Load(path string) (*Config, error) {
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

	if cfg.Database.Path != "" && !filepath.IsAbs(cfg.Database.Path) {
		cfg.Database.Path = filepath.Join(base, cfg.Database.Path)
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

	// Dosyanın VAR OLMASI aranmıyor, yolun verilmiş olması aranıyor:
	// veritabanını ilk açılışta store.Open kendisi oluşturur.
	if c.Database.Path == "" {
		return fmt.Errorf("database.path is empty")
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

	return nil
}

// OOBEnabled, OIDC destekli tarayıcı girişinin yapılandırılıp
// yapılandırılmadığını söyler (Validate tam/boş garantisini verdi).
func (c *Config) OOBEnabled() bool { return c.OIDC.IssuerURL != "" }
