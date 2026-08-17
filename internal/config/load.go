package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"
	"golang.org/x/crypto/ssh"
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

	for i := range cfg.Targets {
		if cfg.Targets[i].KeyFile != "" && !filepath.IsAbs(cfg.Targets[i].KeyFile) {
			cfg.Targets[i].KeyFile = filepath.Join(base, cfg.Targets[i].KeyFile)
		}
	}

	if cfg.Recording.Dir != "" && !filepath.IsAbs(cfg.Recording.Dir) {
		cfg.Recording.Dir = filepath.Join(base, cfg.Recording.Dir)
	}

	err = cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}

	return &cfg, nil
}

// Validate checks the config for missing fields, conflicting names and
// nonexistent files. It reports the first problem found; the error message
// names the offending field, target or path.
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

	for i, target := range c.Targets {
		if target.Name == "" {
			return fmt.Errorf("targets[%d]: missing required field: name", i)
		}

		fields := []struct {
			name string
			val  string
		}{
			{"host", target.Host},
			{"user", target.User},
			{"key_file", target.KeyFile},
			{"host_key", target.HostKey},
		}

		for _, f := range fields {
			if f.val == "" {
				return fmt.Errorf("targets[%s]: missing required field: %s", target.Name, f.name)
			}
		}

		if _, err := os.Stat(target.KeyFile); err != nil {
			return fmt.Errorf("targets[%s]: key_file: %w", target.Name, err)
		}

		if target.Port < 1 || target.Port > 65535 {
			return fmt.Errorf("targets[%s]: invalid target port", target.Name)
		}
	}

	target, found := findDuplicate(c.Targets, func(t TargetConfig) string { return t.Name })
	if found {
		return fmt.Errorf("duplicate target name: %s", target)
	}

	user, found := findDuplicate(c.Users, func(t UserConfig) string { return t.Name })
	if found {
		return fmt.Errorf("duplicate username: %s", user)
	}

	for _, user := range c.Users {
		if len(user.PublicKeys) == 0 {
			return fmt.Errorf("user[%s]: has no public key", user.Name)
		}

		for i, publicKey := range user.PublicKeys {
			_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
			if err != nil {
				return fmt.Errorf("user[%s], public_keys[%d] %w", user.Name, i, err)
			}
		}
	}

	return nil
}

func findDuplicate[T any, K comparable](list []T, getKey func(T) K) (K, bool) {
	seen := make(map[K]bool)

	for _, item := range list {
		key := getKey(item)
		if seen[key] {
			return key, true
		}
		seen[key] = true
	}

	var zero K
	return zero, false
}
