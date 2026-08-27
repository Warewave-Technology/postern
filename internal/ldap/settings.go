package ldap

// Ayarların veritabanından okunması.
//
// Config dosyasında DEĞİL: panelden düzenlenip test edilebilsin, servis
// hesabı parolası düz metin olarak dosyada gezmesin (S5.1 kararı).

import (
	"context"
	"errors"
	"fmt"

	"github.com/warewave/postern/internal/store"
)

// Ayar anahtarları. Noktalı ad alanı settings tablosunun sözleşmesi.
const (
	KeyURL            = "ldap.url"
	KeyBindDN         = "ldap.bind_dn"
	KeyBindPassword   = "ldap.bind_password"
	KeyUserBase       = "ldap.user_base"
	KeyUserFilter     = "ldap.user_filter"
	KeyGroupAttribute = "ldap.group_attribute"
	KeyGroupBase      = "ldap.group_base"
	KeyGroupFilter    = "ldap.group_filter"
	KeyGroupNameFrom  = "ldap.group_name_from"
)

// SecretKeys, şifrelenerek saklanması gereken ayarlar.
var SecretKeys = map[string]bool{KeyBindPassword: true}

// ErrNotConfigured: LDAP ayarlanmamış. Hata değil bir DURUM — kurulum
// grupları OIDC claim'inden okuyor olabilir.
var ErrNotConfigured = errors.New("ldap: not configured")

// LoadConfig, ayarları veritabanından okur.
//
// ldap.url yoksa ErrNotConfigured döner: çağıran claim kaynağına düşer.
func LoadConfig(ctx context.Context, db *store.Store) (Config, error) {
	get := func(key string) (string, error) {
		v, err := db.Setting(ctx, key)
		if errors.Is(err, store.ErrNotFound) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		return v, nil
	}

	url, err := get(KeyURL)
	if err != nil {
		return Config{}, err
	}
	if url == "" {
		return Config{}, ErrNotConfigured
	}

	cfg := Config{URL: url}
	for key, dst := range map[string]*string{
		KeyBindDN:         &cfg.BindDN,
		KeyBindPassword:   &cfg.BindPassword,
		KeyUserBase:       &cfg.UserBase,
		KeyUserFilter:     &cfg.UserFilter,
		KeyGroupAttribute: &cfg.GroupAttribute,
		KeyGroupBase:      &cfg.GroupBase,
		KeyGroupFilter:    &cfg.GroupFilter,
		KeyGroupNameFrom:  &cfg.GroupNameFrom,
	} {
		v, err := get(key)
		if err != nil {
			return Config{}, fmt.Errorf("ldap.LoadConfig[%s]: %w", key, err)
		}
		*dst = v
	}
	return cfg, nil
}

// SourceFromStore, ayarları okuyup kaynağı kurar.
// LDAP ayarlanmamışsa ErrNotConfigured.
func SourceFromStore(ctx context.Context, db *store.Store) (*Source, error) {
	cfg, err := LoadConfig(ctx, db)
	if err != nil {
		return nil, err
	}
	return New(cfg)
}
