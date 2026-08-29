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
	KeyURL    = "ldap.url"
	KeyBindDN = "ldap.bind_dn"
	// #nosec G101 -- kimlik bilgisi değil, settings tablosunun ANAHTAR adı
	KeyBindPassword   = "ldap.bind_password"
	KeyUserBase       = "ldap.user_base"
	KeyUserFilter     = "ldap.user_filter"
	KeyGroupAttribute = "ldap.group_attribute"
	KeyGroupBase      = "ldap.group_base"
	KeyGroupFilter    = "ldap.group_filter"
	KeyGroupNameFrom  = "ldap.group_name_from"
	KeyGroupScope     = "ldap.group_scope"

	/*
	 * KeyAuthEnabled, dizin PAROLASIYLA panel girişinin açık olduğu.
	 *
	 * ⚠️ VARSAYILAN KAPALI ve bu bir güvenlik kararı: bu ayarı açmak
	 * postern'in kullanıcının KURUMSAL parolasını görmesi demek.
	 * Yapılandırmayı yapan kişinin bilerek açtığı bir kapı olmalı,
	 * LDAP'ı grup kaynağı olarak kuranın yanında gelen bir yan etki
	 * değil.
	 */
	KeyAuthEnabled = "ldap.auth_enabled"
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
		KeyGroupScope:     &cfg.GroupScope,
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

/*
 * CheckConnection, YALNIZCA bağlantıyı ve servis hesabını sınar.
 *
 * NEDEN AYRI: SourceFromStore dokuz alanın hepsini istiyor (New tam
 * yapılandırma doğruluyor), dolayısıyla "URL'im ve servis hesabım doğru
 * mu" sorusu ancak her şey doldurulduktan sonra sorulabiliyordu.
 * Sihirbazın ilk adımını sınanamaz yapan buydu: dokuz alandan hangisinin
 * yanlış olduğunu, dokuzu da yazdıktan sonra öğreniyordunuz.
 *
 * ⚠️ SAKLANAN DEĞERLERİ okur, gönderileni değil — Test ile aynı sözleşme.
 * Parola yazılırken sınamak, panelin sunucuya kimlik bilgisi ileten ayrı
 * bir ucu olması demekti; oysa aynı parola zaten kaydedilirken gidiyor
 * ve tek doğruluk kaynağı saklanan değer olmalı.
 */
func CheckConnection(ctx context.Context, db *store.Store) error {
	cfg, err := LoadConfig(ctx, db)
	if err != nil {
		return err
	}
	if cfg.URL == "" {
		return ErrNotConfigured
	}

	// ⚠️ New()'den GEÇMİYOR: New tam yapılandırma istiyor. Ama New'in
	// TAŞIMA kuralı burada da geçerli olmak zorunda — şifresiz ldap://
	// yalnızca loopback'te. Aksi hâlde bu uç, New'in reddettiği bir
	// bağlantıyı "çalışıyor" diye onaylayan bir yan kapı olurdu.
	if err := checkScheme(cfg.URL); err != nil {
		return err
	}

	s := &Source{cfg: cfg}
	conn, err := s.connect(ctx)
	if err != nil {
		return err
	}
	return conn.Close()
}
