package auth

// OIDC yapılandırmasının veritabanındaki hâli.
//
// ⚠️ NEDEN DOSYADA DEĞİL: LDAP servis hesabı parolası için verilen
// kararın aynısı (internal/ldap/settings.go). İstemci sırrı düz metin
// olarak dosyada gezmesin, ve kurulum sunucuya girmeden yapılabilsin —
// ürünün "kurulumdan sonra host'a hiç dokunma" hedefi tam olarak bu.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/warewave/postern/internal/store"
)

const (
	KeyOIDCIssuer   = "oidc.issuer_url"
	KeyOIDCClientID = "oidc.client_id"
	// #nosec G101 -- kimlik bilgisi değil, settings tablosunun ANAHTAR adı
	KeyOIDCClientSecret = "oidc.client_secret"

	/*
	 * KeyOIDCManaged, "bu kurulumun OIDC ayarları ARTIK veritabanında".
	 *
	 * ⚠️ Var olma sebebi yükseltme günü. Config dosyasında oidc.* olan
	 * bir kurulum, bu işaret konana kadar DOSYAYI kullanmaya devam
	 * ediyor: aksi hâlde yükseltme, çalışan bir OIDC kurulumunu boş
	 * veritabanı satırlarıyla sessizce kapatırdı.
	 *
	 * İşaret bir kez konduğunda dosya bir daha okunmuyor — iki kaynak
	 * arasında "hangisi kazanır" sorusunu her okumada yeniden sormak,
	 * cevabın zamanla kaymasına açık kapı bırakırdı.
	 */
	KeyOIDCManaged = "oidc.managed_in_db"

	/*
	 * KeyOIDCGroupsClaim, grup adlarını taşıyan claim.
	 *
	 * ⚠️ ALAN VARDI, AYARI YOKTU. OIDCConfig.GroupsClaim ilk günden
	 * beri duruyor ve yorumu Entra'nın "roles", bazı kurulumların
	 * "memberOf" kullandığını söylüyor — ama onu dolduran hiçbir yol
	 * yazılmamıştı, yani pratikte "groups" sabitti. Entra ya da Okta
	 * kullanan bir kurum hiç grup göremiyordu ve sebebini de göremiyordu:
	 * ekranda ayarlanacak bir şey yoktu.
	 */
	KeyOIDCGroupsClaim = "oidc.groups_claim"

	/*
	 * KeyOIDCScopes, yetkilendirme isteğinde istenen kapsamlar.
	 *
	 * ⚠️ SABİTTİ ve eksikti: "openid email". `profile` YOKTU, oysa
	 * preferred_username çoğu sağlayıcıda tam olarak orada yaşıyor —
	 * yani postern kullanıcı adını isteyip istemediğini söylemeden
	 * bekliyordu ve gelmeyince e-posta eşleştirmesine düşüyordu.
	 * Okta ve Auth0 ayrıca grupları vermek için AÇIK bir kapsam
	 * istiyor; onu ekleyecek bir yer de yoktu.
	 */
	KeyOIDCScopes = "oidc.scopes"
)

// DefaultOIDCScopes, kapsam ayarlanmadığında istenenler.
//
// ⚠️ profile BURADA: preferred_username onun içinde geliyor ve
// postern'in kimlik yolunun tamamı o claim'e dayanıyor.
const DefaultOIDCScopes = "openid email profile"

// OIDCSecretKeys, şifrelenerek saklanması gereken OIDC ayarları.
var OIDCSecretKeys = map[string]bool{KeyOIDCClientSecret: true}

// ErrOIDCNotConfigured: veritabanında OIDC ayarı yok.
var ErrOIDCNotConfigured = errors.New("auth: oidc is not configured in the database")

// StoredOIDC, veritabanındaki OIDC ayarları.
type StoredOIDC struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	// GroupsClaim boşsa "groups" kullanılıyor (oidc.go).
	GroupsClaim string
	// Scopes boşsa DefaultOIDCScopes kullanılıyor.
	Scopes string
}

// OIDCManagedInDB, ayarların veritabanına taşınmış olduğu.
func OIDCManagedInDB(ctx context.Context, db *store.Store) bool {
	v, err := db.Setting(ctx, KeyOIDCManaged)
	return err == nil && strings.TrimSpace(v) != ""
}

/*
 * LoadOIDC, veritabanındaki OIDC ayarlarını okur.
 *
 * ⚠️ EKSİK ALAN HATA. Yarım bir yapılandırmadan istemci kurmaya
 * çalışmak, sağlayıcıya anlamsız bir istek atıp "ulaşılamıyor" demek
 * olurdu — oysa sorun ağda değil, ayarda.
 */
func LoadOIDC(ctx context.Context, db *store.Store) (StoredOIDC, error) {
	get := func(key string) (string, error) {
		v, err := db.Setting(ctx, key)
		if errors.Is(err, store.ErrNotFound) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(v), nil
	}

	var out StoredOIDC
	for key, dst := range map[string]*string{
		KeyOIDCIssuer:       &out.IssuerURL,
		KeyOIDCClientID:     &out.ClientID,
		KeyOIDCClientSecret: &out.ClientSecret,
		KeyOIDCGroupsClaim:  &out.GroupsClaim,
		KeyOIDCScopes:       &out.Scopes,
	} {
		v, err := get(key)
		if err != nil {
			return StoredOIDC{}, fmt.Errorf("auth.LoadOIDC[%s]: %w", key, err)
		}
		*dst = v
	}

	if out.IssuerURL == "" {
		return StoredOIDC{}, ErrOIDCNotConfigured
	}
	if out.ClientID == "" {
		return StoredOIDC{}, fmt.Errorf("auth.LoadOIDC: %s is set but %s is empty",
			KeyOIDCIssuer, KeyOIDCClientID)
	}
	// ClientSecret BOŞ OLABİLİR: public client + PKCE geçerli bir
	// kurulum (bkz. OIDCConfig.ClientSecret).
	return out, nil
}
