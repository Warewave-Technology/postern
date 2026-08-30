package auth

// Aktif giriş kaynağı: panelin kapısını AYNI ANDA yalnızca bir kaynak açar.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/warewave/postern/internal/store"
)

/*
 * LoginSource, panel girişinin hangi kaynağa sorulduğu.
 *
 * ⚠️ NEDEN TEK DEĞER, İKİ BOOLEAN DEĞİL.
 *
 * "OIDC etkin" ve "LDAP etkin" diye iki bayrak, ikisinin birden açık
 * olduğu bir durumu TEMSİL EDİLEBİLİR yapardı. O durumun anlamı yok —
 * ama var olduğu anda, kural her yazma yolunda tekrarlanan bir kontrole
 * dönüşür: CLI'dan doğrudan yazan biri, iki isteğin yarışı, ya da
 * kontrolü eklemeyi unutan yeni bir uç onu bozar. Tek değerli bir
 * ayarda o durum hiç yoktur; kural şemanın kendisidir.
 *
 * SSH kapısı BUNA BAĞLI DEĞİL ve olmamalı: orada kimlik anahtarla
 * kanıtlanıyor ve panel kaynağını değiştirmek kimsenin sunucu erişimini
 * kesmemeli. Bu ayar yalnızca PANELİN kapısını seçiyor.
 */
type LoginSource string

const (
	// SourceLocal, postern'in kendi kimlik bilgileri. Hiçbir dizin
	// kaynağı seçilmediğinde geçerli olan geri dönüş yolu — ve acil
	// çıkış: dizin arızalanırsa host'tan buraya dönülür.
	SourceLocal LoginSource = "local"

	// SourceOIDC, kimlik sağlayıcı üzerinden tarayıcı akışı.
	SourceOIDC LoginSource = "oidc"

	// SourceLDAP, dizin kullanıcı adı + KURUMSAL parola.
	SourceLDAP LoginSource = "ldap"
)

// KeyLoginSource, ayarlar tablosundaki anahtar.
const KeyLoginSource = "auth.source"

// ErrUnknownSource: tanınmayan kaynak adı.
var ErrUnknownSource = errors.New("auth: unknown login source")

// ParseLoginSource, metni kaynağa çevirir.
//
// Tanımadığını REDDEDİYOR, bir varsayılana düşmüyor: yazım hatası olan
// bir ayarın sessizce yerel kapıyı açması, tam olarak kapatılmak istenen
// kapıyı açmak olurdu.
func ParseLoginSource(v string) (LoginSource, error) {
	switch LoginSource(strings.ToLower(strings.TrimSpace(v))) {
	case SourceLocal:
		return SourceLocal, nil
	case SourceOIDC:
		return SourceOIDC, nil
	case SourceLDAP:
		return SourceLDAP, nil
	}
	return "", fmt.Errorf("%w: %q (expected local, oidc or ldap)", ErrUnknownSource, v)
}

/*
 * ActiveLoginSource, saklanan kaynağı okur; saklanmamışsa TÜRETİR.
 *
 * ⚠️ TÜRETME, YÜKSELTMEYİ BOZMAMAK İÇİN. Bu ayar yokken kurulmuş bir
 * dağıtımda OIDC yapılandırılmışsa kapı zaten OIDC'ydi; körlemesine
 * "local" demek, çalışan bir kurulumu yükseltmenin kimsenin giremediği
 * bir panele dönüşmesi demekti.
 *
 * stored=false döndüğünde arayüz bunu SÖYLEMELİ: "seçilmedi, config
 * dosyasından türetildi" ile "seçildi" aynı şey değil.
 *
 * ⚠️ OKUMA HATASI YUTULMUYOR. Bir veritabanı arızasında varsayılana
 * düşmek, kapalı olması gereken bir kapıyı açardı; çağıran hatayı görüp
 * kapalı tarafta kalmalı.
 */
func ActiveLoginSource(ctx context.Context, db *store.Store, oidcConfigured bool) (src LoginSource, stored bool, err error) {
	v, err := db.Setting(ctx, KeyLoginSource)
	if errors.Is(err, store.ErrNotFound) {
		if oidcConfigured {
			return SourceOIDC, false, nil
		}
		return SourceLocal, false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("auth.ActiveLoginSource: %w", err)
	}

	parsed, perr := ParseLoginSource(v)
	if perr != nil {
		// Saklanan değer bozuk: türetilmiş bir varsayılana düşmek,
		// operatörün seçtiğini sandığı kapıdan BAŞKA birini açardı.
		return "", true, perr
	}
	return parsed, true, nil
}
