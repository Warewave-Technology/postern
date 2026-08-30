package auth

// Aktif giriş kaynağı: panelin kapısını AYNI ANDA yalnızca bir kaynak açar.

import (
	"context"
	"errors"
	"fmt"
	"strconv"
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

/*
 * KeyAdminGroup, YÖNETİCİ yetkisi veren grubun adı.
 *
 * ⚠️ Burada, ldap paketinde DEĞİL: grup adı OIDC claim'inden de
 * gelebiliyor ve iki kaynağın paylaştığı bir kavramı birinin paketine
 * koymak, diğerini o pakete bağımlı kılıyordu.
 *
 * ⚠️ Bu grubu ele geçiren yalnızca rol almıyor: panele giriyor, yani
 * DENETİM GÜNLÜĞÜNÜ ve OTURUM KAYITLARINI da okuyor. Rol almaktan
 * farklı bir şey — geçmişe erişim.
 */
const KeyAdminGroup = "ldap.admin_group"

/*
 * InAdminGroup, verilen grup listesinin yönetici grubunu içerip
 * içermediğini söyler.
 *
 * ⚠️ YALNIZCA GERÇEKTEN ÇÖZÜLMÜŞ gruplarla çağrılmalı. "Bulamadım" ya
 * da "cevap veremedim" hâlinde boş bir listeyle çağrılırsa cevap
 * "hayır" olur — ki bu güvenli taraf, ama çağıranın o ayrımı zaten
 * yapmış olması gerekir.
 *
 * Karşılaştırma harf duyarsız: dizinler grup adlarını öyle sayıyor ve
 * "SysAdmins" yazan bir ayarın "sysadmins" grubunu görmemesi sessiz bir
 * yetki kaybı olurdu.
 */
func InAdminGroup(ctx context.Context, db *store.Store, groups []string) (bool, error) {
	want, err := db.Setting(ctx, KeyAdminGroup)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	want = strings.TrimSpace(want)
	if want == "" {
		return false, nil
	}
	for _, g := range groups {
		if strings.EqualFold(strings.TrimSpace(g), want) {
			return true, nil
		}
	}
	return false, nil
}

/*
 * KeyAutoCreate, kimliği doğrulanan ama postern hesabı olmayan kişi
 * için hesabın KENDİLİĞİNDEN açılıp açılmayacağı.
 *
 * ⚠️ VARSAYILAN KAPALI ve bu bir güvenlik kararı. "IdP'de hesabın
 * olması postern'de hesabın olması demek değil" kuralı ürünün
 * başından beri yazılı; açık varsayılan onu sessizce tersine
 * çevirirdi. Kapalıyken kapı da kapanmıyor: kişi onay kuyruğuna
 * düşüyor ve bunu ekranda görüyor.
 */
const KeyAutoCreate = "auth.auto_create"

// AutoCreateEnabled, hesapların kendiliğinden açılıp açılmadığı.
//
// Okunamayan ya da bozuk değer KAPALI sayılıyor: bir veritabanı
// arızası, hesap açan bir kapıyı kendiliğinden açmamalı.
func AutoCreateEnabled(ctx context.Context, db *store.Store) bool {
	v, err := db.Setting(ctx, KeyAutoCreate)
	if err != nil {
		return false
	}
	on, perr := strconv.ParseBool(strings.TrimSpace(v))
	return perr == nil && on
}

/*
 * KeySetupCompleted, kurulum sihirbazının TAMAMLANDIĞI an.
 *
 * ⚠️ VAR OLMA SEBEBİ: sihirbaz "isteğe bağlı bir ekran" olarak
 * bırakıldığında atlanıyordu, ve atlandığında geriye kaynağı
 * seçilmemiş — yani kapısı config dosyasından TÜRETİLEN — bir kurulum
 * kalıyordu. Ürünün en kritik kararı, keşfedilmeyi bekleyen bir menü
 * maddesi olamaz.
 *
 * Zaman damgası, boolean değil: "ne zaman kuruldu" sorusunun cevabı
 * denetim açısından bedava geliyor.
 */
const KeySetupCompleted = "setup.completed_at"

// SetupCompleted, kurulum sihirbazının tamamlanmış olduğu.
//
// Okunamayan değer TAMAMLANMAMIŞ sayılıyor: bir veritabanı arızasında
// sihirbazı göstermek, kurulmamış bir sistemi kurulmuş sanmaktan
// zararsız.
func SetupCompleted(ctx context.Context, db *store.Store) bool {
	v, err := db.Setting(ctx, KeySetupCompleted)
	return err == nil && strings.TrimSpace(v) != ""
}
