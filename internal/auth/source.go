package auth

// Aktif giriş kaynağı: panelin kapısını AYNI ANDA yalnızca bir kaynak açar.

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

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

/*
 * Zaman temelli hesap iptalinin ayarları.
 *
 * ⚠️ NEDEN ZAMAN: OIDC'de kaynağa "bu kişi hâlâ var mı" diye
 * SORULAMIYOR — bir claim ancak kullanıcı giriş yaparken geliyor. Yani
 * IdP'de kapatılmış bir hesap, kişi bir daha hiç girmezse postern'de
 * süresiz ayakta kalıyor. Elimizdeki tek ölçüt, kaynağın o kişiyi en
 * son ne zaman doğruladığı.
 *
 * ⚠️ VARSAYILANLAR CÖMERT VE BU KASITLI. Bu sayaç "işten ayrıldı"yı
 * değil "bir süredir kendini kanıtlamadı"yı ölçüyor; üç haftalık bir
 * tatil yanlış pozitif üretiyor. Bedeli düşük tutan şey, pasifleşmenin
 * TEK BİR GİRİŞLE geri alınması — ve kaynak kişiyi gerçekten kapattıysa
 * o giriş zaten olmuyor.
 */
const (
	KeyConfirmTTL = "auth.confirm_ttl"
	KeyDeleteTTL  = "auth.delete_after"

	// DefaultConfirmTTL, doğrulanmayan hesabın pasifleşme süresi.
	DefaultConfirmTTL = 45 * 24 * time.Hour
	// DefaultDeleteTTL, pasif hesabın 'deleted' işaretlenme süresi.
	DefaultDeleteTTL = 180 * 24 * time.Hour
)

// ConfirmTTL, hesabın doğrulanmadan kalabileceği süre. 0 = KAPALI.
func ConfirmTTL(ctx context.Context, db *store.Store) time.Duration {
	return durationSetting(ctx, db, KeyConfirmTTL, DefaultConfirmTTL)
}

// DeleteTTL, pasif hesabın silinmiş işaretlenme süresi. 0 = KAPALI.
func DeleteTTL(ctx context.Context, db *store.Store) time.Duration {
	return durationSetting(ctx, db, KeyDeleteTTL, DefaultDeleteTTL)
}

/*
 * durationSetting, süre ayarını okur.
 *
 * ⚠️ ÇÖZÜMLENEMEYEN DEĞER VARSAYILANA DÜŞÜYOR, SIFIRA DEĞİL. Sıfır
 * "kapalı" demek ve bir yazım hatasının korumayı sessizce kapatması,
 * korumanın hiç olmamasından daha kötü — operatör kapalı olduğunu
 * bilmez. "0" YAZILDIĞINDA kapanıyor: o bilinçli bir karar.
 */
func durationSetting(ctx context.Context, db *store.Store, key string, fallback time.Duration) time.Duration {
	v, err := db.Setting(ctx, key)
	if err != nil {
		return fallback
	}
	d, perr := ParseAccountDuration(v)
	if perr != nil {
		return fallback
	}
	return d
}

/*
 * ParseAccountDuration, süre ayarını çözer — GÜN dahil.
 *
 * ⚠️ time.ParseDuration "d" BİLMİYOR ve bu buradaki ölçekte gerçek bir
 * tuzak: bu ayarların doğal birimi gün ve operatör "45d" yazıyor.
 * Ölçüldü — "45d" kaydediliyor, çözümlenemiyor, sessizce varsayılana
 * düşüyor ve operatör yazdığının anlaşıldığını sanıyor. En kötü hâli
 * "365d" yazıp korumanın 45 günde çalıştığını fark etmemek.
 *
 * "0" KAPALI demek ve bilinçli bir karar; onun dışında çözümlenemeyen
 * değer HATA — yazma yolları bunu reddedip operatöre söylüyor.
 */
func ParseAccountDuration(raw string) (time.Duration, error) {
	v := strings.TrimSpace(raw)
	if v == "0" {
		return 0, nil
	}
	if rest, ok := strings.CutSuffix(v, "d"); ok {
		days, err := strconv.Atoi(rest)
		if err != nil || days < 0 {
			return 0, fmt.Errorf("auth: %q is not a number of days", raw)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("auth: %q is not a duration "+
			"(use 45d, 720h, or 0 to switch it off)", raw)
	}
	return d, nil
}
