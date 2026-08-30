package ldap

import (
	"strconv"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
)

/*
 * Hesabın DİZİNDE HÂLÂ AÇIK olup olmadığı.
 *
 * ⚠️ NEDEN AYRI BİR SORU: grup üyeliği "bu kişi neye erişmeli"yi
 * söylüyor, hesabın açık olup olmadığı "bu kişi hâlâ burada mı"yı.
 * İkisini birbirine karıştırmak somut bir açık üretiyordu: bir hesabı
 * devre dışı bırakmak, işten ayrılma ve olay müdahalesinde atılan İLK
 * adımdır — ama AD'de bu ne girişi siler ne de grup üyeliklerini
 * kaldırır. Yalnızca gruplara bakan bir tazeleme o hesabı "present,
 * rolleri şunlar" diye okur ve rollerini yeniden yazar.
 *
 * ⚠️ EN İYİ ÇABA, GARANTİ DEĞİL. Dizin bu özniteliklerin hiçbirini
 * sunmuyorsa ya da servis hesabı okuyamıyorsa, sonuç "açık" olur —
 * yani koruma yoksa davranış eskisi gibi kalır, ama yanlışlıkla kimse
 * dışarıda bırakılmaz. Bunu bilerek bu yöne eğiyoruz: sessiz bir
 * kilitlenme, sessiz bir korumasızlıktan daha pahalı olurdu ve
 * korumasızlık en azından senkronizasyon döngüsünde yakalanıyor.
 */

// livenessAttrs, hesap durumunu taşıyan yaygın öznitelikler.
//
// Üçü de standart ad ve olmayan bir özniteliği istemek zararsız: dizin
// onu cevapta döndürmüyor, hepsi bu.
var livenessAttrs = []string{
	// Active Directory: bit 0x2 (ACCOUNTDISABLE).
	"userAccountControl",
	// 389 Directory Server / FreeIPA: "TRUE" ise hesap kilitli.
	"nsAccountLock",
	// OpenLDAP ppolicy: dolu ise hesap kilitlenmiş.
	"pwdAccountLockedTime",

	/*
	 * ⚠️ SÜRESİ DOLMUŞ HESAP DA KAPALIDIR — ve bu, kapatılmış hesaptan
	 * FARKLI bir mekanizma.
	 *
	 * Süreli hesap, taşeron/danışman nüfusunun standart yönetim biçimi:
	 * AD'de hesap açılırken bitiş tarihi verilir ve o gün geldiğinde
	 * KİMSE bir şey yapmaz — ne disable bayrağı düşer, ne grup üyeliği
	 * kalkar, ne kayıt silinir. Yalnızca bu alan geçmişte kalır.
	 *
	 * Yani tam da "kimse elle müdahale etmediği için" gözden kaçan
	 * nüfus, yalnızca gruplara ve disable bayrağına bakan bir kontrol
	 * tarafından "hâlâ burada" diye okunuyordu.
	 */
	// Active Directory: Windows FILETIME. 0 ve 0x7FFFFFFFFFFFFFFF = süresiz.
	"accountExpires",
	// POSIX (shadowAccount): 1970-01-01'den itibaren GÜN. Negatif/boş = süresiz.
	"shadowExpire",
}

/*
 * Windows FILETIME ile Unix epoch arasındaki fark.
 *
 * FILETIME 1601-01-01'den itibaren 100 nanosaniyelik aralıkları sayar;
 * aradaki 11644473600 saniye, 369 yılın (89 artık gün dahil) karşılığı.
 */
const (
	filetimeEpochOffsetSeconds = 11644473600
	filetimeTicksPerSecond     = 10000000

	/*
	 * accountExpiresNever: AD "süresiz"i İKİ ayrı değerle yazıyor ve
	 * ikisi de sahada görülüyor — 0 (hiç ayarlanmamış) ve int64 tavanı
	 * (arayüzden "asla" seçilmiş).
	 *
	 * ⚠️ İKİSİNİN AĞIRLIĞI AYNI DEĞİL, ölçüldü:
	 *
	 *   0'ı elemek ZORUNLU. Elenmezse 0, 1601-01-01'e çözülür ve o
	 *   dizindeki HERKES "süresi dolmuş" diye reddedilir. Mutasyon
	 *   testi bunu gösteriyor.
	 *
	 *   Tavan değerini elemek gerekli DEĞİL: aynı aritmetik onu 30828
	 *   yılına taşıyor, yani zaten gelecekte kalıyor. Sabit yine de
	 *   duruyor — niyeti yazıya döküyor ve davranışın bir rastlantıya
	 *   bağlı kalmasını engelliyor.
	 */
	accountExpiresNever = int64(0x7FFFFFFFFFFFFFFF)
)

// adAccountDisabled, userAccountControl'daki ACCOUNTDISABLE biti.
const adAccountDisabled = 0x2

/*
 * accountExpired, hesabın süresinin dolup dolmadığını söyler.
 *
 * ⚠️ ÇÖZÜMLENEMEYEN DEĞER "DOLMUŞ" SAYILMAZ. Beklenmedik bir biçim
 * gördüğümüzde herkesi dışarı atmak, bir şema farkını toplu erişim
 * kaybına çevirirdi — liveness.go'nun genel yönü burada da geçerli:
 * koruma uygulanamıyorsa davranış eskisi gibi kalır.
 */
func accountExpired(entry *goldap.Entry, now time.Time) (bool, string) {
	if raw := entry.GetEqualFoldAttributeValue("accountExpires"); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil {
			if v != 0 && v != accountExpiresNever {
				exp := time.Unix(v/filetimeTicksPerSecond-filetimeEpochOffsetSeconds, 0).UTC()
				if now.After(exp) {
					return true, "accountExpires " + exp.Format("2006-01-02")
				}
			}
		}
	}

	if raw := entry.GetEqualFoldAttributeValue("shadowExpire"); raw != "" {
		if days, err := strconv.ParseInt(raw, 10, 64); err == nil && days >= 0 {
			exp := time.Unix(days*86400, 0).UTC()
			if now.After(exp) {
				return true, "shadowExpire " + exp.Format("2006-01-02")
			}
		}
	}
	return false, ""
}

/*
 * accountDisabled, girişin devre dışı olup olmadığını söyler.
 *
 * Herhangi biri "kapalı" diyorsa kapalı sayılıyor: bir dizin aynı anda
 * birden çok mekanizma taşıyabilir ve en kısıtlayıcı cevabı almak
 * doğru taraf.
 */
func accountDisabled(entry *goldap.Entry) (bool, string) {
	if raw := entry.GetEqualFoldAttributeValue("userAccountControl"); raw != "" {
		// Ayrıştırılamayan değer "kapalı" sayılmıyor: bilmediğimiz bir
		// biçim yüzünden birini dışarıda bırakmak, korumanın sağladığı
		// faydadan pahalı.
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil && v&adAccountDisabled != 0 {
			return true, "userAccountControl has ACCOUNTDISABLE"
		}
	}
	if strings.EqualFold(entry.GetEqualFoldAttributeValue("nsAccountLock"), "TRUE") {
		return true, "nsAccountLock is TRUE"
	}
	if entry.GetEqualFoldAttributeValue("pwdAccountLockedTime") != "" {
		return true, "pwdAccountLockedTime is set"
	}

	// Süresi dolmuş hesap da kapalıdır — ama AYRI bir mekanizmayla,
	// ve o mekanizma kimsenin elle müdahale etmediği için sessiz.
	if expired, why := accountExpired(entry, time.Now()); expired {
		return true, why
	}
	return false, ""
}
