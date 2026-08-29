package ldap

import (
	"strconv"
	"strings"

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
}

// adAccountDisabled, userAccountControl'daki ACCOUNTDISABLE biti.
const adAccountDisabled = 0x2

/*
 * accountDisabled, girişin devre dışı olup olmadığını söyler.
 *
 * Herhangi biri "kapalı" diyorsa kapalı sayılıyor: bir dizin aynı anda
 * birden çok mekanizma taşıyabilir ve en kısıtlayıcı cevabı almak
 * doğru taraf.
 */
func accountDisabled(entry *goldap.Entry) (bool, string) {
	if raw := entry.GetAttributeValue("userAccountControl"); raw != "" {
		// Ayrıştırılamayan değer "kapalı" sayılmıyor: bilmediğimiz bir
		// biçim yüzünden birini dışarıda bırakmak, korumanın sağladığı
		// faydadan pahalı.
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil && v&adAccountDisabled != 0 {
			return true, "userAccountControl has ACCOUNTDISABLE"
		}
	}
	if strings.EqualFold(entry.GetAttributeValue("nsAccountLock"), "TRUE") {
		return true, "nsAccountLock is TRUE"
	}
	if entry.GetAttributeValue("pwdAccountLockedTime") != "" {
		return true, "pwdAccountLockedTime is set"
	}
	return false, ""
}
