// Package policy answers one question: may this user reach this target, and
// as which OS account?
package policy

import (
	"slices"
	"time"

	"github.com/Warewave-Technology/postern/internal/model"
)

// osUserNamePatternRegex, hedefte hesap adı olarak kabul ettiğimiz biçim.
//
// Nokta S5.2'de eklendi: kimlik sağlayıcıdan gelen kullanıcı adları
// kurumsal ortamda "isim.soyisim" biçiminde ve hedeflerdeki hesap adları
// da odur. Nokta olmadan bu tasarımın varsaydığı her kullanıcı reddedilirdi.
//
// Dışarıda kalanlar bilinçli: büyük harf (Linux hesapları geleneksel
// olarak küçük harf ve büyük/küçük karışımı "Web01/web01" sınıfından
// karışıklık üretir), Türkçe ve diğer ASCII dışı harfler (hedefteki
// useradd çoğu dağıtımda reddeder), boşluk ve kabuk metakarakterleri.
//
// İlk karakterin harf ya da alt çizgi olması şart: nokta ya da tire ile
// başlayan adlar hem useradd'de sorun çıkarır hem komut satırında
// bayrak sanılabilir.

type Decision struct {
	Allowed bool

	OSUser string

	Reason string

	// Temporary, iznin bir rolden değil süreli bir haktan geldiği —
	// denetim satırı ve oturum kaydı bunu söylemeli.
	Temporary bool
}

/*
 * AuthorizeWithTemporary, Authorize'ın süreli hakları da tanıyan hâli.
 *
 * ⚠️ ROL ÖNCE. Rolü olan kişi için hak fazladan bir şey söylemiyor; rolü
 * OLMAYAN kişi için hak, hedefe giden TEK yol. Hak ancak hedefte
 * uygulanmış (hesap açılmış), vadesi dolmamış ve kişinin bugünkü
 * os_user'ıyla aynı hesaba verilmişse sayılıyor: sertifikanın principal'ı
 * os_user, hedefteki principals dosyası da hakkın hesabına yazılıyor —
 * ikisi ayrışırsa hedef zaten reddeder, ama burada durmak reddi bastion'da
 * ve gerekçeli tutuyor.
 *
 * ⚠️ AYNI KONTROLLER: root, yönetim hesabı ve ad biçimi burada da
 * reddediliyor. Süreli hak bir kestirme değil.
 */
func AuthorizeWithTemporary(u model.User, t model.Target, requested string,
	temp []model.TemporaryAccess, now time.Time) Decision {
	d := Authorize(u, t, requested)
	if d.Allowed {
		return d
	}
	for _, a := range temp {
		if a.Target != t.Name || !a.Live(now) {
			continue
		}
		if a.OSUser != u.OSUser {
			return Decision{Allowed: false,
				Reason: "policy.Authorize: temporary access was granted to a different account name"}
		}
		if !validateOSUserName(u.OSUser) {
			return Decision{Allowed: false, Reason: "policy.Authorize: OSUser name violation"}
		}
		if u.OSUser == "root" {
			return Decision{Allowed: false, Reason: "policy.Authorize: root access violation"}
		}
		if model.IsManagementName(u.OSUser) {
			return Decision{Allowed: false, Reason: "policy.Authorize: management account violation"}
		}
		if requested != "" && requested != u.OSUser {
			return Decision{Allowed: false, Reason: "policy.Authorize: identitiy injection access violation"}
		}
		return Decision{Allowed: true, OSUser: u.OSUser, Temporary: true}
	}
	return d
}

// Authorize decides whether u may open a session on t, and as which OS user.
func Authorize(u model.User, t model.Target, requested string) Decision {
	for _, role := range u.Roles {
		if slices.Contains(role.Targets, t.Name) {
			if !validateOSUserName(u.OSUser) {
				return Decision{Allowed: false, Reason: "policy.Authorize: OSUser name violation"}
			}

			if u.OSUser == "root" {
				return Decision{Allowed: false, Reason: "policy.Authorize: root access violation"}
			}

			/*
			 * ⚠️ YÖNETİM HESABI root GİBİ: HİÇBİR KİŞİYE AÇILMIYOR.
			 *
			 * reservedOSUsers'tan farkı bilinçli. Orada operatör bir adı
			 * BİLEREK verebiliyor ("postgres" meşru bir DBA erişimi); bu
			 * iki ad ise hedefte parolasız root tutan hesabın kendisi.
			 * Yazma yolları zaten reddediyor; burada da duruyor çünkü bu,
			 * elle düzenlenmiş ya da eski bir sürümün yazdığı satıra karşı
			 * son savunma (validateOSUserName'in gerekçesiyle aynı).
			 */
			if model.IsManagementName(u.OSUser) {
				return Decision{Allowed: false, Reason: "policy.Authorize: management account violation"}
			}

			if requested != "" {
				if u.OSUser == requested {
					return Decision{Allowed: true, OSUser: u.OSUser}
				}

				return Decision{Allowed: false, Reason: "policy.Authorize: identitiy injection access violation"}
			}

			return Decision{Allowed: true, OSUser: u.OSUser}
		}
	}

	return Decision{Allowed: false, Reason: "policy.Authorize: default access denied"}
}

func validateOSUserName(osUser string) bool {
	// Tek tanim model.ValidOSUserName. Buradaki kontrol YİNE DE
	// duruyor: yazma yollari kurali uygulasa bile bu, veritabanina
	// elle dokunulmus bir satira karsi son savunma.
	return model.ValidOSUserName(osUser)
}
