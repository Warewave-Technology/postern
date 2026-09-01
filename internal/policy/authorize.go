// Package policy answers one question: may this user reach this target, and
// as which OS account?
package policy

import (
	"slices"

	"github.com/warewave/postern/internal/model"
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
