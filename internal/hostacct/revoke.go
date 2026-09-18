package hostacct

/*
 * Grup kaybının hedefteki karşılığı.
 *
 * ⚠️ İKİ AYRI SONUÇ VE ARALARINDAKİ FARK BU DOSYANIN TAMAMI. Kişi hedefe
 * başka bir grupla hâlâ erişiyorsa yapılacak şey yalnızca o grubun
 * üyeliğini düşürmek — yıkıcı değil, geri alınabilir, onay istemez.
 * Hiçbir grubu kalmadıysa söz konusu olan hesabın kendisidir ve karar
 * insana aittir (spec K2/K3).
 */

import (
	"strings"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/provision"
)

// Effect, bir grup kaybının bu hedefteki sonucu.
type Effect string

const (
	// EffectNone, bu hedefte değişen bir şey yok.
	EffectNone Effect = "none"
	// EffectDemote, kişi hedefe hâlâ erişiyor; yalnızca kaybettiği
	// grubun üyeliği düşürülüyor.
	EffectDemote Effect = "demote"
	// EffectLock, kişinin hedefe erişimi tamamen bitti; hesap kilitleniyor.
	EffectLock Effect = "lock"
)

/*
 * EffectOf, grup listesi daraldığında bu hedefte ne olması gerektiğini
 * söyler.
 *
 * ⚠️ SAF: iki kullanıcı hâli ve bir hedef. Kararın doğruluğu bir tablo
 * testiyle kanıtlanabilsin diye; yanlış verildiğinde bedeli ya kişiyi
 * hakkı olan makineden atmak ya da erişimi bittiğini sandığınız birini
 * makinede açık bırakmak.
 */
func EffectOf(before, after model.User, t model.Target) Effect {
	had := reachCount(before, t.Name)
	has := reachCount(after, t.Name)
	switch {
	case had == 0 || had == has:
		return EffectNone
	case has > 0:
		return EffectDemote
	default:
		return EffectLock
	}
}

func reachCount(u model.User, target string) int {
	n := 0
	for _, g := range u.Groups {
		if reaches(g, target) {
			n++
		}
	}

	return n
}

/*
 * RevokeFor, kilit kipinde bir geri alma isteği kurar.
 *
 * ⚠️ YENİ BİR PLANLAYICI YAZILMIYOR: provision.RevokePlan zaten kilit
 * kipini biliyor ve gerekçesi orada yazılı — silinen hesabın UID'si
 * yeniden kullanılabiliyor, sonraki hesap aynı numarayı alırsa
 * öncekinin dosyalarının sahibi oluyor. İkinci bir planlayıcı, o
 * gerekçenin bir kopyasını daha tutmak ve ikisinin ayrışmasını
 * beklemek olurdu.
 *
 * ⚠️ KİP HER ZAMAN ModeLock. Bu yol otomatik ve içinde insan yok (K3);
 * silme, insanın açıkça istediği ayrı bir yol (K2/K8).
 */
func RevokeFor(facts provision.AccountFacts, osUser, principalsFile string) provision.Revoke {
	return provision.Revoke{
		User: osUser,
		Mode: provision.ModeLock,
		/*
		 * ⚠️ UID HEDEFTEN OKUNUYOR, VARSAYILMIYOR. RevokePlan sistem
		 * hesaplarına dokunmayı reddediyor ve bu reddi UID'ye bakarak
		 * veriyor; numarayı vermemek, planın her seferinde "bu bir sistem
		 * hesabı" diye reddetmesi demek — yani kilit hiç inmez.
		 */
		UID:            facts.UID,
		Home:           facts.Home,
		PrincipalsFile: principalsFile,
		/*
		 * Grubun sudo dosyası BURADA DEĞİL: o dosya gruba ait ve grupta
		 * başkaları olabilir. Kaldırılan şey kişinin ÜYELİĞİ; dosyayı
		 * silmek, aynı gruptaki herkesin yetkisini almak olurdu.
		 */
	}
}

// HostGroupsOf, kişinin bu hedefte üye olduğu postern gruplarının adları.
func HostGroupsOf(u model.User, t model.Target) []string {
	var out []string
	for _, g := range u.Groups {
		if reaches(g, t.Name) {
			out = append(out, HostGroupPrefix+strings.ToLower(g.Name))
		}
	}

	return out
}
