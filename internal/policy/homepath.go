package policy

/*
 * Yol kurallarında "kişinin kendi evi".
 *
 * ⚠️ NEDEN VAR: BİR KİŞİNİN EVİNİ ADIYLA YAZAN GRUP KURALI, BİR KİŞİLİK
 * BİR KURALDIR. Demoda ölçüldü — `developer` grubu /home/ayse'ye izin
 * veriyordu ve o gruptaki başka herkes dosya tarayıcısını bir reddin
 * üstüne açıyordu. Token'sız üç çıkış yolunun üçü de yanlış: kişi başına
 * kural ekip büyüyünce dağılıyor, /home'a izin vermek gruptaki herkese
 * herkesin evini açıyor, kişi başına grup ise grup değil.
 *
 * ⚠️ EV TAHMİN EDİLMİYOR, HEDEFTEN OKUNUYOR. "/home/<ad>" varsaymak bu
 * depoda zaten reddedilmiş bir şey (provision.Account'un yanındaki not):
 * evi başka yerde olan bir hesapta kural, o hesabın sahibi olmadığı bir
 * dizini gösterirdi.
 */

import (
	"path"
	"strings"

	"github.com/Warewave-Technology/postern/v2/internal/model"
)

// UsesHome, kurallardan herhangi biri evi mi gösteriyor.
func UsesHome(groups []model.Group) bool {
	for _, g := range groups {
		for _, r := range g.Paths {
			if model.IsHomeRule(r.Prefix) {
				return true
			}
		}
	}

	return false
}

/*
 * ExpandHome, ev token'ını gerçek yola çevirir.
 *
 * home boşsa ya da mutlak değilse ikinci dönüş false: çağıran o hâlde
 * POLİTİKAYI UYGULAYAMIYOR demektir ve bunu sessizce geçmemeli
 * (SFTPDecider'daki nota bak).
 */
func ExpandHome(prefix, home string) (string, bool) {
	if !model.IsHomeRule(prefix) {
		return prefix, true
	}
	if home == "" || !strings.HasPrefix(home, "/") {
		return "", false
	}
	if prefix == model.HomeToken {
		return path.Clean(home), true
	}

	return path.Clean(home + "/" + strings.TrimPrefix(prefix, model.HomeToken+"/")), true
}
