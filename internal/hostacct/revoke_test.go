package hostacct

import (
	"testing"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/provision"
)

/*
 * ⚠️ BU AYRIM İTME YOLUNUN TAMAMI.
 *
 * Kişi hedefe BAŞKA bir grupla hâlâ erişiyorsa yapılacak tek şey o
 * grubun üyeliğini düşürmek: yıkıcı değil, geri alınabilir, onay
 * istemez. Hiçbir grubu kalmadıysa söz konusu olan HESABIN KENDİSİ ve
 * insan kararı devreye giriyor (K2/K3).
 *
 * İkisini karıştırmak iki yönde de pahalı: kısmi kayıpta hesabı silmek,
 * kişiyi hâlâ hakkı olan makineden atmak; tam kayıpta yalnızca grubu
 * düşürmek ise hesabı sudo'suz ama AÇIK bırakmak demek — yani erişimi
 * bitirdiğini sanan yöneticiye bitmemiş bir erişim.
 */
func TestLosingOneGroupDemotesAndLosingAllLocks(t *testing.T) {
	tgt := model.Target{Name: "db01"}
	before := model.User{OSUser: "ayse", Groups: []model.Group{
		{Name: "dba", Targets: []string{"db01"}},
		{Name: "sre", Targets: []string{"db01"}},
	}}
	afterPartial := model.User{OSUser: "ayse", Groups: []model.Group{
		{Name: "sre", Targets: []string{"db01"}},
	}}
	afterAll := model.User{OSUser: "ayse"}

	if got := EffectOf(before, afterPartial, tgt); got != EffectDemote {
		t.Errorf("kısmi kayıp = %v, düşürme bekleniyordu", got)
	}
	if got := EffectOf(before, afterAll, tgt); got != EffectLock {
		t.Errorf("tam kayıp = %v, kilit bekleniyordu", got)
	}
	if got := EffectOf(before, before, tgt); got != EffectNone {
		t.Errorf("değişmeyen erişim = %v", got)
	}
}

/*
 * ⚠️ BAŞKA BİR HEDEFİ KAYBETMEK BU HEDEFİ ETKİLEMİYOR. Grup listesi
 * daraldı diye her makinede iş yapmak, tek bir yetki değişikliğini
 * filonun tamamına yayılan bir yazma dalgasına çevirirdi.
 */
func TestLosingAGroupThatNeverReachedThisTargetChangesNothing(t *testing.T) {
	before := model.User{OSUser: "ayse", Groups: []model.Group{
		{Name: "dba", Targets: []string{"db01"}},
		{Name: "web", Targets: []string{"web01"}},
	}}
	after := model.User{OSUser: "ayse", Groups: []model.Group{
		{Name: "dba", Targets: []string{"db01"}},
	}}
	if got := EffectOf(before, after, model.Target{Name: "db01"}); got != EffectNone {
		t.Errorf("db01 = %v — kaybedilen grup oraya hiç erişmiyordu", got)
	}
	if got := EffectOf(before, after, model.Target{Name: "web01"}); got != EffectLock {
		t.Errorf("web01 = %v — oraya erişim tamamen bitti", got)
	}
}

/*
 * ⚠️ OTOMATİK YOL ASLA SİLMİYOR (K3). Bu yolda insan yok: dizin
 * senkronu birini gruptan düşürdüğünde hesabın silinmesi, bir dizin
 * hatasının üretimde geri alınamaz bir veri kaybına dönüşmesi demek.
 * Kilit geri alınabilir; silme, insanın açıkça istediği ayrı bir yol.
 */
func TestTheAutomaticPathLocksAndNeverDeletes(t *testing.T) {
	u := model.User{OSUser: "ayse"}
	r := RevokeFor(u, model.Target{Name: "db01"}, "/etc/ssh/auth_principals/ayse")
	if r.Mode != provision.ModeLock {
		t.Errorf("kip = %q, kilit bekleniyordu", r.Mode)
	}
	if r.User != "ayse" {
		t.Errorf("hesap = %q", r.User)
	}
	/*
	 * ⚠️ GRUBUN SUDO DOSYASI GERİ ALMAYA GİRMİYOR. O dosya gruba ait ve
	 * grupta başkaları olabilir; silmek, aynı gruptaki herkesin
	 * yetkisini almak olurdu. Kaldırılan şey kişinin üyeliği.
	 */
	if len(r.SudoFiles) != 0 {
		t.Errorf("grup sudo dosyası geri almaya girdi: %v", r.SudoFiles)
	}
	if r.PrincipalsFile == "" {
		t.Error("principals dosyası verilmemiş — asıl erişim kesici o")
	}
}
