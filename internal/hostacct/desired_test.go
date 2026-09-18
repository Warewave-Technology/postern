package hostacct

import (
	"testing"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/provision"
	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/sudoers"
)

/*
 * ⚠️ YALNIZCA BU HEDEFİ VEREN GRUPLAR. Kişinin bütün gruplarını her
 * makineye yazmak, postern'i tam da yerine geçtiği şeye — N kullanıcıyı
 * M makineye basan bir dağıtıcıya — çevirirdi. Ürünün cümlesi bu: hesap
 * kullanıldığı yerde vardır, ve yetki de öyle.
 */
func TestOnlyTheGroupsThatReachThisTargetAreWanted(t *testing.T) {
	u := model.User{
		Name: "ayse", OSUser: "ayse",
		Groups: []model.Group{
			{Name: "sre", Targets: []string{"db01", "web01"}},
			{Name: "dba", Targets: []string{"db01"}},
			{Name: "web", Targets: []string{"web01"}},
		},
	}
	want := Compute(u, model.Target{Name: "db01"}, nil, false)

	var names []string
	for _, g := range want.Groups {
		names = append(names, g.Name)
	}
	if len(names) != 2 || names[0] != "postern-dba" || names[1] != "postern-sre" {
		t.Errorf("istenen gruplar: %v — yalnızca db01'i veren ikisi, önekli ve sıralı", names)
	}
	if want.OSUser != "ayse" {
		t.Errorf("hesap adı: %q", want.OSUser)
	}
}

/*
 * ⚠️ ÖNEK SAHİPLİK KANITI (K5). Hedefte zaten bir `dba` grubu olabilir ve
 * içinde postern'in tanımadığı yirmi kişi durabilir; kuralı o gruba
 * yazmak, verilen yetkiyi onlara da vermek olurdu.
 */
func TestTheHostGroupIsPrefixed(t *testing.T) {
	u := model.User{Name: "a", OSUser: "a", Groups: []model.Group{
		{Name: "dba", Targets: []string{"db01"}},
	}}
	got := Compute(u, model.Target{Name: "db01"}, nil, false).Groups
	if len(got) != 1 || got[0].Name != "postern-dba" {
		t.Errorf("grup adı: %+v", got)
	}
}

/*
 * ⚠️ PARMAK İZİ SICAK YOLUN TAMAMI. Eşitse hedefe HİÇ bağlanılmıyor,
 * dolayısıyla istenen durumun her parçası izin içinde olmak zorunda.
 * Kuralın değişmesi ize yansımazsa, sudo kuralını düzelten bir yönetici
 * makinede eskisinin durmaya devam ettiğini göremez.
 */
func TestTheFingerprintMovesWhenAnythingThatReachesTheHostMoves(t *testing.T) {
	u := model.User{Name: "ayse", OSUser: "ayse", Groups: []model.Group{
		{Name: "dba", Targets: []string{"db01"}},
	}}
	tgt := model.Target{Name: "db01"}
	rule := sudoers.Rule{Commands: []sudoers.Command{
		{Path: "/usr/bin/pg_ctl", Args: []string{"reload"}},
	}}

	base := Compute(u, tgt, nil, false).Fingerprint
	withRule := Compute(u, tgt, map[string]store.GroupSudo{"dba": {Rule: rule}}, false).Fingerprint
	if base == withRule {
		t.Error("sudo kuralı eklendi, parmak izi değişmedi — kural hedefe hiç inmez")
	}

	changed := sudoers.Rule{Commands: []sudoers.Command{
		{Path: "/usr/bin/pg_ctl", Args: []string{"reload"}, RunAs: "postgres"},
	}}
	withAccount := Compute(u, tgt, map[string]store.GroupSudo{"dba": {Rule: changed}}, false).Fingerprint
	if withRule == withAccount {
		t.Error("komutun hesabı değişti, parmak izi değişmedi — yetki sessizce eski kalır")
	}

	u2 := u
	u2.OSUser = "ayse.y"
	if Compute(u2, tgt, nil, false).Fingerprint == base {
		t.Error("hesap adı değişti, parmak izi değişmedi")
	}

	u3 := u
	u3.Groups = append([]model.Group{{Name: "sre", Targets: []string{"db01"}}}, u.Groups...)
	if Compute(u3, tgt, nil, false).Fingerprint == base {
		t.Error("yeni grup eklendi, parmak izi değişmedi")
	}
}

/*
 * ⚠️ SIRA İZİ DEĞİŞTİRMEMELİ. Gruplar veritabanından farklı sırayla
 * gelebiliyor; sıralanmamış bir iz, hiçbir şey değişmediği hâlde her
 * bağlantıda hedefe bağlanmaya yol açardı — yani hızlı şeridi yok ederdi.
 */
func TestTheFingerprintDoesNotDependOnGroupOrder(t *testing.T) {
	a := model.User{Name: "a", OSUser: "a", Groups: []model.Group{
		{Name: "sre", Targets: []string{"db01"}},
		{Name: "dba", Targets: []string{"db01"}},
	}}
	b := model.User{Name: "a", OSUser: "a", Groups: []model.Group{
		{Name: "dba", Targets: []string{"db01"}},
		{Name: "sre", Targets: []string{"db01"}},
	}}
	tgt := model.Target{Name: "db01"}
	if Compute(a, tgt, nil, false).Fingerprint != Compute(b, tgt, nil, false).Fingerprint {
		t.Error("sıra izi değiştiriyor")
	}
}

/* Hedefe erişim yoksa istenen durum da yok: boş grup listesi. */
func TestAUserWithNoGroupForThisTargetWantsNothing(t *testing.T) {
	u := model.User{Name: "a", OSUser: "a", Groups: []model.Group{
		{Name: "web", Targets: []string{"web01"}},
	}}
	if got := Compute(u, model.Target{Name: "db01"}, nil, false); len(got.Groups) != 0 {
		t.Errorf("gruplar: %+v", got.Groups)
	}
}

/*
 * ⚠️ MARKER GRUBU SİLMENİN ÖN KOŞULU, VE YALNIZCA POSTERN'İN AÇTIĞINDA.
 *
 * postern-managed, "bu hesabı ben açtım"ın makine üstündeki hâli;
 * provision.RevokePlan silmeyi buna bakarak veriyor. Devralınan bir
 * hesaba koymak, postern'den önce var olan bir hesabı silinebilir
 * yapardı — ve o silme geri alınamaz.
 */
func TestTheManagedMarkerIsOnlyOnAccountsPosternCreated(t *testing.T) {
	u := model.User{Name: "a", OSUser: "a", Groups: []model.Group{
		{Name: "dba", Targets: []string{"db01"}},
	}}
	tgt := model.Target{Name: "db01"}

	created := Compute(u, tgt, nil, true)
	var names []string
	for _, g := range created.Groups {
		names = append(names, g.Name)
	}
	if !slicesContains(names, provision.ManagedGroup) {
		t.Errorf("postern'in açtığı hesapta marker yok: %v", names)
	}

	adopted := Compute(u, tgt, nil, false)
	names = nil
	for _, g := range adopted.Groups {
		names = append(names, g.Name)
	}
	if slicesContains(names, provision.ManagedGroup) {
		t.Errorf("devralınan hesaba marker konmuş: %v", names)
	}

	/*
	 * ⚠️ MARKER FINGERPRINT'E DE GİRİYOR. Girmeseydi, marker'ı eksik
	 * kalmış bir hesap (ör. yarıda kalmış bir hazırlama) fast lane'den
	 * geçer ve bir daha hiç düzelmezdi — yani silinemez hâle gelirdi.
	 */
	if created.Fingerprint == adopted.Fingerprint {
		t.Error("marker fingerprint'i değiştirmiyor")
	}
}

func slicesContains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}

	return false
}
