package policy

import (
	"testing"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/sftpaudit"
)

func rule(prefix string, allow, write bool) model.PathRule {
	return model.PathRule{Prefix: prefix, Allow: allow, CanWrite: write}
}

func read(p string) sftpaudit.Request { return sftpaudit.Request{Op: sftpaudit.OpOpen, Path: p} }
func write(p string) sftpaudit.Request {
	return sftpaudit.Request{Op: sftpaudit.OpOpen, Path: p, Write: true}
}

/*
 * ⚠️ KURALSIZ ROL POLİTİKA KURDURMUYOR.
 *
 * Bu, yükseltmenin ertesi sabahını belirleyen davranış: göç var olan hiçbir
 * rolü değiştirmiyor ve kuralı olmayan bir kurulum bu özellikten önceki gibi
 * çalışıyor. nil dönmek "her şeyi reddet"in tersi — veri yoluna fazladan
 * karar, tutma ve gecikme de eklenmiyor.
 */
func TestNoRulesMeansNoPolicy(t *testing.T) {
	if d := SFTPDecider(nil); d != nil {
		t.Fatal("rol yokken politika kuruldu")
	}
	if d := SFTPDecider([]model.Role{{Name: "dev"}}); d != nil {
		t.Fatal("kuralsız rol politika kurdurdu")
	}
}

/*
 * Kuralsız BİR rol, kurallı diğerlerini etkisiz kılıyor.
 *
 * ⚠️ SEZGİYE AYKIRI AMA TUTARLI: kural yazmak bir ROLÜ kısıtlamak demek,
 * kullanıcıyı değil. Aksini seçseydik (kesişim), kısıtlı bir rol eklemek
 * kullanıcının mevcut erişimini SESSİZCE daraltırdı — ve sessiz daralma,
 * fark edilmesi en zor arıza türü.
 */
func TestAnUnrestrictedRoleKeepsAccessOpen(t *testing.T) {
	d := SFTPDecider([]model.Role{
		{Name: "kisitli", Paths: []model.PathRule{rule("/srv", true, false)}},
		{Name: "serbest"},
	})
	if d != nil {
		t.Fatal("kuralsız rol varken politika kuruldu")
	}
}

func TestLongestPrefixWinsSoCarveOutsWork(t *testing.T) {
	d := SFTPDecider([]model.Role{{Name: "dev", Paths: []model.PathRule{
		rule("/home/u", true, true),
		rule("/home/u/.ssh", false, false),
	}}})
	if d == nil {
		t.Fatal("politika kurulmadı")
	}

	cases := []struct {
		req  sftpaudit.Request
		want bool
	}{
		{read("/home/u/notlar.txt"), true},
		{write("/home/u/notlar.txt"), true},
		{read("/home/u/.ssh/id_ed25519"), false},
		{write("/home/u/.ssh/authorized_keys"), false},
		{read("/etc/shadow"), false},
	}
	for _, c := range cases {
		got, reason := d(c.req)
		if got != c.want {
			t.Errorf("%q: %v bekleniyordu, %v (%s)", c.req.Path, c.want, got, reason)
		}
	}
}

/*
 * ⚠️ ÖNEK DİZİN SINIRINDA EŞLEŞİYOR.
 *
 * Düz dizgi öneki kullansaydık "/home/user" kuralı "/home/username"i de
 * kapsardı — ve kuralı yazan kişi bunu fark etmezdi. Sessizce fazla erişim
 * veren bir kural, hiç kural olmamasından kötü.
 */
func TestPrefixDoesNotLeakAcrossNameBoundaries(t *testing.T) {
	d := SFTPDecider([]model.Role{{Name: "dev", Paths: []model.PathRule{
		rule("/home/user", true, true),
	}}})

	if ok, _ := d(read("/home/user/x")); !ok {
		t.Error("kendi ağacı reddedildi")
	}
	if ok, _ := d(read("/home/username/x")); ok {
		t.Error("ÖNEK KOMŞU DİZİNE SIZDI: /home/user kuralı /home/username'i açtı")
	}
	if ok, _ := d(read("/home/user")); !ok {
		t.Error("kökün kendisi reddedildi")
	}
}

// Salt okuma kuralı yazmayı kapsamıyor.
func TestReadOnlyRuleRefusesWrites(t *testing.T) {
	d := SFTPDecider([]model.Role{{Name: "dev", Paths: []model.PathRule{
		rule("/srv/veri", true, false),
	}}})

	if ok, _ := d(read("/srv/veri/a.csv")); !ok {
		t.Error("okuma reddedildi")
	}
	if ok, reason := d(write("/srv/veri/a.csv")); ok {
		t.Error("salt okuma kuralı yazmaya izin verdi")
	} else if reason == "" {
		t.Error("ret gerekçesiz")
	}
}

/*
 * ⚠️ İKİ YOLLU İSTEKLERDE İKİSİ DE KONTROL EDİLİYOR.
 *
 * Tek yola bakmak, izinli bir dizinden yasak bir yere bağ kurmayı ya da
 * yasak bir yerden izinli bir yere taşımayı serbest bırakırdı — yol
 * politikasını tümüyle boşa çıkaran şey tam olarak budur.
 */
func TestBothPathsAreCheckedOnTwoPathOperations(t *testing.T) {
	d := SFTPDecider([]model.Role{{Name: "dev", Paths: []model.PathRule{
		rule("/home/u", true, true),
	}}})

	cases := []struct {
		name string
		req  sftpaudit.Request
	}{
		{"izinliden yasağa", sftpaudit.Request{
			Op: sftpaudit.OpRename, Path: "/home/u/a", NewPath: "/etc/cron.d/a", Write: true}},
		{"yasaktan izinliye", sftpaudit.Request{
			Op: sftpaudit.OpLink, Path: "/etc/shadow", NewPath: "/home/u/kopya", Write: true}},
	}
	for _, c := range cases {
		if ok, _ := d(c.req); ok {
			t.Errorf("%s: geçti — bağ/taşıma politikayı atlatıyor", c.name)
		}
	}
}

// Birden çok rol: herhangi biri izin veriyorsa erişim var.
func TestAccessIsTheUnionOfRoles(t *testing.T) {
	d := SFTPDecider([]model.Role{
		{Name: "a", Paths: []model.PathRule{rule("/srv/a", true, false)}},
		{Name: "b", Paths: []model.PathRule{rule("/srv/b", true, true)}},
	})

	if ok, _ := d(read("/srv/a/x")); !ok {
		t.Error("a rolünün yolu reddedildi")
	}
	if ok, _ := d(write("/srv/b/x")); !ok {
		t.Error("b rolünün yolu reddedildi")
	}
	if ok, _ := d(read("/srv/c/x")); ok {
		t.Error("hiçbir rolün kapsamadığı yol geçti")
	}
}

/*
 * ⚠️ AÇIK RET BİR VETODUR: BAŞKA BİR ROLÜN İZNİ ONU GERİ AÇAMAZ.
 *
 * ÖLÇÜLEN ARIZA: kararı rol rol verip "herhangi biri izin veriyorsa evet"
 * dediğimizde açık retler hayatta kalmıyordu. Demoda görüldü: developer
 * rolünde /home/sidinak/.ssh reddedilmişti, sftp-demo rolü /home/sidinak'a
 * izin veriyordu ve .ssh AÇIK KALDI. Yönetici bir dalı kestiğini sanıyor,
 * kesmemiş oluyor — sessizce fazla erişim, kural yazmanın en kötü sonucu.
 */
func TestAnExplicitDenyIsNotReopenedByAnotherRole(t *testing.T) {
	d := SFTPDecider([]model.Role{
		{Name: "kisan", Paths: []model.PathRule{
			rule("/home/u", true, true),
			rule("/home/u/.ssh", false, false),
		}},
		{Name: "acan", Paths: []model.PathRule{
			rule("/home/u", true, true),
		}},
	})

	if ok, _ := d(read("/home/u/notlar.txt")); !ok {
		t.Error("izinli yol reddedildi")
	}
	if ok, _ := d(read("/home/u/.ssh/id_ed25519")); ok {
		t.Fatal("AÇIK RET BAŞKA BİR ROLÜN İZNİYLE GERİ AÇILDI")
	}
}

/*
 * Aynı önek üzerinde bir rol ret, diğeri izin diyorsa RET kazanıyor.
 *
 * ⚠️ EŞİTLİKTE RET, çünkü aksi hâlde bir dalı kesmek isteyen yönetici
 * kesiğin başka bir rolce aynı uzunlukta geri açılabileceğini bilmek
 * zorunda kalırdı. Veto olmayan bir ret, ret değildir.
 */
func TestDenyWinsOnEqualLengthPrefixes(t *testing.T) {
	d := SFTPDecider([]model.Role{
		{Name: "a", Paths: []model.PathRule{rule("/srv/gizli", true, true)}},
		{Name: "b", Paths: []model.PathRule{rule("/srv/gizli", false, false)}},
	})

	if ok, reason := d(read("/srv/gizli/x")); ok {
		t.Fatal("eşit uzunlukta izin, reddi bastırdı")
	} else if reason == "" {
		t.Error("ret gerekçesiz")
	}
}

// Yazma hakkı aynı uzunlukta birleşiyor: bir rol salt okuma, diğeri yazma
// veriyorsa yazma var. (Ret olmadığı sürece.)
func TestWriteRightUnionsAtTheSameLength(t *testing.T) {
	d := SFTPDecider([]model.Role{
		{Name: "ro", Paths: []model.PathRule{rule("/srv/v", true, false)}},
		{Name: "rw", Paths: []model.PathRule{rule("/srv/v", true, true)}},
	})

	if ok, _ := d(write("/srv/v/a")); !ok {
		t.Error("yazma hakkı birleşmedi")
	}
}
