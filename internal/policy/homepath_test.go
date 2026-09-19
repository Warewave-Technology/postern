package policy

import (
	"testing"

	"github.com/Warewave-Technology/postern/v2/internal/model"
	"github.com/Warewave-Technology/postern/v2/internal/sftpaudit"
)

/*
 * ⚠️ BİR KİŞİNİN EVİNİ ADIYLA YAZAN GRUP KURALI, BİR KİŞİLİK KURALDIR.
 *
 * Demoda ölçüldü: `developer` grubu /home/ayse'ye izin veriyordu ve o
 * gruptaki başka herkes dosya tarayıcısını bir reddin üstüne açıyordu.
 * Token, tek bir kuralın grubun HER üyesi için doğru olmasını sağlıyor.
 */
func TestTheHomeTokenIsEachPersonsOwnHome(t *testing.T) {
	groups := []model.Group{{Name: "dev", Paths: []model.PathRule{
		{Prefix: "~", Allow: true, CanWrite: true},
		{Prefix: "/", Allow: false},
	}}}

	ayse := SFTPDecider(groups, "/home/ayse")
	yigit := SFTPDecider(groups, "/srv/people/yigit")

	if ok, why := ayse(sftpaudit.Request{Path: "/home/ayse/notlar"}); !ok {
		t.Errorf("kendi evi reddedildi: %s", why)
	}
	if ok, _ := ayse(sftpaudit.Request{Path: "/srv/people/yigit/notlar"}); ok {
		t.Error("başkasının evi açıldı")
	}
	// Ev /home altında olmak zorunda değil: yol hedeften okunuyor.
	if ok, why := yigit(sftpaudit.Request{Path: "/srv/people/yigit/notlar"}); !ok {
		t.Errorf("/home dışındaki ev reddedildi: %s", why)
	}
	if ok, _ := yigit(sftpaudit.Request{Path: "/home/ayse/notlar"}); ok {
		t.Error("başkasının evi açıldı")
	}
}

/*
 * ⚠️ EVİN İÇİNDEN DAL KESİLEBİLİYOR. `~` izinliyken `~/.ssh` reddi
 * çalışmalı: en uzun eşleşen önek kazanıyor ve genişletme uzunluğu
 * değiştirdiği için bu, genişletmeden SONRA hâlâ doğru olmak zorunda.
 */
func TestADenyUnderTheHomeStillCuts(t *testing.T) {
	d := SFTPDecider([]model.Group{{Name: "dev", Paths: []model.PathRule{
		{Prefix: "~", Allow: true, CanWrite: true},
		{Prefix: "~/.ssh", Allow: false},
	}}}, "/home/ayse")

	if ok, _ := d(sftpaudit.Request{Path: "/home/ayse/notlar"}); !ok {
		t.Error("ev reddedildi")
	}
	if ok, _ := d(sftpaudit.Request{Path: "/home/ayse/.ssh/id_ed25519"}); ok {
		t.Error("~/.ssh reddi çalışmadı")
	}
}

/*
 * ⚠️ EV OKUNAMAZSA HİÇBİR ŞEYE İZİN YOK.
 *
 * Kuralı atlamak ilk bakışta zararsız görünüyor ve değil: `~/.ssh` RET
 * kuralı sessizce düşerse, yöneticinin kestiğini sandığı dal açık kalır.
 * Değerlendirilemeyen bir politika, yok sayılabilecek bir politika değil.
 */
func TestAnUnreadableHomeRefusesEverything(t *testing.T) {
	d := SFTPDecider([]model.Group{{Name: "dev", Paths: []model.PathRule{
		{Prefix: "~", Allow: true, CanWrite: true},
		{Prefix: "~/.ssh", Allow: false},
		{Prefix: "/tmp", Allow: true},
	}}}, "")

	if d == nil {
		t.Fatal("politika hiç kurulmadı")
	}
	for _, p := range []string{"/home/ayse", "/home/ayse/.ssh/id", "/tmp/x"} {
		ok, why := d(sftpaudit.Request{Path: p})
		if ok {
			t.Errorf("%s açıldı", p)
		}
		if why == "" {
			t.Errorf("%s reddedildi ama sebep yok", p)
		}
	}
}

// Ev token'ı olmayan kurallar okunamayan evden etkilenmiyor.
func TestRulesWithoutTheTokenAreUnaffected(t *testing.T) {
	d := SFTPDecider([]model.Group{{Name: "dev", Paths: []model.PathRule{
		{Prefix: "/srv", Allow: true},
	}}}, "")

	if ok, why := d(sftpaudit.Request{Path: "/srv/data"}); !ok {
		t.Errorf("token kullanmayan kural bozuldu: %s", why)
	}
}

/*
 * ⚠️ BAŞKASININ EVİ TOKEN'LA ADRESLENEMİYOR. "~veli" kabuğun sözdizimi;
 * burada bir yol öneki olarak okunsaydı, kuralı yazanın beklemediği bir
 * yere erişim açardı.
 */
func TestOnlyTheOwnHomeFormIsATokenRule(t *testing.T) {
	if model.IsHomeRule("~veli") {
		t.Error("~veli token sayıldı")
	}
	if !model.IsHomeRule("~") || !model.IsHomeRule("~/.ssh") {
		t.Error("kendi ev biçimi token sayılmadı")
	}
	// Token olmayan bir önek genişletmeden geçiyor.
	if got, ok := ExpandHome("~veli", "/home/ayse"); !ok || got != "~veli" {
		t.Errorf("genişletme = %q, %v", got, ok)
	}
}

// Mutlak olmayan ya da boş ev, çözülemedi demek.
func TestAHomeThatIsNotAbsoluteIsNoHome(t *testing.T) {
	for _, home := range []string{"", "home/ayse", "  "} {
		if _, ok := ExpandHome("~", home); ok {
			t.Errorf("%q ev olarak kabul edildi", home)
		}
	}
}

// UsesHome, bedeli yalnızca token kullananlara bırakan anahtar.
func TestUsesHomeOnlySeesTokenRules(t *testing.T) {
	if UsesHome([]model.Group{{Paths: []model.PathRule{{Prefix: "/srv"}}}}) {
		t.Error("token yokken ev sorulacaktı")
	}
	if !UsesHome([]model.Group{{Paths: []model.PathRule{{Prefix: "/srv"}, {Prefix: "~/x"}}}}) {
		t.Error("token varken ev sorulmayacaktı")
	}
}
