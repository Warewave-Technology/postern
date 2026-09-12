package upstream

// Yönetilebilirlik yoklamasının çıktı ayrıştırması.

import (
	"strings"
	"testing"
)

/*
 * ⚠️ ÇIKTILAR UYDURULMADI, GERÇEK KONTEYNERLERDEN ALINDI.
 *
 * Uydurulmuş bir çıktıya karşı yazılan ayrıştırıcı, kendi
 * varsayımlarını doğrular. Buradaki iki blok Debian 13 ve Alpine 3.22
 * üzerinde gerçekten koşturuldu.
 */
const debianWhich = `/usr/sbin/useradd
/usr/sbin/adduser
/usr/sbin/groupadd
/usr/sbin/addgroup
/usr/sbin/usermod
/usr/sbin/userdel
/usr/sbin/groupdel
/usr/sbin/visudo`

const debianSudo = `
User postern may run the following commands on 0f04332b235c:
    (ALL) NOPASSWD: ALL`

// Alpine'da busybox yalnızca ikisini veriyor.
const alpineWhich = `/usr/sbin/adduser
/usr/sbin/addgroup`

func TestDebianTargetIsManageable(t *testing.T) {
	c := ParseCapabilities(debianSudo, debianWhich, "ID=debian\nID_LIKE=\n")

	if !c.Manageable() {
		t.Fatalf("yönetilebilir sayılmadı: %s", c.Summary())
	}
	/*
	 * ⚠️ useradd KAZANMALI. Debian'da ikisi de var; adduser bir Perl
	 * sarmalayıcı ve bayrakları dağıtıma göre değişiyor. Yanlışını
	 * seçmek, komutu sessizce yanlış kurmak demek.
	 */
	if c.AddUser != "/usr/sbin/useradd" {
		t.Errorf("AddUser = %q, useradd bekleniyordu", c.AddUser)
	}
	if c.AddGroup != "/usr/sbin/groupadd" {
		t.Errorf("AddGroup = %q, groupadd bekleniyordu", c.AddGroup)
	}
	if c.Family != "debian" {
		t.Errorf("aile = %q", c.Family)
	}
}

/*
 * ⚠️ BU TESTİN KORUDUĞU ŞEY: TAHMİN ETMEMEK.
 *
 * Alpine'da busybox'ın adduser'ı var ama usermod, visudo ve sudo yok.
 * "adduser gördüm, yönetebilirim" demek yarım yapılandırılmış bir
 * makine bırakırdı — ve panel yeşil görünürdü, ki bu hiç
 * yapılandırmamaktan kötü.
 */
func TestAlpineTargetIsRefusedWithReasons(t *testing.T) {
	c := ParseCapabilities("sudo: command not found", alpineWhich, "ID=alpine\n")

	if c.Manageable() {
		t.Fatal("YÖNETİLEBİLİR SAYILDI: eksik araçlarla makine yarım kalırdı")
	}

	summary := c.Summary()
	for _, want := range []string{"sudo", "usermod", "visudo"} {
		if !strings.Contains(summary, want) {
			t.Errorf("%q eksiği söylenmedi: %q", want, summary)
		}
	}
	// Bulunan araç yine de kaydediliyor: operatöre ne VAR olduğunu da
	// söylemek, neyi kuracağını gösteriyor.
	if c.AddUser != "/usr/sbin/adduser" {
		t.Errorf("bulunan adduser kaydedilmedi: %q", c.AddUser)
	}
	if c.Family != "alpine" {
		t.Errorf("aile = %q", c.Family)
	}
}

/*
 * ⚠️ "sudo" KELİMESİNİ GÖRMEK, SUDO HAKKI DEMEK DEĞİL.
 *
 * Yetkisiz bir hesapta `sudo -n -l` çıktısında da "sudo" geçiyor.
 * Kelimeyi aramak, hakkı olmayan bir hesabı yetkili sayardı — yani
 * yoklamanın cevapladığı soruyu tam ters çevirirdi.
 */
func TestSudoIsNotInferredFromTheWordSudo(t *testing.T) {
	c := ParseCapabilities(
		"sudo: a password is required\nsudo: unable to resolve host",
		debianWhich, "ID=debian\n")

	if c.Sudo {
		t.Error("HAKKI OLMAYAN HESAP YETKİLİ SAYILDI")
	}
	if c.Manageable() {
		t.Error("sudo'suz hedef yönetilebilir sayıldı")
	}
}

// ⚠️ Türev dağıtımlar kendi ID'lerini veriyor; aile ID_LIKE'ta.
func TestDerivedDistributionsFindTheirFamily(t *testing.T) {
	for _, tc := range []struct{ osRelease, want string }{
		{"ID=rocky\nID_LIKE=\"rhel centos fedora\"\n", "rhel"},
		{"ID=ubuntu\nID_LIKE=debian\n", "debian"},
		{"ID=\"opensuse-leap\"\nID_LIKE=\"suse opensuse\"\n", "suse"},
		{"ID=plan9\n", ""},
	} {
		if got := familyOf(tc.osRelease); got != tc.want {
			t.Errorf("familyOf(%q) = %q, %q bekleniyordu", tc.osRelease, got, tc.want)
		}
	}
}

/*
 * ⚠️ BOŞ ÇIKTI "HER ŞEY VAR" DEMEK DEĞİL. Yoklama yarıda kesildiğinde
 * (bağlantı koptu, komut hiç koşmadı) sonuç yönetilebilir OLMAMALI:
 * ölçülmemiş bir şeyi ölçülmüş saymak, bu dosyadaki tek gerçek risk.
 */
func TestEmptyOutputIsNotTakenAsSuccess(t *testing.T) {
	if ParseCapabilities("", "", "").Manageable() {
		t.Fatal("BOŞ YOKLAMA YÖNETİLEBİLİR SAYILDI")
	}
}
