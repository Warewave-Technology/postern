package upstream

/*
 * Hedefin YÖNETİLEBİLİR olup olmadığı.
 *
 * ⚠️ BU YOKLAMA, Probe'DAN FARKLI BİR YERDE KOŞUYOR VE FARK ÖNEMLİ.
 * Probe kullanıcının kendi bağlantısında çalışıyor; gerekçesi probe.go'da
 * yazılı ve o gün doğruydu: postern'in hedefte kullanıcılardan bağımsız,
 * kalıcı bir erişimi yoktu. Yönetim hesabıyla birlikte artık var, ve bu
 * yoklama onu kullanıyor. Yani buradaki komutlar hedefin günlüklerinde
 * "postern" olarak görünüyor, bağlanan kişi olarak değil — doğru olan da
 * bu, çünkü yapan gerçekten postern.
 *
 * ⚠️ TAHMİN YOK. Bir dağıtımı tanımadığımızda "muhtemelen useradd vardır"
 * demek, yarım yapılandırılmış bir makine bırakır ve panel yeşil görünür.
 * Yarım yapılandırılmış hedef, hiç yapılandırılmamış olandan kötüdür:
 * ilkinde kimse bakmaz.
 */

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/Warewave-Technology/postern/internal/model"
)

/*
 * CapabilityCommands, yönetilebilirliği ölçen SABİT komutlar.
 *
 * Probe'daki kuralın aynısı: derleme zamanında sabit, yapılandırılamaz,
 * salt okuma ve kabuk yorumuna açık hiçbir şey içermiyor. Operatörün
 * komut yazabildiği bir alan, config'e erişen herkese bütün filoda
 * uzaktan komut çalıştırma yetkisi verirdi.
 *
 * ⚠️ SON SÖZÜ ARACIN KENDİSİ SÖYLÜYOR. "sudoers dosyasını yazdık"
 * demek, sudo'nun onu OKUDUĞU anlamına gelmiyor: sudoers.d ancak ana
 * dosyada bir includedir satırı varsa okunuyor ve sıkılaştırılmış
 * kurulumlarda o satır kaldırılmış olabiliyor. `sudo -n -l` postern'in
 * KENDİ hakkını listeliyor; çıktı doluysa hem sudo çalışıyor hem de
 * kuralımızın okunduğu kanıtlanmış oluyor.
 */
var CapabilityCommands = []string{
	"sudo -n -l",
	/*
	 * ⚠️ DÖNGÜ, ÇOKLU ARGÜMAN DEĞİL — ÖLÇÜLDÜ. `command -v` POSIX'te
	 * TEK bir ad alıyor: Debian'ın dash'i çoklu argümanda yalnızca
	 * ilkini basıyor, Alpine'ın busybox'ı hiçbir şey basmıyor. İlk
	 * yazdığım biçim bu yüzden "yalnızca useradd var" diyordu ve
	 * sonuç sessizce yanlıştı.
	 *
	 * Döngüdeki adlar derleme zamanında sabit; dışarıdan hiçbir şey
	 * bu dizeye girmiyor, dolayısıyla "değişken içerik kabuğa
	 * verilmez" kuralı korunuyor.
	 */
	"for n in useradd adduser groupadd addgroup usermod userdel groupdel visudo bash; do command -v $n; done",
	/*
	 * ⚠️ sshd'YE SORULUYOR, YAPILANDIRMA DOSYASINA DEĞİL. Sertifikayla
	 * giriş, hesabın principals dosyasında principal'ı bulmaya bağlı ve o
	 * dosyanın YERİ sshd'nin ETKİN AuthorizedPrincipalsFile değeri —
	 * sshd_config'i okumak, Include ile gelen ya da ilk-değer-kazanır
	 * kuralıyla ezilen satırı yanlış okuturdu (Ansible rolündeki ölçüm).
	 * sshd -T root istiyor; yönetim hesabının sudo'su var. Çıktı boşsa
	 * (sshd yolda değil, -T desteklenmiyor) dosya bilinmiyor sayılıyor.
	 */
	"sudo -n sshd -T 2>/dev/null | awk 'tolower($1)==\"authorizedprincipalsfile\"{print $2}'",
}

/*
 * ManageCapabilities, hedefte neyin bulunduğu.
 *
 * ⚠️ ARAÇ ADLARI SAKLANIYOR, "var/yok" DEĞİL. useradd ile busybox
 * adduser'ın bayrakları farklı; hangisinin bulunduğunu bilmeden doğru
 * komutu kuramayız ve "adduser vardır" varsayımı Alpine'de sessizce
 * yanlış komut üretirdi.
 */
type ManageCapabilities struct {
	// Sudo, postern'in parolasız sudo hakkının GÖRÜLDÜĞÜ.
	Sudo bool

	// AddUser / AddGroup, bulunan araçların tam yolu ("" ise yok).
	AddUser  string
	AddGroup string
	ModUser  string
	DelUser  string
	DelGroup string
	Visudo   string

	// Family, os-release'den çıkan aile ("debian", "rhel", "alpine"…).
	Family string
	/*
	 * Shell, açılan hesaba yazılacak kabuk: bash bulunduysa onun yolu,
	 * yoksa /bin/sh. ⚠️ ÖLÇÜLDÜ: /bin/bash sabit yazılıydı ve Alpine'de
	 * hesap açılıyor, sertifika kabul ediliyor ve sshd "shell /bin/bash
	 * does not exist" diye kapıyı kapatıyordu.
	 */
	Shell string

	// Missing, eksik olanların adı — panelin yazacağı cümle bu.
	Missing []string
	/*
	 * PrincipalsFile, sshd'nin etkin AuthorizedPrincipalsFile deseni
	 * ("/etc/ssh/auth_principals/%u"). Boşsa ya sshd "none" diyor (giriş
	 * adı sertifikanın principal'ında aranır, dosya gerekmez) ya da
	 * sorulamadı. Geçici hesabın sertifikayla açılabilmesi için plan bu
	 * desene göre hesabın dosyasını yazıyor.
	 */
	PrincipalsFile string
}

/*
 * Manageable, postern'in bu hedefi yönetip yönetemeyeceği.
 *
 * ⚠️ POZİTİF KANIT İSTİYOR. "Eksik bir şey görmedim" yetmiyor; her
 * parçanın BULUNDUĞU görülmüş olmalı. Yoklama yarıda kesildiyse
 * (bağlantı koptu, komut boş döndü) sonuç "yönetilebilir" olmamalı.
 */
func (c ManageCapabilities) Manageable() bool {
	return len(c.Missing) == 0
}

// Summary, panelde ve denetim satırında görünecek tek cümle.
func (c ManageCapabilities) Summary() string {
	if c.Manageable() {
		return "manageable"
	}

	return "not manageable: " + strings.Join(c.Missing, ", ") + " missing"
}

/*
 * ParseCapabilities, sabit komutların çıktısını okur.
 *
 * Ayrı bir fonksiyon çünkü arıza burada yaşıyor: bağlantı kurmadan,
 * gerçek dağıtım çıktılarına karşı ölçülebiliyor.
 */
func ParseCapabilities(sudoOut, whichOut, osRelease, sshdPrincipals string) ManageCapabilities {
	var c ManageCapabilities

	/*
	 * ⚠️ "sudo" KELİMESİNİ ARAMIYORUZ, HAKKIN KENDİSİNİ ARIYORUZ.
	 * `sudo -n -l` yetkisi olmayan bir kullanıcıda hata basıyor ve o
	 * hatada da "sudo" geçiyor; kelimeyi aramak, hakkı olmayan bir
	 * hesabı yetkili sanmak olurdu.
	 */
	c.Sudo = strings.Contains(sudoOut, "NOPASSWD:") ||
		strings.Contains(sudoOut, "(ALL) ALL")

	for _, line := range strings.Split(whichOut, "\n") {
		p := strings.TrimSpace(line)
		if p == "" || !strings.HasPrefix(p, "/") {
			continue
		}
		switch path.Base(p) {
		case "useradd":
			c.AddUser = p
		case "adduser":
			// ⚠️ useradd VARSA O KAZANIYOR. Debian'da ikisi de var ve
			// adduser bir Perl sarmalayıcı: etkileşimli sorabiliyor,
			// bayrakları dağıtıma göre değişiyor. useradd her yerde
			// aynı davranıyor.
			if c.AddUser == "" {
				c.AddUser = p
			}
		case "groupadd":
			c.AddGroup = p
		case "addgroup":
			if c.AddGroup == "" {
				c.AddGroup = p
			}
		case "usermod":
			c.ModUser = p
		case "userdel":
			c.DelUser = p
		case "groupdel":
			c.DelGroup = p
		case "visudo":
			c.Visudo = p
		case "bash":
			c.Shell = p
		}
	}
	if c.Shell == "" {
		c.Shell = "/bin/sh"
	}

	c.Family = familyOf(osRelease)
	// "none" sshd'nin "dosya yok, giriş adına bak" cevabı; boşla aynı.
	if pf := strings.TrimSpace(sshdPrincipals); pf != "" && pf != "none" {
		c.PrincipalsFile = pf
	}

	// Eksik olanlar tek tek adlandırılıyor: "yönetilemiyor" demek,
	// operatöre ne yapacağını söylemiyor.
	if !c.Sudo {
		c.Missing = append(c.Missing, "passwordless sudo for postern")
	}
	if c.AddUser == "" {
		c.Missing = append(c.Missing, "useradd or adduser")
	}
	if c.AddGroup == "" {
		c.Missing = append(c.Missing, "groupadd or addgroup")
	}
	if c.ModUser == "" {
		c.Missing = append(c.Missing, "usermod")
	}
	/*
	 * ⚠️ visudo ZORUNLU. Onsuz sudoers dosyasını yerine koymadan
	 * doğrulayamayız, ve doğrulanmamış bir sudoers dosyası o makinede
	 * herkesin sudo'sunu götürür — postern'in kendisi dahil, yani
	 * makine kendini onaramaz hâle gelir.
	 */
	if c.Visudo == "" {
		c.Missing = append(c.Missing, "visudo")
	}

	return c
}

// familyOf, os-release'den dağıtım ailesini çıkarır.
func familyOf(osRelease string) string {
	var id, like string
	for _, line := range strings.Split(osRelease, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			id = v
		case "ID_LIKE":
			like = v
		}
	}

	// ⚠️ ID_LIKE ÖNCE DEĞİL SONRA: türev dağıtımlar kendi ID'lerini
	// veriyor ("rocky") ve ailesini ID_LIKE'ta söylüyor ("rhel fedora").
	for _, cand := range append([]string{id}, strings.Fields(like)...) {
		switch cand {
		case "debian", "ubuntu":
			return "debian"
		case "rhel", "fedora", "centos":
			return "rhel"
		case "suse", "opensuse", "sles":
			return "suse"
		case "alpine":
			return "alpine"
		}
	}

	return ""
}

/*
 * Capabilities, hedefte sabit komutları çalıştırıp yeteneği ölçer.
 *
 * ⚠️ HATA "YÖNETİLEBİLİR DEĞİL" DEMEK DEĞİL. Bağlantı koptuğunda
 * bilmediğimiz şeyi bilmiyoruz; onu "yönetilemez" diye kaydetmek,
 * ölçmediğimiz bir sonucu ölçülmüş gibi göstermek olurdu.
 *
 * ⚠️ BU KURAL YAZILIYDI AMA UYGULANMIYORDU. İlk hâli her hatayı yutup
 * boş çıktıyı ayrıştırıyordu: kopan bir bağlantı "sudo yok, useradd yok,
 * visudo yok" diye, hatasız dönüyordu. Sıfırdan farklı çıkış bir cevap
 * (CommandError), cevapsızlık ise hata.
 */
func (c *Conn) Capabilities(ctx context.Context) (ManageCapabilities, error) {
	if c == nil || c.client == nil {
		return ManageCapabilities{}, fmt.Errorf("upstream.Capabilities: no connection")
	}

	out := make([]string, 0, len(CapabilityCommands))
	for _, cmd := range CapabilityCommands {
		o, err := answered(c.Exec(ctx, cmd, ""))
		if err != nil {
			return ManageCapabilities{}, fmt.Errorf("upstream.Capabilities: %w", err)
		}
		out = append(out, o)
	}

	/*
	 * ⚠️ os-release'in YOKLUĞU BİR CEVAP. BSD'lerde ve bazı konteyner
	 * tabanlarında dosya yok; aile boş kalıyor ve karar bundan
	 * etkilenmiyor (Manageable aileye bakmıyor). Ama bağlantının burada
	 * kopması hâlâ bir hata.
	 */
	osRelease, err := answered(c.Exec(ctx, "cat /etc/os-release", ""))
	if err != nil {
		return ManageCapabilities{}, fmt.Errorf("upstream.Capabilities: %w", err)
	}

	return ParseCapabilities(out[0], out[1], osRelease, out[2]), nil
}

/*
 * answered, sıfırdan farklı çıkışı CEVAP sayar ve çıktıyı korur;
 * yalnızca cevapsızlığı hata olarak geçirir.
 *
 * `command -v` bulamadığı ad için, `sudo -n -l` yetkisiz hesap için
 * sıfırdan farklı dönüyor — ikisi de ölçümün kendisi.
 */
func answered(out string, err error) (string, error) {
	var cmdErr *CommandError
	if err == nil || errors.As(err, &cmdErr) {
		return out, nil
	}

	return "", err
}

// model paketine bağımlılığı koru: TargetProbe ile aynı yerde yaşıyor.
var _ = model.TargetProbe{}
