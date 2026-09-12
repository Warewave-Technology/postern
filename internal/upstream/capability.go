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
	"for n in useradd adduser groupadd addgroup usermod userdel groupdel visudo; do command -v $n; done",
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

	// Missing, eksik olanların adı — panelin yazacağı cümle bu.
	Missing []string
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
func ParseCapabilities(sudoOut, whichOut, osRelease string) ManageCapabilities {
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
		}
	}

	c.Family = familyOf(osRelease)

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
 */
func (c *Conn) Capabilities(ctx context.Context) (ManageCapabilities, error) {
	if c == nil || c.client == nil {
		return ManageCapabilities{}, fmt.Errorf("upstream.Capabilities: no connection")
	}

	out := make([]string, 0, len(CapabilityCommands)+1)
	for _, cmd := range CapabilityCommands {
		o, err := c.run(ctx, cmd)
		if err != nil {
			/*
			 * ⚠️ ÇIKIŞ KODU YOK SAYILIYOR, ÇIKTI ALINIYOR. `command -v`
			 * bulunamayan her ad için sıfırdan farklı dönüyor ve
			 * `sudo -n -l` yetkisizken hata veriyor — ikisi de bizim
			 * için bir CEVAP, arıza değil.
			 */
			out = append(out, o)
			continue
		}
		out = append(out, o)
	}

	osRelease, _ := c.run(ctx, "cat /etc/os-release")

	return ParseCapabilities(out[0], out[1], osRelease), nil
}

// model paketine bağımlılığı koru: TargetProbe ile aynı yerde yaşıyor.
var _ = model.TargetProbe{}
