// Package model holds postern's domain types.
//
// S2'de bu tipler config'den elle kuruluyordu; S3'ten beri veritabanından
// geliyorlar (şema bu alanların birebir karşılığı). Kararları veren kod
// model tiplerine baktığı için, kaynağın değişmesi policy'yi etkilemedi —
// motorun SQLite'tan PostgreSQL'e geçmesi de bu pakete dokunmadı.
package model

import (
	"fmt"
	"regexp"
)

// User, bastion'da kimliği doğrulanmış kişi.
type User struct {
	// Name, postern kullanıcı adı ("yigit"). auth.go'nun doğruladığı ve
	// Permissions'a koyduğu değer.
	Name string

	// OSUser, kişinin hedeflerdeki VARSAYILAN hesabı. İstek boş geldiğinde
	// principal bu olur.
	//
	// S3 şemasında users.os_user (NOT NULL) — kişiye özel, paylaşılmaz.
	// Driver 1'in özü bu alan: herkes hedefe kendi adıyla düşüyor.
	OSUser string

	// Groups, kişinin sahip olduğu gruplar. Hedef erişimi rollerden gelir.
	Groups []Group

	// SSOOnly true ise bu kullanıcı YALNIZCA kimlik sağlayıcı üzerinden
	// girebilir; public key ile girişi reddedilir.
	//
	// IdP'den otomatik oluşan (JIT) kullanıcılar böyle doğar: erişimleri
	// IdP'de kapatılınca gerçekten bitsin ve grupları her girişte
	// tazelensin diye. Elle oluşturulan servis hesapları false kalır.
	SSOOnly bool

	/*
	 * DirBound, hesabın bir DİZİN kimliğine bağlı olduğu.
	 *
	 * ⚠️ Oturum açılışında dizine yeniden sorulup sorulmayacağının
	 * DOĞRU koşulu bu — SSOOnly değil. Ölçüldü: yetkisi dizinden gelen
	 * bir yönetici (admin_via='group') sso_only=false ile duruyordu,
	 * yani dizinde kapatılsa bile anahtarıyla oturum açardı.
	 */
	DirBound bool

	// Admin, uygulama YÖNETİM yetkisi (kullanıcı/grup/hedef değiştirme,
	// web'deki yönetim sayfaları). Hedef erişimiyle ilgisi yok: admin
	// olmayan biri terminale girebilir, admin olan biri grubu yoksa hiçbir
	// hedefe giremez. İki eksen bilerek ayrık.
	Admin bool
}

// osUserNamePattern is what a target's account name may look like.
//
// ⚠️ KURAL BURADA, ÇÜNKÜ İKİ YERDE GEREKİYOR: politika kapısı (son
// savunma) ve YAZMA yolları (hesabın hiç bozuk doğmaması). İkisine ayrı
// birer kopya koymak, ölçülmüş bir arızanın tam olarak sebebiydi:
// kural yalnızca politikada vardı, yazma yollarında yoktu ve hesap
// "kurulmuş görünüp her oturumda reddedilen" bir hâlde doğuyordu.
//
// Desen kasten dar: POSIX'in taşınabilir kullanıcı adı kümesi. Büyük
// harf yok (çoğu sistemde ayrı bir hesap demek), '@' yok (Entra ID'nin
// UPN'i buraya düşer), Türkçe harf yok.
var osUserNamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

// ValidOSUserName reports whether name may be used as a target account.
func ValidOSUserName(name string) bool {
	return osUserNamePattern.MatchString(name)
}

/*
 * ControlCharAt, dizgideki ilk kontrol karakterinin bayt konumu; yoksa -1.
 *
 * ⚠️ TEK TANIM, İKİ KAPI. Aynı kural hem SERTİFİKA İMZALANIRKEN
 * (ca.Sign: key id ve principal) hem de kullanıcı adı VERİTABANINA
 * YAZILIRKEN uygulanıyor. İki ayrı kopya yazmak, ikisinin ayrışması
 * demekti — ve ayrışmanın yönü fark ediyor: yazma kuralı imzalama
 * kuralından GEVŞEK olursa, açılabilen ama sertifikası hiç kesilemeyen
 * bir hesap doğar. Bu depo o arızayı bir kez ölçtü (os_user kuralı
 * yalnızca politika kapısındaydı; hesap "kurulmuş görünüp her oturumda
 * reddedilen" hâlde doğuyordu, bkz. refuseBadOSUser).
 *
 * ⚠️ C1 DE SAYILIYOR (U+0080-U+009F), imzalama tarafındaki bayt
 * taramasının kaçırdığı aralık: UTF-8'de C2 80 olarak kodlanıyor ve iki
 * baytın ikisi de 0x20'nin üstünde. Terminal ve günlük ayrıştırıcıları
 * onları da yorumluyor. Kural bu yüzden rune üzerinden.
 */
func ControlCharAt(s string) int {
	for i, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return i
		}
	}

	return -1
}

/*
 * ValidUsername, adın postern kullanıcı adı olarak yazılabilir olduğu.
 *
 * ⚠️ YALNIZCA KONTROL KARAKTERİ ELENİYOR, ŞEKİL DEĞİL. Kullanıcı adı
 * kimlik sağlayıcısından geliyor ve e-posta, UPN ya da uzun bir dizin
 * adı olabiliyor; ona bir desen dayatmak kurumun kendi ad alanını
 * reddetmek olurdu. Elenen şey ÖLÇÜLEN zarar: ad, sertifikanın key
 * id'sine giriyor ve hedefin sshd günlüğüne olduğu gibi yazılıyor —
 * satır sonu taşıyan bir ad, o günlüğe kendi satırını yazdırıyordu.
 */
func ValidUsername(name string) error {
	if i := ControlCharAt(name); i >= 0 {
		return fmt.Errorf("username %q has a control character at byte %d", name, i)
	}

	return nil
}
