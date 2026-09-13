package upstream

/*
 * Yönetim bağlantısı: postern'in hedefi KENDİ adına açması.
 *
 * ⚠️ BU DOSYADAKİ SERTİFİKA, SİSTEMİN EN GÜÇLÜ KİMLİĞİ. Açtığı hesap
 * hedefte parolasız root sudo tutuyor (deploy/ansible/roles/postern_target).
 * Bu yüzden ayrı ve ADI OLAN bir kapı: DialWithCert'e bir principal alanı
 * eklemek, Identity'yi yanlış dolduran her çağıranın onu üretebilmesi
 * demekti. Ayrı bir fonksiyon grep'lenebiliyor ve her çağrı yeri bilinçli
 * bir karar.
 *
 * ⚠️ İNSANIN ELİNE SERTİFİKA VERİLMİYOR. Bunu bir CLI komutu ("ca sign")
 * yapsaydı, ortaya filodaki her makinenin root'unu açan, postern'in
 * dışında yaşayan ve ne için kullanıldığı hiçbir yere yazılmayan bir
 * kimlik çıkardı. ca.Sign'ın ömür için üst sınırı yok ve depoda iptal
 * listesi (KRL) yok: elden çıkmış bir sertifikayı geri almanın tek yolu
 * süresinin dolmasını beklemek. Sertifika yalnızca burada, bellekte,
 * iki dakikalık üretiliyor.
 */

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/ca"
	"github.com/Warewave-Technology/postern/internal/model"
)

/*
 * manageCertValidFor, yönetim sertifikasının ömrü.
 *
 * ⚠️ OTURUM SERTİFİKASINDAN KISA. Sertifikanın geçerli olması gereken an
 * yalnızca el sıkışma anı: bağlantı kurulduktan sonra süresi dolsa da
 * oturum devam ediyor (OpenSSH yeniden doğrulamıyor). Uzun bir yayılım
 * koşusu uzun bir ömür gerektirmiyor, ve kısa ömür sızmış bir
 * sertifikanın işe yarayacağı pencereyi daraltıyor.
 */
const manageCertValidFor = 2 * time.Minute

/*
 * DialManagement, hedefe yönetim hesabıyla bağlanır.
 *
 * ⚠️ actor VE reason ZORUNLU ve sertifikanın KeyID'sine giriyor. KeyID
 * hedefin KENDİ sshd günlüğüne düşüyor ("Accepted publickey for postern
 * ... ID postern-manage: admin: check"). Makinenin sahibi postern'in
 * denetim kaydını göremiyor olabilir; o satırda düğmeye kimin bastığı
 * yazmıyorsa, filo çapında bir root girişi hiçbir kişiye
 * bağlanamazdı.
 */
func DialManagement(ctx context.Context, t model.Target, authority *ca.CA, actor, reason string) (*Conn, error) {
	if authority == nil {
		return nil, fmt.Errorf("upstream.DialManagement: no certificate authority")
	}

	/*
	 * ⚠️ KONTROL KARAKTERLERİ TEMİZLENİYOR. KeyID hedefin auth.log'una
	 * olduğu gibi yazılıyor; içine satır sonu giren bir ad, o günlükte
	 * sahte bir satır uydurabilirdi. truncate bunları atıyor.
	 */
	actor = truncate(strings.TrimSpace(actor), 64)
	reason = truncate(strings.TrimSpace(reason), 96)
	if actor == "" || reason == "" {
		return nil, fmt.Errorf("upstream.DialManagement: an actor and a reason are " +
			"required; both are written to the target's own log")
	}

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("upstream.DialManagement: %w", err)
	}

	ephemeralSigner, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("upstream.DialManagement: %w", err)
	}

	cert, err := authority.Sign(ca.CertRequest{
		PublicKey:  ephemeralSigner.PublicKey(),
		KeyID:      model.ManagementPrincipal + ": " + actor + ": " + reason,
		Principals: []string{model.ManagementPrincipal},
		ValidFor:   manageCertValidFor,
		/*
		 * ⚠️ PTY YOK — VE BUNU "Extensions: nil" SAĞLAMIYOR. ca.Sign her
		 * sertifikaya permit-pty'yi koşulsuz ekliyor, çünkü insanlar
		 * kabuk açıyor; bu satırın ilk hâli nil verip PTY'nin kapalı
		 * olduğunu İDDİA ediyordu ve yanlıştı. Yönetim koşusu komut
		 * çalıştırıyor, PTY istemiyor; filodaki her makinede root tutan
		 * bir kimliğe gerekmeyen izin verilmiyor. Port yönlendirme ve
		 * agent forwarding zaten varsayılan olarak kapalı.
		 */
		WithoutPTY: true,
	})
	if err != nil {
		return nil, fmt.Errorf("upstream.DialManagement: %w", err)
	}

	signer, err := ssh.NewCertSigner(cert, ephemeralSigner)
	if err != nil {
		return nil, fmt.Errorf("upstream.DialManagement: %w", err)
	}

	/*
	 * ⚠️ GİRİŞ ADI İLE PRINCIPAL BİLEREK FARKLI — ve bu, DialWithCert'in
	 * yorumundaki "kullanıcı adı principal'la aynı olmak zorunda"
	 * kuralının TEK istisnası. Hedefte AuthorizedPrincipalsFile %u:
	 * giriş adı hangi dosyanın okunacağını seçiyor, principal o dosyada
	 * yazmalı. Yönetim hesabının dosyasında yalnızca "postern-manage"
	 * var; AuthorizedPrincipalsFile'ı OLMAYAN bir hedefte ise sshd giriş
	 * adını principal listesinde arıyor, "postern" orada yok ve giriş
	 * reddediliyor. Yani iki yapılandırmada da yanlış yöne düşülmüyor.
	 */
	conn, err := dialer(ctx, t, model.ManagementAccount, signer)
	if err != nil {
		return nil, fmt.Errorf("upstream.DialManagement: %w", err)
	}

	return conn, nil
}
