package ca

import (
	"crypto/rand"
	"fmt"
	"maps"
	"math/big"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	timeShiftSec = 60 * time.Second
)

// CertRequest, tek bir kullanıcı sertifikası için istenenleri taşır.
//
// Her alan bir güvenlik kararıdır; hiçbiri "kolaylık olsun" diye
// varsayılana bırakılmamalı.
type CertRequest struct {
	// PublicKey, sertifikalanacak anahtar. S2.3'te bu, oturum başına
	// üretilen ve diske hiç yazılmayan efemeral bir anahtar olacak.
	PublicKey ssh.PublicKey

	// KeyID, sertifikanın kim için kesildiği ("yigit@warewave.io").
	// Hedefteki sshd bunu auth log'una yazar — audit izinin ta kendisi.
	KeyID string

	// Principals, sertifikanın geçerli olduğu OS kullanıcı adları.
	// ⚠️ ASLA BOŞ BIRAKILMAZ — sebebi Sign'ın yorumunda.
	Principals []string

	// ValidFor, sertifikanın ömrü. Kısa tut: sertifika sızarsa pencere
	// bu kadar açık kalır.
	ValidFor time.Duration

	// Extensions, sertifikanın izin verdiği yetenekler. Boş bırakılırsa
	// yalnızca güvenli varsayılan uygulanır (bkz. Sign).
	Extensions map[string]string
}

// Sign issues a user certificate for req, signed by the CA.
//
// ⚠️ BU DOSYA SENİN (plan §0). Aşağıdaki kurallar planın S2.2 bölümünden;
// her biri sign_test.go'da bir testle karşılanıyor. Kodu satır satır sen
// yaz, ben gözden geçireyim.
//
// Doğru implementasyonun taşıması gerekenler:
//
//   - CertType: ssh.UserCert. Host sertifikası değil — tip karışırsa
//     hedef sertifikayı bambaşka bir amaçla değerlendirir.
//
//   - ValidPrincipals: req.Principals. BOŞSA HATA DÖN.
//     Sebebi x/crypto'nun kendi kaynağında yazılı (certs.go):
//     "By default, certs are valid for all users/hosts."
//     Yani boş liste "kısıtlama yok" demek — root dahil her kullanıcı
//     için geçerli bir sertifika basmış olursun. Sessizce geçmesi,
//     bu projedeki en pahalı hata olurdu.
//
//   - ValidAfter: ŞİMDİDEN 60 SANİYE ÖNCE. Bastion ile hedefin saatleri
//     birkaç saniye kayıksa, "şu andan itibaren geçerli" bir sertifika
//     hedef tarafından "henüz geçerli değil" diye reddedilir. Geriye
//     tarihlemek bu toleransı verir.
//
//   - ValidBefore: ValidAfter + req.ValidFor.
//     ⚠️ Dikkat: geriye tarihleme yüzünden kullanılabilir pencere
//     ValidFor'dan 60 sn KISADIR. ValidFor bu paydan küçük ya da ona
//     eşitse sertifika doğduğu anda ölmüş olur — bunu hata say.
//
//   - Serial: her sertifika için benzersiz. Audit'te "hangi sertifika"
//     sorusunun cevabı bu; crypto/rand ile üret (math/rand DEĞİL).
//
//   - KeyId: req.KeyID. Boşsa hata — kime kesildiği bilinmeyen bir
//     sertifika, denetlenemez bir erişim demektir.
//
//   - Permissions.Extensions: "permit-pty" HER ZAMAN açık (interaktif
//     oturum bunsuz çalışmaz). "permit-port-forwarding" ve
//     "permit-agent-forwarding" VARSAYILAN KAPALI — istenirse
//     req.Extensions ile açılır. Varsayılan deny ilkesi burada da geçerli.
//
//   - CriticalOptions: S2'de boş. İleride "source-address" ya da
//     "force-command" gerekirse buraya girer.
//
//   - İmza: cert.SignCert(rand.Reader, c.signer). Bu, hem Signature'ı hem
//     SignatureKey'i doldurur.
func (c *CA) Sign(req CertRequest) (*ssh.Certificate, error) {
	if len(req.Principals) == 0 {
		return nil, fmt.Errorf("ca.Sign: req.Principals has no member")
	}

	if req.KeyID == "" {
		return nil, fmt.Errorf("ca.Sign: req.KeyID is empty")
	}

	if req.PublicKey == nil {
		return nil, fmt.Errorf("ca.Sign: req.PublicKey is empty")
	}

	if req.ValidFor.Seconds() <= timeShiftSec.Seconds() {
		return nil, fmt.Errorf("ca.Sign: cert lifetime too short")
	}

	validAfter := time.Now().Add(-timeShiftSec)
	validBefore := validAfter.Add(req.ValidFor)

	serial, err := generateRandomSerial64()
	if err != nil {
		return nil, fmt.Errorf("ca.Sign: %w", err)
	}

	sshPermissionExtensions := map[string]string{
		"permit-pty": "",
	}
	if len(req.Extensions) > 0 {
		maps.Copy(sshPermissionExtensions, req.Extensions)
	}

	cert := ssh.Certificate{
		Key:             req.PublicKey,
		CertType:        ssh.UserCert,
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
		ValidPrincipals: req.Principals,
		Serial:          serial,
		KeyId:           req.KeyID,
		Permissions:     ssh.Permissions{Extensions: sshPermissionExtensions},
	}

	err = cert.SignCert(rand.Reader, c.signer)
	if err != nil {
		return nil, fmt.Errorf("ca.Sign: %w", err)
	}

	return &cert, nil
}

func generateRandomSerial64() (uint64, error) {
	// OpenSSH uses a uint64 (8 bytes) for certificate serial tracking numbers
	max := new(big.Int).SetUint64(18446744073709551615) // Max uint64
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0, err
	}
	return n.Uint64(), nil
}
