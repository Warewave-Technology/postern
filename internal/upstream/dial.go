// Package upstream implements the outbound (client-side) half of the
// bastion: dialing targets and opening channels on their behalf.
package upstream

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/ca"
	"github.com/warewave/postern/internal/config"
)

// Conn is an established SSH connection to a target.
type Conn struct {
	client *ssh.Client
	target config.TargetConfig
}

// Dial connects to target t as an SSH client, authenticating with the key
// at t.KeyFile. The target's host key MUST match t.HostKey.
func Dial(ctx context.Context, t config.TargetConfig) (*Conn, error) {
	data, err := os.ReadFile(t.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("target %s: %w", t.Name, err)
	}

	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("target %s: %w", t.Name, err)
	}

	conn, err := dialer(ctx, t, signer)
	if err != nil {
		return nil, fmt.Errorf("upstream.Dial: %w", err)
	}

	return conn, nil
}

// Client exposes the underlying SSH client — S1.4 testleri session açmak,
// S1.5 broker'ı hedefte kanal açmak için kullanacak.
func (c *Conn) Client() *ssh.Client { return c.client }

// Close closes the connection to the target.
func (c *Conn) Close() error {
	if c != nil && c.client != nil {
		return c.client.Close()
	}

	return nil
}

// --- S2.3: sertifika ile bağlanma ---

// certValidFor, kesilen sertifikanın ömrü.
//
// Sertifika yalnızca ilk el sıkışmada kullanılır; oturum kurulduktan sonra
// süresi dolsa bile bağlantı yaşamaya devam eder. Dolayısıyla kısa tutmanın
// bedeli yok, karşılığı ise büyük: sertifika bir şekilde sızarsa saldırganın
// penceresi bu kadar dar olur.
const certValidFor = 5 * time.Minute

// Identity, oturumu açan kişiyi ve onun hedefteki karşılığını taşır.
type Identity struct {
	// PosternUser, bastion'da kimliği DOĞRULANMIŞ kullanıcı (auth.go'nun
	// Permissions'a koyduğu "postern-user"). Sertifikanın KeyId'sine girer
	// ve hedefin auth log'una düşer — audit izinin başladığı yer burası.
	PosternUser string

	// OSUser, hedefte hangi OS kullanıcısı olarak oturum açılacağı.
	// Hem sertifikanın tek principal'ı hem SSH bağlantısının kullanıcı adı.
	//
	// ⚠️ S2.4'te bu değeri policy.Authorize belirleyecek (senin dosyan).
	// Kullanıcı girdisinden DOĞRUDAN gelmemeli: principal'a giden değer
	// doğrulanmamışsa, kullanıcı istediği hesabı seçer.
	OSUser string
}

// DialWithCert connects to t using a freshly minted, short-lived certificate
// instead of a static key.
//
// Bu, S2'nin bütün amacı: hedefte hiçbir authorized_keys satırı yok, erişimi
// veren şey CA'nın imzaladığı ve kullanıcının kimliğini taşıyan bir
// sertifika. Kullanıcı hedefe KENDİ ADIYLA düşüyor.
//
// TODO(yigit) — S2.3: implement et.
//
//  1. Efemeral ed25519 anahtar çifti üret (crypto/ed25519 + crypto/rand).
//     ⚠️ DİSKE YAZMA. Oturuma özel, süreç belleğinde doğup ölecek
//     (plan Ek B: "Efemeral anahtarlar diske yazılmıyor").
//
//  2. ssh.NewSignerFromKey ile efemeral signer'ı üret.
//
//  3. authority.Sign(ca.CertRequest{...}):
//     PublicKey  → efemeral signer'ın public key'i
//     KeyID      → identity.PosternUser (audit izi)
//     Principals → []string{identity.OSUser} — TEK principal
//     ValidFor   → certValidFor
//     Extensions → nil (permit-pty'yi Sign zaten veriyor)
//
//  4. ssh.NewCertSigner(cert, ephemeralSigner) → certSigner.
//     Bu, "sertifikayı sun, özel anahtarla imzala" diyen auth yöntemidir.
//
//  5. ClientConfig:
//     User            → identity.OSUser (hedefteki hesap)
//     Auth            → ssh.PublicKeys(certSigner)
//     HostKeyCallback → hostKeyCallback(t.HostKey) — S1'deki pinleme AYNEN
//     duruyor. Sertifika bizim hedefe kimliğimizi kanıtlar; hedefin bize
//     kimliğini kanıtlaması hâlâ host key'in işi.
//
//  6. Bağlantı katmanları Dial ile birebir aynı: net.Dialer.DialContext →
//     context.AfterFunc(nc.Close) → ssh.NewClientConn → ssh.NewClient.
//     Bu ortak kısmı Dial ile paylaşan bir yardımcıya çıkarmak isteyebilirsin;
//     ikisinin tek farkı ClientConfig'in nasıl kurulduğu.
func DialWithCert(ctx context.Context, t config.TargetConfig, identity Identity, authority *ca.CA) (*Conn, error) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("upstream.DialWithCert: %w", err)
	}

	ephemeralSigner, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("upstream.DialWithCert: %w", err)
	}

	cert, err := authority.Sign(ca.CertRequest{
		PublicKey:  ephemeralSigner.PublicKey(),
		KeyID:      identity.PosternUser,
		Principals: []string{identity.OSUser},
		ValidFor:   certValidFor,
		Extensions: nil,
	})
	if err != nil {
		return nil, fmt.Errorf("upstream.DialWithCert: %w", err)
	}

	signer, err := ssh.NewCertSigner(cert, ephemeralSigner)
	if err != nil {
		return nil, fmt.Errorf("upstream.DialWithCert: %w", err)
	}

	t.User = identity.OSUser

	conn, err := dialer(ctx, t, signer)
	if err != nil {
		return nil, fmt.Errorf("upstream.DialWithCert: %w", err)
	}

	return conn, nil
}

func dialer(ctx context.Context, t config.TargetConfig, signer ssh.Signer) (*Conn, error) {
	cb, algos, err := hostKeyCallback(t.HostKey)
	if err != nil {
		return nil, fmt.Errorf("target %s: %w", t.Name, err)
	}

	ccfg := &ssh.ClientConfig{
		User:              t.User,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback:   cb,
		HostKeyAlgorithms: algos,
	}

	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))

	var d net.Dialer
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("target %s: %w", t.Name, err)
	}

	stop := context.AfterFunc(ctx, func() { nc.Close() })
	defer stop()

	c, chans, reqs, err := ssh.NewClientConn(nc, addr, ccfg)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("target %s: %w", t.Name, err)
	}

	client := ssh.NewClient(c, chans, reqs)

	return &Conn{client: client, target: t}, nil
}
