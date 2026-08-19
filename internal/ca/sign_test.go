package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// --- yardımcılar ---

func testCA(t *testing.T) *CA {
	t.Helper()

	c, err := Init(filepath.Join(t.TempDir(), "ca_ed25519"))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	return c
}

// subjectKey, sertifikalanacak anahtar. S2.3'te bu, oturum başına üretilen
// efemeral anahtar olacak.
func subjectKey(t *testing.T) ssh.PublicKey {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sshPub
}

// fakeConn, Authenticate'e principal'ı taşıyan asgari ssh.ConnMetadata.
// Hedefteki sshd de principal'ı bağlantının kullanıcı adından alır.
type fakeConn struct{ user string }

func (f fakeConn) User() string          { return f.user }
func (f fakeConn) SessionID() []byte     { return []byte("test-session") }
func (f fakeConn) ClientVersion() []byte { return []byte("SSH-2.0-test") }
func (f fakeConn) ServerVersion() []byte { return []byte("SSH-2.0-postern") }
func (f fakeConn) RemoteAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000} }
func (f fakeConn) LocalAddr() net.Addr   { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22} }

// authenticate, hedefin yerinde duran doğrulayıcı: yalnızca BİZİM CA'mızı
// tanır ve zamanı test kontrol eder.
//
// ⚠️ Authenticate kullanıyoruz, CheckCert DEĞİL — ikisi farklı soruları
// cevaplıyor ve karıştırmak klasik bir auth açığıdır:
//
//	IsUserAuthority(cert.SignatureKey)  → "bu CA'ya GÜVENİYOR muyum?"
//	CheckCert(...)                      → "bu sertifika GEÇERLİ mi?"
//
// CheckCert imzayı sertifikanın KENDİ İÇİNDEKİ SignatureKey ile doğrular;
// yani saldırganın kendi CA'sıyla kestiği sertifika da CheckCert'ten geçer.
// Güven kararını yapan tek şey IsUserAuthority ve onu yalnızca Authenticate
// çağırır — hedefteki sshd'nin izlediği yol da budur.
func authenticate(c *CA, now time.Time, principal string, cert *ssh.Certificate) error {
	caKey := c.PublicKey().Marshal()
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return string(auth.Marshal()) == string(caKey)
		},
		Clock: func() time.Time { return now },
	}

	_, err := checker.Authenticate(fakeConn{user: principal}, cert)
	return err
}

func validRequest(t *testing.T) CertRequest {
	return CertRequest{
		PublicKey:  subjectKey(t),
		KeyID:      "yigit@warewave.io",
		Principals: []string{"yigit"},
		ValidFor:   5 * time.Minute,
	}
}

// --- testler ---

// Temel kanıt: kesilen sertifika, hedefin yerindeki doğrulayıcıdan geçiyor.
func TestSignProducesUsableCert(t *testing.T) {
	c := testCA(t)
	req := validRequest(t)

	cert, err := c.Sign(req)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if cert.CertType != ssh.UserCert {
		t.Errorf("CertType = %d, beklenen UserCert (%d)", cert.CertType, ssh.UserCert)
	}
	if cert.KeyId != req.KeyID {
		t.Errorf("KeyId = %q, beklenen %q — audit izi buradan okunur", cert.KeyId, req.KeyID)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "yigit" {
		t.Errorf("ValidPrincipals = %v, beklenen [yigit]", cert.ValidPrincipals)
	}
	if cert.SignatureKey == nil || cert.Signature == nil {
		t.Fatal("sertifika imzalanmamış")
	}

	// CheckCert imzayı da kriptografik olarak doğrular.
	if err := authenticate(c, time.Now(), "yigit", cert); err != nil {
		t.Fatalf("hedef sertifikayı reddetti: %v", err)
	}
}

// ⚠️ S2.2'nin en kritik kuralı.
//
// x/crypto'nun kendi kaynağında (certs.go, CheckCert):
//
//	if len(cert.ValidPrincipals) > 0 {
//	    // By default, certs are valid for all users/hosts.
//
// Yani boş liste "kısıtlama yok" demektir: root dahil HER kullanıcı için
// geçerli bir sertifika basmış olursun. Sign bunu üretmeyi reddetmeli.
func TestSignRejectsEmptyPrincipals(t *testing.T) {
	c := testCA(t)

	for _, principals := range [][]string{nil, {}} {
		req := validRequest(t)
		req.Principals = principals

		if _, err := c.Sign(req); err == nil {
			t.Fatalf("boş principal listesi (%v) kabul edildi — her kullanıcı için geçerli sertifika basıldı", principals)
		}
	}
}

// Saat kayması toleransı: bastion ile hedefin saatleri birkaç saniye
// kayıksa, "şu andan geçerli" bir sertifika hedefte "henüz geçerli değil"
// diye reddedilir. Geriye tarihleme bu toleransı verir.
func TestSignBackdatesForClockSkew(t *testing.T) {
	c := testCA(t)

	before := time.Now()
	cert, err := c.Sign(validRequest(t))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	skew := before.Sub(time.Unix(int64(cert.ValidAfter), 0))
	if skew < 30*time.Second {
		t.Errorf("ValidAfter yalnızca %v geriden başlıyor — saat kayması toleransı yetersiz", skew)
	}
	if skew > 5*time.Minute {
		t.Errorf("ValidAfter %v geriden başlıyor — gereğinden fazla, pencere boşuna açılıyor", skew)
	}

	// Saati 30 sn geri olan bir hedef bile sertifikayı kabul etmeli.
	pastTarget := time.Now().Add(-30 * time.Second)
	if err := authenticate(c, pastTarget, "yigit", cert); err != nil {
		t.Errorf("saati 30 sn geri olan hedef reddetti: %v", err)
	}
}

// Ömür penceresi ValidAfter'dan itibaren ValidFor kadar; sonrasında hedef
// reddetmeli.
func TestSignExpiry(t *testing.T) {
	c := testCA(t)
	req := validRequest(t)
	req.ValidFor = 5 * time.Minute

	cert, err := c.Sign(req)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if got := cert.ValidBefore - cert.ValidAfter; got != uint64(req.ValidFor.Seconds()) {
		t.Errorf("pencere = %d sn, beklenen %d", got, int(req.ValidFor.Seconds()))
	}

	// Pencerenin sonrasına kurulmuş bir saatte reddedilmeli.
	future := time.Unix(int64(cert.ValidBefore), 0).Add(time.Second)
	if err := authenticate(c, future, "yigit", cert); err == nil {
		t.Fatal("süresi dolmuş sertifika kabul edildi")
	}
}

// ⚠️ Geriye tarihleme yüzünden kullanılabilir pencere ValidFor'dan kısadır.
// ValidFor bu paya eşit ya da ondan küçükse sertifika doğduğu anda ölür —
// böyle bir isteği sessizce karşılamak yerine hata ver.
func TestSignRejectsTooShortLifetime(t *testing.T) {
	c := testCA(t)

	for _, d := range []time.Duration{0, 10 * time.Second, 60 * time.Second} {
		req := validRequest(t)
		req.ValidFor = d

		if _, err := c.Sign(req); err == nil {
			t.Errorf("ValidFor=%v kabul edildi — sertifika doğduğu anda süresi dolmuş olurdu", d)
		}
	}
}

// Yanlış principal ile giriş reddedilmeli: sertifika "yigit" için kesildi,
// "root" olarak kullanılamaz.
func TestSignWrongPrincipalRejected(t *testing.T) {
	c := testCA(t)

	cert, err := c.Sign(validRequest(t))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := authenticate(c, time.Now(), "root", cert); err == nil {
		t.Fatal("yigit için kesilen sertifika root olarak kabul edildi")
	}
}

// Başka bir CA'nın sertifikası kabul edilmemeli — imza doğrulaması çalışıyor.
func TestSignForeignCARejected(t *testing.T) {
	mine := testCA(t)
	other := testCA(t)

	cert, err := other.Sign(validRequest(t))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := authenticate(mine, time.Now(), "yigit", cert); err == nil {
		t.Fatal("başka bir CA'nın sertifikası kabul edildi")
	}
}

// Varsayılan deny: pty açık (interaktif oturum bunsuz çalışmaz), port ve
// agent forwarding kapalı. İstenirse açıkça açılır.
func TestSignExtensions(t *testing.T) {
	c := testCA(t)

	t.Run("varsayilanlar", func(t *testing.T) {
		cert, err := c.Sign(validRequest(t))
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}

		if _, ok := cert.Extensions["permit-pty"]; !ok {
			t.Error("permit-pty yok — interaktif oturum açılmaz")
		}
		for _, forbidden := range []string{"permit-port-forwarding", "permit-agent-forwarding", "permit-X11-forwarding"} {
			if _, ok := cert.Extensions[forbidden]; ok {
				t.Errorf("%s istenmediği halde sertifikada var — varsayılan deny ihlali", forbidden)
			}
		}
	})

	t.Run("istenen acikca aciliyor", func(t *testing.T) {
		req := validRequest(t)
		req.Extensions = map[string]string{"permit-agent-forwarding": ""}

		cert, err := c.Sign(req)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if _, ok := cert.Extensions["permit-agent-forwarding"]; !ok {
			t.Error("açıkça istenen extension sertifikaya girmemiş")
		}
		if _, ok := cert.Extensions["permit-port-forwarding"]; ok {
			t.Error("istenmeyen extension da açılmış")
		}
	})
}

// Serial audit'te "hangi sertifika" sorusunun cevabı; tekrar etmemeli.
func TestSignSerialsAreUnique(t *testing.T) {
	c := testCA(t)
	seen := make(map[uint64]bool)

	for i := 0; i < 50; i++ {
		cert, err := c.Sign(validRequest(t))
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if cert.Serial == 0 {
			t.Fatal("Serial sıfır — audit'te sertifikaları ayırt edemezsin")
		}
		if seen[cert.Serial] {
			t.Fatalf("Serial tekrar etti: %d", cert.Serial)
		}
		seen[cert.Serial] = true
	}
}

// Eksik girdiler sessizce geçmemeli.
func TestSignRejectsIncompleteRequests(t *testing.T) {
	c := testCA(t)

	t.Run("public key yok", func(t *testing.T) {
		req := validRequest(t)
		req.PublicKey = nil
		if _, err := c.Sign(req); err == nil {
			t.Fatal("anahtarsız istek kabul edildi")
		}
	})

	t.Run("KeyID bos", func(t *testing.T) {
		req := validRequest(t)
		req.KeyID = ""
		if _, err := c.Sign(req); err == nil {
			t.Fatal("KeyID'siz istek kabul edildi — kime kesildiği bilinmeyen sertifika denetlenemez")
		}
	})
}
