//go:build integration

package integration

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Warewave-Technology/postern/internal/ca"
	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/upstream"
)

// certTarget, SERTİFİKA kabul eden bir hedef: authorized_keys'inde tek bir
// statik anahtar yok, yalnızca TrustedUserCAKeys satırı var.
type certTarget struct {
	host    string
	port    int
	hostKey string
	cont    testcontainers.Container
}

// startCertTarget, verilen CA'ya güvenen bir OpenSSH konteyneri kaldırır.
//
// Hedef tarafının yapılandırması testdata/certtarget/Dockerfile'da ve
// çalıştırılabilir dokümantasyon niteliğinde: gerçek bir hedefte de tam
// olarak o iki satır gerekiyor.
func startCertTarget(t *testing.T, caAuthorizedKey string) certTarget {
	t.Helper()
	ctx := context.Background()

	cont, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context:   filepath.Join("testdata", "certtarget"),
				KeepImage: true, // her testte yeniden derlemesin
			},
			ExposedPorts: []string{"22/tcp"},
			Files: []testcontainers.ContainerFile{{
				// CA'nın public anahtarı: hedefin güvendiği TEK şey.
				Reader:            strings.NewReader(caAuthorizedKey),
				ContainerFilePath: "/etc/ssh/postern_ca.pub",
				FileMode:          0o644,
			}},
			WaitingFor: wait.ForListeningPort("22/tcp").WithStartupTimeout(3 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("sertifika hedefi başlatılamadı (Docker ayakta mı?): %v", err)
	}
	t.Cleanup(func() { _ = cont.Terminate(context.Background()) })

	// Test düşerse hedefin sshd log'unu bas: LogLevel VERBOSE sayesinde
	// "neden reddettim" sorusunun cevabı orada yazıyor. Sertifika
	// sorunlarını tahminle kovalamak yerine hedefe sormak çok daha hızlı.
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		rc, err := cont.Logs(context.Background())
		if err != nil {
			return
		}
		defer rc.Close()
		out, _ := io.ReadAll(rc)
		t.Logf("--- hedef sshd log ---\n%s", out)
	})

	host, err := cont.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mp, err := cont.MappedPort(ctx, "22")
	if err != nil {
		t.Fatal(err)
	}

	code, rd, err := cont.Exec(ctx, []string{"cat", "/etc/ssh/ssh_host_ed25519_key.pub"}, tcexec.Multiplexed())
	if err != nil || code != 0 {
		t.Fatalf("host key okunamadı (exit=%d): %v", code, err)
	}
	raw, err := io.ReadAll(rd)
	if err != nil {
		t.Fatal(err)
	}

	return certTarget{
		host:    host,
		port:    int(mp.Num()),
		hostKey: strings.TrimSpace(string(raw)),
		cont:    cont,
	}
}

// target, upstream'in beklediği domain tipi.
func (c certTarget) target() model.Target {
	return model.Target{
		Name:    "cert-target",
		Host:    c.host,
		Port:    c.port,
		HostKey: c.hostKey,
		// ⚠️ Hedefteki HESAP burada yok: sertifika modelinde onu policy verir.
	}
}

func testAuthority(t *testing.T) *ca.CA {
	t.Helper()

	authority, err := ca.Init(filepath.Join(t.TempDir(), "ca_ed25519"))
	if err != nil {
		t.Fatalf("ca.Init: %v", err)
	}
	return authority
}

// runOnTarget, bağlanılan hedefte tek bir komut çalıştırır.
func runOnTarget(t *testing.T, conn *upstream.Conn, cmd string) string {
	t.Helper()

	sess, err := conn.Client().NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	out, err := sess.Output(cmd)
	if err != nil {
		t.Fatalf("%q: %v", cmd, err)
	}
	return strings.TrimSpace(string(out))
}

// S2.3'ün "Bitti" kanıtı — ve planın driver 1 iddiasının kanıtı:
// kullanıcı hedefe KENDİ ADIYLA düşüyor ve hedefte hiçbir statik anahtar yok.
func TestDialWithCert(t *testing.T) {
	authority := testAuthority(t)
	tgt := startCertTarget(t, authority.AuthorizedKey())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := upstream.DialWithCert(ctx, tgt.target(), upstream.Identity{
		PosternUser: "yigit@warewave.io",
		OSUser:      "postern",
	}, authority)
	if err != nil {
		t.Fatalf("DialWithCert: %v", err)
	}
	defer conn.Close()

	if got := runOnTarget(t, conn, "id -un"); got != "postern" {
		t.Errorf("hedefteki kullanıcı = %q, beklenen %q", got, "postern")
	}

	// ⚠️ Driver 1'in özü: hedefte hiçbir statik anahtar YOK. Erişimi veren
	// tek şey, bu oturum için kesilmiş kısa ömürlü sertifika.
	if got := runOnTarget(t, conn, "test -f /home/postern/.ssh/authorized_keys && echo VAR || echo YOK"); got != "YOK" {
		t.Errorf("hedefte authorized_keys bulundu (%q) — sertifika modelinin amacı statik anahtarı ORTADAN KALDIRMAK", got)
	}
}

// Başka bir CA'nın kestiği sertifika reddedilmeli: TrustedUserCAKeys yalnızca
// bizim CA'mızı listeliyor.
func TestDialWithCertUntrustedCA(t *testing.T) {
	trusted := testAuthority(t)
	rogue := testAuthority(t)

	tgt := startCertTarget(t, trusted.AuthorizedKey())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := upstream.DialWithCert(ctx, tgt.target(), upstream.Identity{
		PosternUser: "saldirgan@example.com",
		OSUser:      "postern",
	}, rogue)
	if err == nil {
		t.Fatal("güvenilmeyen CA'nın sertifikası kabul edildi")
	}

	/*
	 * ⚠️ SINIFLANDIRMA GERÇEK sshd'YE KARŞI SABİTLENİYOR.
	 *
	 * "Hedef bizi reddetti" ile "hedefe ulaşamadım" operatöre bambaşka
	 * şeyler söylüyor ve web terminali bu ayrımı kullanıcıya gösteren
	 * cümleyi buradan seçiyor (httpapi/terminal.go). Ayrım
	 * kütüphanenin hata METNİNE bakılarak yapılsaydı, x/crypto o metni
	 * değiştirdiği gün sessizce yanlış sınıfa düşerdik — ve kullanıcı
	 * "hedefe ulaşılamıyor" diye yanlış yere bakardı. Burada gerçek
	 * bir OpenSSH sunucusu gerçekten reddediyor.
	 */
	if !errors.Is(err, upstream.ErrRefused) {
		t.Errorf("hata ErrRefused değil: %v — terminal ekranı yanlış "+
			"sebebi gösterir", err)
	}
	if errors.Is(err, upstream.ErrUnreachable) {
		t.Error("reddedilen sertifika 'erişilemez' diye sınıflandı")
	}
}

/*
 * ⚠️ HOST ANAHTARI UYUŞMAZLIĞI, REDDEN AYRI BİR OLAY.
 *
 * Biri "hedef bize güvenmiyor" (yapılandırma eksik), diğeri "hedefin
 * kimliği sabitlediğimizden başka" (yapılandırma değişmiş ya da araya
 * giren var). İkisini aynı mesajla göstermek, ikincisini görmezden
 * gelinecek bir kuruluma çevirirdi.
 */
func TestDialClassifiesHostKeyMismatch(t *testing.T) {
	authority := testAuthority(t)
	tgt := startCertTarget(t, authority.AuthorizedKey())

	// Hedefi DOĞRU adresle ama YANLIŞ host anahtarıyla kaydet.
	target := tgt.target()
	other := testAuthority(t)
	target.HostKey = other.AuthorizedKey()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := upstream.DialWithCert(ctx, target, upstream.Identity{
		PosternUser: "yigit", OSUser: "postern",
	}, authority)
	if err == nil {
		t.Fatal("yanlış host anahtarıyla bağlantı kuruldu")
	}
	if !errors.Is(err, upstream.ErrHostKeyMismatch) {
		t.Errorf("hata ErrHostKeyMismatch değil: %v", err)
	}
	if errors.Is(err, upstream.ErrRefused) {
		t.Error("anahtar uyuşmazlığı 'sertifika reddi' diye sınıflandı — " +
			"operatör yanlış yeri düzeltmeye çalışır")
	}
}

/*
 * Erişilemeyen hedef: kapalı bir porta bağlanmak ErrUnreachable
 * vermeli. Yanlış sınıflanırsa ekran "hedef sertifikamızı reddetti"
 * der ve operatör var olmayan bir CA sorununu kovalar.
 */
func TestDialClassifiesUnreachable(t *testing.T) {
	authority := testAuthority(t)
	tgt := startCertTarget(t, authority.AuthorizedKey())

	target := tgt.target()
	// Kapalı olduğu bilinen bir port.
	target.Port = 1

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, err := upstream.DialWithCert(ctx, target, upstream.Identity{
		PosternUser: "yigit", OSUser: "postern",
	}, authority)
	if err == nil {
		t.Fatal("kapalı porta bağlanıldı")
	}
	if !errors.Is(err, upstream.ErrUnreachable) {
		t.Errorf("hata ErrUnreachable değil: %v", err)
	}
}

// Principal politikası hedefte de uygulanıyor: AuthorizedPrincipalsFile
// yalnızca "postern" hesabı için tanımlı. Başka bir hesap istenirse hedef
// reddeder — bastion'daki karar (S2.4) tek savunma hattı değil.
func TestDialWithCertUnknownPrincipal(t *testing.T) {
	authority := testAuthority(t)
	tgt := startCertTarget(t, authority.AuthorizedKey())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := upstream.DialWithCert(ctx, tgt.target(), upstream.Identity{
		PosternUser: "yigit@warewave.io",
		OSUser:      "nobody", // /etc/ssh/auth_principals/nobody yok
	}, authority); err == nil {
		t.Fatal("principal tanımlı olmayan hesaba giriş kabul edildi")
	}
}

// Host key pinleme sertifika modelinde de yürürlükte: sertifika BİZİM
// hedefe kimliğimizi kanıtlar, hedefin bize kimliğini kanıtlaması hâlâ
// host key'in işidir (plan Ek B: InsecureIgnoreHostKey hiçbir yerde yok).
func TestDialWithCertStillPinsHostKey(t *testing.T) {
	authority := testAuthority(t)
	tgt := startCertTarget(t, authority.AuthorizedKey())

	cfg := tgt.target()
	cfg.HostKey = authority.AuthorizedKey() // hedefin değil, CA'nın anahtarı

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := upstream.DialWithCert(ctx, cfg, upstream.Identity{
		PosternUser: "yigit@warewave.io",
		OSUser:      "postern",
	}, authority); err == nil {
		t.Fatal("yanlış host key kabul edildi — MITM savunması sertifika modelinde de gerekli")
	}
}
