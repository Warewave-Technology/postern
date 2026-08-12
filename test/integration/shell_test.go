//go:build integration

package integration

import (
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// errorAs, errors.As'ı testte okunur kılan ince sarmalayıcı.
func errorAs(err error, target any) bool { return errors.As(err, target) }

// S1.5'in "Bitti" kanıtı: gerçek bir OpenSSH istemcisi → postern → gerçek bir
// OpenSSH sunucusu. Zincirin tamamı: handshake, auth, kanal kabulü, hedefe
// bağlanma, request relay, veri kopyalama, exit-status.
//
// proxyClient bir istemci kurar; hedef konteyner "web01" adıyla config'e girer.
func proxyClient(t *testing.T) *ssh.Client {
	t.Helper()

	tgt := startSSHTarget(t)
	tc := tgt.targetConfig()
	tc.Name = "web01"

	addr, hostPub, signer := testServer(t, tc)

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "yigit:web01",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         15 * time.Second,
	})
	if err != nil {
		t.Fatalf("proxy'ye bağlanılamadı: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	return client
}

// 1) Komut çalışıyor ve çıktısı doğru geçiyor.
func TestProxyExecOutput(t *testing.T) {
	client := proxyClient(t)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	out, err := sess.Output("echo hello")
	if err != nil {
		t.Fatalf("Output: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "hello" {
		t.Fatalf("çıktı = %q, beklenen %q", got, "hello")
	}
}

// 2) Çıkış kodu doğru dönüyor — exit-status relay'inin gerçek kanıtı.
// Bu test düşerse ve "0" görüyorsan: exit-status yolda kayboluyor (Ek C.3).
func TestProxyExitStatus(t *testing.T) {
	client := proxyClient(t)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	err = sess.Run("exit 3")
	if err == nil {
		t.Fatal("exit 3 hata döndürmeliydi (ExitError)")
	}

	var exitErr *ssh.ExitError
	if !errorAs(err, &exitErr) {
		t.Fatalf("ExitError bekleniyordu; gelen: %T %v", err, err)
	}
	if exitErr.ExitStatus() != 3 {
		t.Fatalf("çıkış kodu = %d, beklenen 3", exitErr.ExitStatus())
	}
}

// 3) stderr ayrı akıştan geliyor (Ek C.5).
func TestProxyStderrSeparate(t *testing.T) {
	client := proxyClient(t)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	var stderr strings.Builder
	sess.Stderr = &stderr

	out, err := sess.Output("echo ciktilar; echo hatalar >&2")
	if err != nil {
		t.Fatalf("Output: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "ciktilar" {
		t.Fatalf("stdout = %q, beklenen %q", got, "ciktilar")
	}
	if got := strings.TrimSpace(stderr.String()); got != "hatalar" {
		t.Fatalf("stderr = %q, beklenen %q", got, "hatalar")
	}
}

// 4) PTY isteği hedefe ulaşıyor ve istenen boyutla açılıyor.
// stty, busybox'ta var; "satır sütun" basar (ör. "30 120").
func TestProxyPtySize(t *testing.T) {
	client := proxyClient(t)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	modes := ssh.TerminalModes{ssh.ECHO: 0}
	if err := sess.RequestPty("xterm-256color", 30, 120, modes); err != nil {
		t.Fatalf("RequestPty: %v", err)
	}

	out, err := sess.Output("stty size")
	if err != nil {
		t.Fatalf("Output: %v", err)
	}
	got := strings.TrimSpace(string(out))
	if !strings.Contains(got, "120") || !strings.Contains(got, "30") {
		t.Fatalf("stty size = %q, 30 satır × 120 sütun bekleniyordu", got)
	}
}

// 5) Bilinmeyen hedef reddedilmeli — varsayılan deny.
func TestProxyUnknownTargetRejected(t *testing.T) {
	tgt := startSSHTarget(t)
	tc := tgt.targetConfig()
	tc.Name = "web01"

	addr, hostPub, signer := testServer(t, tc)

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "yigit:boyle-bir-hedef-yok",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         15 * time.Second,
	})
	if err != nil {
		t.Fatalf("handshake başarılı olmalıydı (hedef kontrolü kanal aşamasında): %v", err)
	}
	defer client.Close()

	if _, err := client.NewSession(); err == nil {
		t.Fatal("bilinmeyen hedef için kanal açıldı — reddedilmeliydi")
	}
}
