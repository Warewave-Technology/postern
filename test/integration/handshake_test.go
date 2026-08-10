//go:build integration

package integration

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/config"
	"github.com/warewave/postern/internal/sshd"
)

// testServer, geçici host key + tek kullanıcılı config ile sunucuyu
// 127.0.0.1'de rastgele portta başlatır. Anahtarlar test içinde üretilir,
// diske yalnızca host key yazılır (New dosyadan yüklediği için).
func testServer(t *testing.T) (addr string, hostPub ssh.PublicKey, clientSigner ssh.Signer) {
	t.Helper()

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(hostPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	hostKeyPath := filepath.Join(t.TempDir(), "host_ed25519")
	if err := os.WriteFile(hostKeyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}

	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientSigner, err = ssh.NewSignerFromKey(clientPriv)
	if err != nil {
		t.Fatal(err)
	}
	authorized := string(ssh.MarshalAuthorizedKey(clientSigner.PublicKey()))

	cfg := &config.Config{
		Listen:  config.ListenConfig{Addr: "127.0.0.1:0"},
		HostKey: hostKeyPath,
		Users: []config.UserConfig{
			{Name: "yigit", PublicKeys: []string{authorized}},
		},
	}

	srv, err := sshd.New(cfg, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatalf("sshd.New: %v", err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	go srv.Serve(t.Context(), l)

	return l.Addr().String(), hostSigner.PublicKey(), clientSigner
}

// S1.2 kanıtı: handshake tamamlanıyor ama henüz kanal açılamıyor.
func TestHandshake(t *testing.T) {
	addr, hostPub, clientSigner := testServer(t)

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: "yigit:web01",
		Auth: []ssh.AuthMethod{ssh.PublicKeys(clientSigner)},
		// InsecureIgnoreHostKey YASAK — testte bile (plan Ek B).
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("handshake başarısız: %v", err)
	}
	defer client.Close()

	// S1.2'de session kanalı yok; sunucu her kanalı reddetmeli.
	if _, err := client.NewSession(); err == nil {
		t.Fatal("S1.2'de NewSession hata vermeli (kanal henüz yok)")
	}
}

// Varsayılan deny: config'de kayıtlı olmayan bir anahtar handshake'i geçemez.
func TestHandshakeRejectsUnknownKey(t *testing.T) {
	addr, hostPub, _ := testServer(t)

	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherSigner, err := ssh.NewSignerFromKey(otherPriv)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "yigit:web01",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(otherSigner)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         5 * time.Second,
	})
	if err == nil {
		t.Fatal("bilinmeyen anahtar reddedilmeliydi (varsayılan deny)")
	}
}
