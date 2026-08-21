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

	"github.com/warewave/postern/internal/ca"
	"github.com/warewave/postern/internal/config"
	"github.com/warewave/postern/internal/sshd"
)

// newTestCA, hem bastion'ın kullanacağı anahtar YOLUNU hem hedefin
// güveneceği PUBLIC satırı döner. İkisi aynı CA olmak zorunda: bastion
// sertifikayı bununla keser, hedef bununla doğrular.
func newTestCA(t *testing.T) (keyPath, authorizedKey string) {
	t.Helper()

	keyPath = filepath.Join(t.TempDir(), "ca_ed25519")
	authority, err := ca.Init(keyPath)
	if err != nil {
		t.Fatalf("ca.Init: %v", err)
	}
	return keyPath, authority.AuthorizedKey()
}

// testServer, geçici host key + tek kullanıcılı config ile sunucuyu
// 127.0.0.1'de rastgele portta başlatır. Anahtarlar test içinde üretilir,
// diske yalnızca host key yazılır (New dosyadan yüklediği için).
func testServer(t *testing.T, caKeyPath string, targets ...config.TargetConfig) (addr string, hostPub ssh.PublicKey, clientSigner ssh.Signer) {
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

	// Kullanıcıya verilen hedeflerin hepsini kapsayan tek bir rol: policy
	// artık hedef yetkisini rollerden okuyor.
	var targetNames []string
	for _, tgt := range targets {
		targetNames = append(targetNames, tgt.Name)
	}

	cfg := &config.Config{
		Listen:    config.ListenConfig{Addr: "127.0.0.1:0"},
		HostKey:   hostKeyPath,
		CA:        config.CAConfig{KeyFile: caKeyPath},
		Recording: config.RecordingConfig{Dir: filepath.Join(t.TempDir(), "recordings")},
		Targets:   targets,
		Roles:     []config.RoleConfig{{Name: "ops", Targets: targetNames}},
		Users: []config.UserConfig{
			// OSUser "postern": hedef konteynerdeki hesap. Sertifikanın
			// principal'ı ve SSH kullanıcı adı bu olacak.
			{Name: "yigit", OSUser: "postern", Roles: []string{"ops"}, PublicKeys: []string{authorized}},
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
	caKeyPath, _ := newTestCA(t)
	addr, hostPub, clientSigner := testServer(t, caKeyPath)

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
	caKeyPath, _ := newTestCA(t)
	addr, hostPub, _ := testServer(t, caKeyPath)

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
