//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/config"
	"github.com/warewave/postern/internal/upstream"
)

// sshTarget, testcontainers ile kaldırılmış gerçek bir OpenSSH sunucusu.
type sshTarget struct {
	host    string
	port    int
	hostKey string // sunucunun gerçek ed25519 host public key satırı
	keyFile string // bağlanmaya yetkili istemci private key dosyası
	user    string
}

// startSSHTarget gerçek bir OpenSSH konteyneri başlatır, ürettiği istemci
// anahtarını yetkilendirir ve konteynerin host key'ini içeriden okur.
// İlk çalıştırmada imaj indirilir — yavaşlık normal.
func startSSHTarget(t *testing.T) sshTarget {
	t.Helper()
	ctx := context.Background()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "client_ed25519")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	const user = "postern"
	cont, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "lscr.io/linuxserver/openssh-server:latest",
			ExposedPorts: []string{"2222/tcp"},
			Env: map[string]string{
				"USER_NAME":  user,
				"PUBLIC_KEY": pubLine,
			},
			WaitingFor: wait.ForListeningPort("2222/tcp").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("openssh konteyneri başlatılamadı (Docker ayakta mı?): %v", err)
	}
	t.Cleanup(func() { _ = cont.Terminate(context.Background()) })

	host, err := cont.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mp, err := cont.MappedPort(ctx, "2222")
	if err != nil {
		t.Fatal(err)
	}

	code, rd, err := cont.Exec(ctx,
		[]string{"cat", "/config/ssh_host_keys/ssh_host_ed25519_key.pub"},
		tcexec.Multiplexed())
	if err != nil || code != 0 {
		t.Fatalf("konteynerden host key okunamadı (exit=%d): %v", code, err)
	}
	raw, err := io.ReadAll(rd)
	if err != nil {
		t.Fatal(err)
	}
	hostKey := strings.TrimSpace(string(raw))
	if hostKey == "" {
		t.Fatal("konteynerden boş host key geldi")
	}

	return sshTarget{host: host, port: int(mp.Num()), hostKey: hostKey, keyFile: keyFile, user: user}
}

func (s sshTarget) targetConfig() config.TargetConfig {
	return config.TargetConfig{
		Name:    "it-target",
		Host:    s.host,
		Port:    s.port,
		User:    s.user,
		KeyFile: s.keyFile,
		HostKey: s.hostKey,
	}
}

// S1.4 kanıtı: gerçek bir sshd'ye bağlan, session aç; yanlış host key'i reddet.
func TestDial(t *testing.T) {
	tgt := startSSHTarget(t)

	t.Run("dogru host key ile baglanir", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		conn, err := upstream.Dial(ctx, tgt.targetConfig())
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}

		sess, err := conn.Client().NewSession()
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		sess.Close()

		// defer'lı Close hatayı sessizce yutar — testte en az bir kez
		// dönüş değeri açıkça kontrol edilmeli.
		if err := conn.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	t.Run("yanlis host key reddedilir", func(t *testing.T) {
		_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		otherSigner, err := ssh.NewSignerFromKey(otherPriv)
		if err != nil {
			t.Fatal(err)
		}

		cfg := tgt.targetConfig()
		cfg.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(otherSigner.PublicKey())))

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		if _, err := upstream.Dial(ctx, cfg); err == nil {
			t.Fatal("yanlış host key kabul edildi — MITM savunması yok")
		} else if !strings.Contains(err.Error(), "mismatch") {
			t.Fatalf("host key mismatch hatası bekleniyordu; gelen: %v", err)
		}
	})
}

// tarpit, TCP bağlantısını kabul eden ama SSH banner'ı hiç göndermeyen bir
// dinleyici döner. Ölü bir sunucu, kasıtlı bir tarpit ya da tüm TCP'yi kabul
// eden bir ara katman gerçek hayatta tam böyle davranır.
func tarpit(t *testing.T) (host string, port int) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var conns []net.Conn

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c) // hiçbir şey yazma: karşı taraf beklesin
			mu.Unlock()
		}
	}()

	t.Cleanup(func() {
		l.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})

	addr := l.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port
}

// Dial'ın TAMAMI ctx'e uymalı — yalnızca TCP fazı değil, SSH el sıkışması da.
//
// ⚠️ ssh.NewClientConn'un kendi zaman aşımı YOKTUR; ClientConfig.Timeout
// sadece ssh.Dial'ın TCP bağlantısına uygulanır (x/crypto client.go:204).
// Yani TCP'yi kabul edip el sıkışmayan bir hedef, önlem alınmazsa Dial'ı
// sonsuza dek tutar — bastion için kaynak tüketimi açığı (plan Ek B:
// "Timeout'lar tanımlı: handshake, idle, toplam").
func TestDialRespectsContext(t *testing.T) {
	host, port := tarpit(t)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "client_ed25519")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.TargetConfig{
		Name:    "tarpit",
		Host:    host,
		Port:    port,
		User:    "postern",
		KeyFile: keyFile,
		HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	start := time.Now()
	_, err = upstream.Dial(ctx, cfg)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("el sıkışmayan hedefe Dial başarılı olamaz")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("Dial ctx'e saygı göstermedi: %v sürdü (beklenen ~1s) — SSH el sıkışması sınırsız", elapsed)
	}
}
