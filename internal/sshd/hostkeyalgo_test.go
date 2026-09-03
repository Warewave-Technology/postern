package sshd

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// writeRSAHostKey, RSA bir host key dosyası bırakır.
func writeRSAHostKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "host_rsa")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

/*
 * ⚠️ BASTION'IN KENDİ HOST ANAHTARI DA SHA-1 İMZALAMAMALI.
 *
 * ssh.ServerConfig'de host key algoritma listesi yok; x/crypto RSA için
 * ssh-rsa'yı (SHA-1) da içeren varsayılanı sunuyordu. Ölçülen sonuç:
 * yalnızca ssh-rsa sunan bir istemciyle el sıkışma TAMAMLANIYOR, yani
 * sunucu değişim özetini SHA-1 ile imzalıyor. Gelen ve giden host key
 * doğrulamaları SHA-1'i çıkarmışken bu yol açıktı.
 *
 * Test, yalnızca ssh-rsa sunan bir istemcinin "no common algorithm for
 * host key" ile düştüğünü ölçüyor.
 */
func TestServerHostKeyRefusesSHA1(t *testing.T) {
	cfg := testConfigNoDB(t)
	cfg.HostKey = writeRSAHostKey(t)

	srv, err := New(cfg, nil, testLogger())
	if err != nil {
		t.Fatalf("RSA host key'li sunucu kurulamadı: %v", err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go srv.Serve(t.Context(), l)

	dial := func(algos []string) error {
		c, derr := ssh.Dial("tcp", l.Addr().String(), &ssh.ClientConfig{
			User:              "yigit:web01",
			Auth:              []ssh.AuthMethod{},
			HostKeyCallback:   ssh.InsecureIgnoreHostKey(), //nolint:gosec // test: host key doğrulaması burada konu değil
			HostKeyAlgorithms: algos,
			Timeout:           10 * time.Second,
		})
		if c != nil {
			c.Close()
		}
		return derr
	}

	// Yalnızca ssh-rsa (SHA-1): ortak host key algoritması KALMAMALI.
	err = dial([]string{ssh.KeyAlgoRSA})
	if err == nil {
		t.Fatal("yalnızca ssh-rsa sunan istemciyle el sıkışma tamamlandı — " +
			"sunucu host key'i SHA-1 ile imzalıyor")
	}
	if !strings.Contains(err.Error(), "no common algorithm for host key") {
		t.Errorf("beklenen 'no common algorithm for host key', gelen: %v", err)
	}

	// SHA-2 sunan istemci: el sıkışma host key aşamasını GEÇMELİ.
	// (Sonrasında auth yok, o yüzden 'no supported methods' ile düşer —
	// host key değil, kimlik doğrulama aşaması.)
	err = dial([]string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256})
	if err != nil && strings.Contains(err.Error(), "no common algorithm for host key") {
		t.Errorf("SHA-2 sunan istemci host key aşamasında düştü: %v — "+
			"RSA host key'li her bastion erişilemez olurdu", err)
	}
}
