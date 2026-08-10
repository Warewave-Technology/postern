package upstream

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Sözleşme (S1.4 revizyonu): hostKeyCallback yalnızca callback değil,
// pinlenen anahtarın ALGORİTMA listesini de döner. Sebep: çok tipli host
// key'i olan bir sunucu (rsa+ecdsa+ed25519), istemcinin varsayılan tercih
// sırasına göre FARKLI bir anahtar sunabilir ve pin sahte "mismatch" ile
// ölür. Pinlediğin anahtarın tipi müzakereye de yazılmalı.
func TestHostKeyCallback(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	t.Run("gecerli satir callback ve algo uretir", func(t *testing.T) {
		cb, algos, err := hostKeyCallback(line)
		if err != nil {
			t.Fatalf("beklenmeyen hata: %v", err)
		}
		if cb == nil {
			t.Fatal("callback nil olmamalı")
		}
		if len(algos) != 1 || algos[0] != "ssh-ed25519" {
			t.Fatalf("algos = %v, beklenen [ssh-ed25519]", algos)
		}
	})

	t.Run("bozuk satir hata", func(t *testing.T) {
		if _, _, err := hostKeyCallback("bu bir host key degil"); err == nil {
			t.Fatal("hata bekleniyordu")
		}
	})

	t.Run("bos satir hata", func(t *testing.T) {
		if _, _, err := hostKeyCallback(""); err == nil {
			t.Fatal("hata bekleniyordu")
		}
	})
}
