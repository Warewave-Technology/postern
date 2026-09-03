//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/store"
)

/*
 * ⚠️ BÜTÜN PAKET x/crypto İSTEMCİSİYLE KOŞUYOR — GERÇEK `ssh` İLE HİÇ.
 *
 * Bu boşluk kimlik doğrulama algoritmalarını sıkılaştırırken tehlikeli:
 * kabul edilen imza kümesini daraltan bir değişiklik, x/crypto istemcisi
 * ona uyduğu için testlerde YEŞİL kalır ve gerçek OpenSSH istemcisiyle
 * insanları kapı dışında bırakabilir. Sunucu yazarken en kolay
 * kaçırılan şey, karşı tarafın başka bir uygulama olduğu.
 *
 * Test `ssh` yoksa atlanıyor: koşum ortamına bağımlılık eklemeden,
 * varsa gerçek kanıtı üretiyor.
 */
func TestRealOpenSSHClientCanAuthenticate(t *testing.T) {
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("gerçek ssh istemcisi yok")
	}

	caKeyPath, caAuthorizedKey := newTestCA(t)
	tgt := startCertTarget(t, caAuthorizedKey)
	tc := tgt.target()
	tc.Name = "web01"

	addr, hostPub, _, db := testServerWithDB(t, caKeyPath, tc)

	dir := t.TempDir()
	known := filepath.Join(dir, "known_hosts")
	host, port := splitAddr(t, addr)
	if err := os.WriteFile(known, []byte("["+host+"]:"+port+" "+
		string(ssh.MarshalAuthorizedKey(hostPub))), 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(t *testing.T, keyPath string) (string, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, sshBin,
			"-p", port,
			"-i", keyPath,
			"-o", "IdentitiesOnly=yes",
			"-o", "UserKnownHostsFile="+known,
			"-o", "StrictHostKeyChecking=yes",
			"-o", "BatchMode=yes",
			"yigit:web01@"+host,
			"echo", "gercek-istemci-kaniti",
		)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	t.Run("ed25519 anahtar", func(t *testing.T) {
		out, err := run(t, writeED25519(t, db, dir, "ed"))
		if err != nil {
			t.Fatalf("gerçek ssh istemcisi giremedi: %v\nçıktı: %s", err, out)
		}
		if !strings.Contains(out, "gercek-istemci-kaniti") {
			t.Errorf("komut çalışmadı; çıktı: %q", out)
		}
	})

	/*
	 * ⚠️ RSA'NIN AYRICA SINANMASI ŞART.
	 *
	 * Kabul edilen imza listesinden ssh-rsa (SHA-1) çıkarıldı. Aynı RSA
	 * ANAHTARININ rsa-sha2-256/512 ile hâlâ girebildiğini yalnızca
	 * gerçek istemci kanıtlayabilir: x/crypto zaten SHA-2 tercih ediyor
	 * ve o yüzden bu kırılmayı göremez.
	 */
	t.Run("rsa anahtar", func(t *testing.T) {
		out, err := run(t, writeRSA(t, db, dir, "rsa"))
		if err != nil {
			t.Fatalf("RSA anahtarıyla gerçek ssh istemcisi giremedi: %v\n"+
				"çıktı: %s\nSHA-1'i kapatan değişiklik RSA kullanıcılarını "+
				"da kapı dışında bırakmış olabilir", err, out)
		}
		if !strings.Contains(out, "gercek-istemci-kaniti") {
			t.Errorf("komut çalışmadı; çıktı: %q", out)
		}
	})

	// ⚠️ VE SHA-1'E ZORLANAN İSTEMCİ GİREMEMELİ. Yukarıdaki iki test
	// tek başına, listeyi hiç uygulamayan bir sürümde de geçerdi.
	t.Run("ssh-rsa'ya zorlanmis istemci giremiyor", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, sshBin,
			"-p", port, "-i", filepath.Join(dir, "rsa"),
			"-o", "IdentitiesOnly=yes",
			"-o", "UserKnownHostsFile="+known,
			"-o", "StrictHostKeyChecking=yes",
			"-o", "BatchMode=yes",
			"-o", "PubkeyAcceptedAlgorithms=ssh-rsa",
			"yigit:web01@"+host, "echo", "olmamali",
		)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Errorf("SHA-1'e zorlanan istemci kimlik doğruladı; çıktı: %q", out)
		}
	})
}

// splitAddr, "127.0.0.1:2222" → ("127.0.0.1", "2222").
func splitAddr(t *testing.T, addr string) (host, port string) {
	t.Helper()
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		t.Fatalf("adres ayrıştırılamadı: %q", addr)
	}
	return addr[:i], addr[i+1:]
}

// writeED25519, yeni bir ed25519 anahtarı yazar ve hesaba ekler.
func writeED25519(t *testing.T, db *store.Store, dir, name string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return writeKey(t, db, dir, name, priv)
}

// writeRSA, yeni bir RSA anahtarı yazar ve hesaba ekler.
func writeRSA(t *testing.T, db *store.Store, dir, name string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return writeKey(t, db, dir, name, key)
}

func writeKey(t *testing.T, db *store.Store, dir, name string, priv any) string {
	t.Helper()

	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddPublicKey(context.Background(), "yigit",
		signer.PublicKey().Marshal(), name); err != nil {
		t.Fatal(err)
	}
	return path
}
