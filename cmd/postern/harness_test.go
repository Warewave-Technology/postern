package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/store"
	"github.com/warewave/postern/internal/testdb"
)

/*
 * cmd/postern koşum düzeneği.
 *
 * ⚠️ NEDEN VAR: bu paket 3.500 satır ve TEK bir testi vardı — o da saf
 * bir fonksiyonu ölçüyordu. Burada duran şey, kimsenin panele
 * giremediği gün koşulacak olan: `admin bootstrap`, `admin issue`,
 * `settings set --key auth.source`. Yani ürünün "her şey bozulduğunda
 * içeri girilir" iddiasının tamamı test edilmemiş bir paketteydi.
 *
 * ⚠️ KOMUTLAR GERÇEK BİR VERİTABANINA KARŞI KOŞUYOR. Store'u taklit
 * etmek, tam da ölçmek istediğimiz şeyi — komutun store ile
 * sözleşmesini — ölçmemek olurdu.
 */

// testEnv, geçici bir config + boş bir veritabanı.
type testEnv struct {
	config string
	db     *store.Store
	dir    string
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()

	// Config'in Validate'i host anahtarının VAR OLMASINI istiyor.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	hostKey := filepath.Join(dir, "host")
	if err := os.WriteFile(hostKey, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	caKey := filepath.Join(dir, "ca")
	if err := os.WriteFile(caKey, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}

	dsn := testdb.DSN(t)
	cfgPath := filepath.Join(dir, "postern.yaml")
	cfg := "listen:\n  addr: \"127.0.0.1:0\"\n" +
		"host_key: " + hostKey + "\n" +
		"ca:\n  key_file: " + caKey + "\n" +
		"database:\n  dsn: \"" + dsn + "\"\n" +
		"recording:\n  dir: " + filepath.Join(dir, "rec") + "\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	db, err := store.Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}

	return &testEnv{config: cfgPath, db: db, dir: dir}
}

// run, bir komutu çalıştırır ve çıktısını döner.
func (e *testEnv) run(t *testing.T, cmd *cobra.Command, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(append(args, "--config", e.config))
	err := cmd.Execute()
	return out.String(), err
}
