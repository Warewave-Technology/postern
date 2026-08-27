package sshd

// S1.2 birim test merdiveni — her adımı tek başına koşabilirsin:
//
//	go test ./internal/sshd/ -run TestNew -v                       // adım 1
//	go test ./internal/sshd/ -run TestServerConfigAndCallback -v   // adım 2-3
//	go test ./internal/sshd/ -run TestServeStopsOnContextCancel -v // adım 4
//	go test ./internal/sshd/                                       // hepsi
//
// Uçtan uca kanıt ayrıca test/integration/handshake_test.go'da
// (make test-integration).

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/ca"
	"github.com/warewave/postern/internal/config"
	"github.com/warewave/postern/internal/store"
	"github.com/warewave/postern/internal/testdb"
)

// --- yardımcılar ---

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// writeHostKey geçici bir ed25519 host key dosyası üretir (New dosyadan
// yüklediği için diske yazılır) ve public yarısını döner.
func writeHostKey(t *testing.T) (path string, pub ssh.PublicKey) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "host_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return path, signer.PublicKey()
}

// clientKey yeni bir istemci anahtarı üretir; authorized_keys satırını ve
// public key'i döner.
func clientKey(t *testing.T) (authorized string, pub ssh.PublicKey) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(signer.PublicKey())), signer.PublicKey()
}

func testConfig(t *testing.T) *config.Config {
	t.Helper()

	hostKeyPath, _ := writeHostKey(t)
	return &config.Config{
		Listen:    config.ListenConfig{Addr: "127.0.0.1:0"},
		HostKey:   hostKeyPath,
		CA:        config.CAConfig{KeyFile: testCAKey(t)},
		Database:  config.DatabaseConfig{DSN: testdb.DSN(t)},
		Recording: config.RecordingConfig{Dir: filepath.Join(t.TempDir(), "recordings")},
	}
}

// testStore, "yigit" kullanıcısını verilen anahtarlarla tanıyan gerçek bir
// store kurar — auth.go anahtarları oradan okuyor.
//
// Kimlik verisi artık config'te YAŞAMADIĞI için doğrudan store'a yazılır;
// üretimde bu işi yetkili CLI komutları yapar (S3 sözleşmesi).
func testStore(t *testing.T, cfg *config.Config, authorizedKeys ...string) *store.Store {
	t.Helper()
	ctx := context.Background()

	db, err := store.Open(ctx, cfg.Database.DSN)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	if _, err := db.CreateUser(ctx, "yigit", "", "yigit"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	for _, line := range authorizedKeys {
		pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			t.Fatalf("ParseAuthorizedKey: %v", err)
		}
		if err := db.AddPublicKey(ctx, "yigit", pub.Marshal(), comment); err != nil {
			t.Fatalf("AddPublicKey: %v", err)
		}
	}
	return db
}

// testCAKey, gerçek bir CA anahtarı üretir: New artık ca.Load çağırdığı için
// sahte bir yol yetmiyor — sertifika modelinde CA olmadan sunucu açılmamalı.
func testCAKey(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "ca_ed25519")
	if _, err := ca.Init(path); err != nil {
		t.Fatalf("ca.Init: %v", err)
	}
	return path
}

// fakeConnMeta, PublicKeyCallback'i handshake olmadan çağırabilmek için
// asgari ssh.ConnMetadata implementasyonu.
type fakeConnMeta struct{ user string }

func (f fakeConnMeta) User() string          { return f.user }
func (f fakeConnMeta) SessionID() []byte     { return []byte("test-session") }
func (f fakeConnMeta) ClientVersion() []byte { return []byte("SSH-2.0-test") }
func (f fakeConnMeta) ServerVersion() []byte { return []byte("SSH-2.0-postern") }
func (f fakeConnMeta) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
}
func (f fakeConnMeta) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2222}
}

// --- adım 1: New — host key yükleme ---

func TestNew(t *testing.T) {
	t.Run("gecerli anahtar yukleniyor", func(t *testing.T) {
		srv, err := New(testConfig(t), nil, testLogger())
		if err != nil {
			t.Fatalf("beklenmeyen hata: %v", err)
		}
		if srv == nil {
			t.Fatal("hata yokken srv nil olmamalı")
		}
	})

	t.Run("olmayan host key dosyasi", func(t *testing.T) {
		cfg := testConfig(t)
		cfg.HostKey = filepath.Join(t.TempDir(), "yok_boyle_dosya")

		_, err := New(cfg, nil, testLogger())
		if err == nil {
			t.Fatal("hata bekleniyordu, nil geldi")
		}
		if !strings.Contains(err.Error(), "yok_boyle_dosya") {
			t.Fatalf("hata dosya yolunu söylemeli; gelen: %v", err)
		}
	})

	t.Run("bozuk anahtar dosyasi", func(t *testing.T) {
		cfg := testConfig(t)
		bad := filepath.Join(t.TempDir(), "bozuk_anahtar")
		if err := os.WriteFile(bad, []byte("bu bir ssh anahtari degil"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg.HostKey = bad

		if _, err := New(cfg, nil, testLogger()); err == nil {
			t.Fatal("bozuk anahtar dosyası hata vermeli")
		}
	})
}

// --- adım 2-3: auth.go (SENİN dosyan) + serverConfig ---
//
// Callback'e bilerek serverConfig().PublicKeyCallback üzerinden ulaşıyoruz:
// bu test dosyası auth.go henüz yokken de derlenir; sen serverConfig'i
// yazıp callback'i bağlayınca yeşile döner.

func TestServerConfigAndCallback(t *testing.T) {
	authorized, clientPub := clientKey(t)
	cfg := testConfig(t)
	srv, err := New(cfg, testStore(t, cfg, authorized), testLogger())
	if err != nil {
		t.Fatalf("New: %v (önce TestNew'i yeşile çevir)", err)
	}

	scfg, err := srv.serverConfig()
	if err != nil {
		t.Fatalf("serverConfig: %v", err)
	}
	if scfg.PublicKeyCallback == nil {
		t.Fatal("PublicKeyCallback bağlanmamış")
	}

	t.Run("kayitli anahtar kabul", func(t *testing.T) {
		perms, err := scfg.PublicKeyCallback(fakeConnMeta{user: "yigit:web01"}, clientPub)
		if err != nil {
			t.Fatalf("kayıtlı anahtar reddedildi: %v", err)
		}
		if perms == nil || perms.Extensions["postern-user"] != "yigit" {
			t.Fatalf(`Extensions["postern-user"] = "yigit" bekleniyordu; perms: %+v`, perms)
		}
	})

	t.Run("bilinmeyen anahtar red", func(t *testing.T) {
		_, otherPub := clientKey(t) // config'e girmemiş taze anahtar
		if _, err := scfg.PublicKeyCallback(fakeConnMeta{user: "yigit:web01"}, otherPub); err == nil {
			t.Fatal("bilinmeyen anahtar kabul edildi — varsayılan deny ihlali")
		}
	})
}

// --- adım 4: Serve — kabul döngüsü ve ctx iptali ---
//
// Sözleşme: ctx→l.Close() gözcüsü Serve'ün İÇİNDE yaşar; iptalde Serve
// nil ile döner. SSH konuşmayan ham TCP bağlantısı da paniğe yol açmamalı.

func TestServeStopsOnContextCancel(t *testing.T) {
	authorized, _ := clientKey(t)
	cfg := testConfig(t)
	srv, err := New(cfg, testStore(t, cfg, authorized), testLogger())
	if err != nil {
		t.Fatalf("New: %v (önce TestNew'i yeşile çevir)", err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, l) }()

	// Sunucu ayakta: bağlantı kurulabiliyor. SSH konuşmadan kapatıyoruz;
	// handleConn'daki handshake hatası log'a gitmeli, paniğe değil.
	conn, err := net.DialTimeout("tcp", l.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("sunucuya bağlanılamadı: %v", err)
	}
	conn.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("iptal sonrası Serve nil dönmeli; gelen: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve, ctx iptaline rağmen 2 sn içinde dönmedi")
	}
}
