//go:build integration

package integration

import (
	"context"
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

	"github.com/Warewave-Technology/postern/internal/ca"
	"github.com/Warewave-Technology/postern/internal/config"
	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/sshd"
	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/testdb"
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
func testServer(t *testing.T, caKeyPath string, targets ...model.Target) (addr string, hostPub ssh.PublicKey, clientSigner ssh.Signer) {
	t.Helper()

	addr, hostPub, clientSigner, _ = testServerWithDB(t, caKeyPath, targets...)
	return addr, hostPub, clientSigner
}

// testServerWithDB, testServer'ın store'u da dışarı veren hâli: denetim
// kaydını doğrulayan ya da veritabanını bilerek deviren testler için.
func testServerWithDB(t *testing.T, caKeyPath string, targets ...model.Target) (addr string, hostPub ssh.PublicKey, clientSigner ssh.Signer, db *store.Store) {
	t.Helper()

	srv, hostPub, clientSigner, db := newBastion(t, caKeyPath, targets...)
	addr = startBastion(t, srv)
	return addr, hostPub, clientSigner, db
}

// newBastion, sunucuyu KURAR ama dinlemeye başlamaz — OOB testleri gibi
// dinlemeden önce EnableOOB çağırması gerekenler için ayrık.
func newBastion(t *testing.T, caKeyPath string, targets ...model.Target) (srv *sshd.Server, hostPub ssh.PublicKey, clientSigner ssh.Signer, db *store.Store) {
	t.Helper()
	return newBastionOpts(t, caKeyPath, false, targets...)
}

// tuneConfig, bir sonraki newBastionOpts çağrısının config'ini değiştirir.
// Testler t.Cleanup ile sıfırlar; paralel koşmadıkları için tek değişken
// yeterli.
var tuneConfig func(*config.Config)

/*
 * lastDSN, son kurulan düzeneğin veritabanı adresi.
 *
 * ⚠️ Var olma sebebi: kapanış testleri SÜREÇTEKİ SIRAYI modellemek
 * zorunda — Serve döner, main veritabanını kapatır, süreç ölür. O
 * pencerede yarım kalan bir Session.Close'un bedeli ancak TAZE bir
 * bağlantıyla okunduğunda görünüyor; aynı bağlantıdan okumak, okuma
 * gecikmesi boyunca Close'un yetişmesine izin veriyor ve arıza
 * kaçıyor (ölçüldü: 6 koşuda 0 kez göründü).
 *
 * tuneConfig ile aynı desen ve aynı sebeple güvenli: bu testler
 * paralel koşmuyor.
 */
var lastDSN string

func captureDSN(dsn string) string {
	lastDSN = dsn
	return dsn
}

// withConfig, verilen ayarla bir sunucu kurar ve dinlemeye başlar.
func withConfig(t *testing.T, caKeyPath string, tune func(*config.Config), targets ...model.Target) (addr string, hostPub ssh.PublicKey, clientSigner ssh.Signer) {
	t.Helper()

	tuneConfig = tune
	t.Cleanup(func() { tuneConfig = nil })

	srv, hostPub, clientSigner, _ := newBastionOpts(t, caKeyPath, false, targets...)
	return startBastion(t, srv), hostPub, clientSigner
}

// newBastionOpts, skipSeed true ise kullanıcı/rol tohumlamaz — yalnızca
// hedefleri yazar. JIT sağlama testleri kullanıcının YOKLUĞUNDAN başlar.
func newBastionOpts(t *testing.T, caKeyPath string, skipSeed bool, targets ...model.Target) (srv *sshd.Server, hostPub ssh.PublicKey, clientSigner ssh.Signer, db *store.Store) {
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
		Listen:    config.ListenConfig{Addr: "127.0.0.1:0"},
		HostKey:   hostKeyPath,
		CA:        config.CAConfig{KeyFile: caKeyPath},
		Database:  config.DatabaseConfig{DSN: captureDSN(testdb.DSN(t))},
		Recording: config.RecordingConfig{Dir: filepath.Join(t.TempDir(), "recordings")},
	}

	// Kimlik verisi config'te YAŞAMAZ (S3 sözleşmesi): kullanıcı, rol ve
	// hedefler doğrudan store'a yazılır — üretimde bu işi yetkili CLI yapar.
	// OSUser "postern": hedef konteynerdeki hesap; sertifikanın principal'ı
	// ve SSH kullanıcı adı bu olacak.
	if skipSeed {
		db = seedTargetsOnly(t, cfg.Database.DSN, targets)
	} else {
		db = seedStore(t, cfg.Database.DSN, targets, authorized)
	}

	if tuneConfig != nil {
		tuneConfig(cfg)
	}

	srv, err = sshd.New(cfg, db, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatalf("sshd.New: %v", err)
	}

	return srv, hostSigner.PublicKey(), clientSigner, db
}

// startBastion, kurulmuş sunucuyu rastgele portta dinletir.
func startBastion(t *testing.T, srv *sshd.Server) (addr string) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	go srv.Serve(t.Context(), l)

	return l.Addr().String()
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

// seedStore, "yigit" kullanıcısını (os_user: postern) verilen hedeflerin
// hepsini kapsayan "ops" rolüyle tanıyan bir store kurar. FK sırası:
// hedefler, rol, kullanıcı, bağlar.
func seedStore(t *testing.T, dbDSN string, targets []model.Target, authorizedKey string) *store.Store {
	t.Helper()
	ctx := context.Background()

	db, err := store.Open(ctx, dbDSN)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	if _, err := db.CreateRole(ctx, "ops"); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	for _, tgt := range targets {
		if _, err := db.CreateTarget(ctx, tgt); err != nil {
			t.Fatalf("CreateTarget(%s): %v", tgt.Name, err)
		}
		if err := db.GrantTarget(ctx, "ops", tgt.Name); err != nil {
			t.Fatalf("GrantTarget(%s): %v", tgt.Name, err)
		}
	}

	// E-posta OOB (S3.3) eşleşmesi için: OIDC kimliği users.email
	// üzerinden bulunur. Realm'deki yigit ile aynı adres.
	if _, err := db.CreateUser(ctx, "yigit", "yigit@warewave.io", "postern"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := db.AssignRole(ctx, "yigit", "ops", time.Time{}); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	if err := db.AddPublicKey(ctx, "yigit", pub.Marshal(), comment); err != nil {
		t.Fatalf("AddPublicKey: %v", err)
	}
	return db
}

// seedTargetsOnly, yalnızca hedefleri yazar: kullanıcı, rol ve eşleme
// testin kendi işi.
func seedTargetsOnly(t *testing.T, dbDSN string, targets []model.Target) *store.Store {
	t.Helper()
	ctx := context.Background()

	db, err := store.Open(ctx, dbDSN)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	for _, tgt := range targets {
		if _, err := db.CreateTarget(ctx, tgt); err != nil {
			t.Fatalf("CreateTarget(%s): %v", tgt.Name, err)
		}
	}
	return db
}
