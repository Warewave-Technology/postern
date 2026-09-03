package sshd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/config"
)

// serveOn, verilen config ile bir sunucuyu geçici bir portta çalıştırır.
func serveOn(t *testing.T, srv *Server) net.Addr {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.Serve(ctx, l)
	}()

	t.Cleanup(func() {
		cancel()
		<-done
	})
	return l.Addr()
}

// Sürüm satırını hiç tamamlamayan bir istemci, handshake süresi dolunca
// SUNUCU tarafından kapatılmalı.
//
// Kapattığı açık somut: x/crypto sürüm satırını BAYT BAYT okur ve son
// tarih yoksa saatte bir bayt gönderen bir istemci, kimliğini hiç
// doğrulamadan bir goroutine ve bir dosya tanıtıcısı tutar. Kimlik
// doğrulamasız yaptırabileceğin en ucuz şey budur.
//
// İddia SUNUCUNUN kapatması üzerine: istemci tarafında bir zaman aşımı
// sunucu hakkında hiçbir şey ispatlamazdı.
func TestHandshakeDeadlineClosesStalledConnection(t *testing.T) {
	cfg := testConfigNoDB(t)
	cfg.Listen.HandshakeTimeout = 800 * time.Millisecond

	srv, err := New(cfg, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	addr := serveOn(t, srv)

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// CRLF YOK: sunucu readVersion döngüsünde takılı kalır.
	if _, err := conn.Write([]byte("SSH-2.0-stalled")); err != nil {
		t.Fatal(err)
	}

	// Okuma son tarihi sınırın belirgin biçimde üstünde: erken dönen bir
	// EOF sunucunun kapattığını gösterir, geç dönen bir timeout ise
	// testin kendi sabrının bittiğini.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	start := time.Now()
	_, err = io.ReadAll(conn)
	elapsed := time.Since(start)

	if err != nil && errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("sunucu %v içinde kapatmadı — handshake süresiz", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Errorf("kapanma %v sürdü, ~800ms bekleniyordu", elapsed)
	}
	t.Logf("sunucu bağlantıyı %v içinde kapattı", elapsed)
}

// Handshake BİTTİKTEN sonra son tarih temizlenmeli.
//
// Bu testin varlık sebebi: net.Conn son tarihleri kalıcıdır ve
// x/crypto'nun okuma goroutine'i oturum boyunca okumaya devam eder.
// SetDeadline(time.Time{}) unutulursa HER oturum tam olarak
// handshake_timeout'ta ölür — ve handshake testleri bunu göstermez,
// çünkü handshake başarıyla biter. Bu hata testsiz yeşil sevk edilirdi.
func TestDeadlineIsClearedAfterHandshake(t *testing.T) {
	// Bu test kimlik doğrulamaya kadar gidiyor, dolayısıyla gerçek
	// veritabanı gerekiyor.
	cfg := testConfig(t)
	cfg.Listen.HandshakeTimeout = 700 * time.Millisecond

	signer, authorized := signerAndAuthorized(t)
	srv, err := New(cfg, testStore(t, cfg, authorized), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	addr := serveOn(t, srv)

	client, err := ssh.Dial("tcp", addr.String(), &ssh.ClientConfig{
		User: "yigit:web01",
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		// ⚠️ InsecureIgnoreHostKey TESTTE DE YASAK (handshake_test.go ve
		// cert_test.go'daki notlar). Anahtar cfg.HostKey'de duruyor;
		// geri okumak iki satır. Kuralı yazıp çiğnemek, kuralı hiç
		// yazmamaktan kötü: sonraki okuyan onu geçerli bir desen sanar.
		HostKeyCallback: ssh.FixedHostKey(hostKeyOf(t, cfg.HostKey)),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer client.Close()

	// Handshake süresinin KATBEKAT üstünde bekle. Son tarih temizlenmemiş
	// olsaydı bağlantı burada ölürdü.
	time.Sleep(3 * cfg.Listen.HandshakeTimeout)

	// Bağlantı hâlâ konuşabiliyor mu? Kanal açma denemesi yeter: hedef
	// yoksa reddedilir, ama REDDİN GELMESİ bağlantının yaşadığını
	// gösterir. Ölü bir bağlantı io hatası verirdi.
	_, _, err = client.OpenChannel("session", nil)
	if err == nil {
		return // açıldı: bağlantı kesinlikle canlı
	}

	var openErr *ssh.OpenChannelError
	if !errors.As(err, &openErr) {
		t.Fatalf("bağlantı handshake süresinden sonra ölmüş: %v "+
			"(SetDeadline(time.Time{}) unutulmuş olabilir)", err)
	}
	t.Logf("bağlantı canlı; kanal politikayla reddedildi: %v", openErr)
}

// signerAndAuthorized, bir istemci anahtarı üretir ve hem imzalayıcıyı
// hem authorized_keys satırını döner.
func signerAndAuthorized(t *testing.T) (ssh.Signer, string) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer, string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
}

// testConfigNoDB, veritabanı gerektirmeyen testler için config.
//
// Ayrı olmasının sebebi: dinleyici seviyesindeki testler kimlik
// doğrulamaya hiç ulaşmıyor, dolayısıyla Docker istemeden koşabilmeliler.
func testConfigNoDB(t *testing.T) *config.Config {
	t.Helper()

	hostKeyPath, _ := writeHostKey(t)
	return &config.Config{
		Listen:    config.ListenConfig{Addr: "127.0.0.1:0"},
		HostKey:   hostKeyPath,
		CA:        config.CAConfig{KeyFile: testCAKey(t)},
		Recording: config.RecordingConfig{Dir: filepath.Join(t.TempDir(), "recordings")},
	}
}

// hostKeyOf, host key dosyasının AÇIK anahtarını döner.
//
// testConfig anahtarı üretip yolunu veriyor ama açık yarısını atıyor;
// burada dosyadan geri okumak, testConfig'in imzasını ve bütün
// çağıranlarını değiştirmekten ucuz.
func hostKeyOf(t *testing.T, path string) ssh.PublicKey {
	t.Helper()
	pem, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		t.Fatal(err)
	}
	return signer.PublicKey()
}
