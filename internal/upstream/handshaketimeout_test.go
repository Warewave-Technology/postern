package upstream

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/model"
)

// shortDialTimeout, sınırı testin bekleyebileceği bir süreye indirir.
func shortDialTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := dialTimeout
	dialTimeout = d
	t.Cleanup(func() { dialTimeout = old })
}

// hostSigner, testlik bir ed25519 sunucu anahtarı üretir.
func hostSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// targetAt, dinleyicinin adresini bir hedefe çevirir.
func targetAt(t *testing.T, l net.Listener, hostKey ssh.PublicKey) model.Target {
	t.Helper()
	host, portStr, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	tg := model.Target{Name: "t1", Host: host, Port: port}
	if hostKey != nil {
		tg.HostKey = string(ssh.MarshalAuthorizedKey(hostKey))
	}
	return tg
}

/*
 * ⚠️ TCP'Yİ KABUL EDİP SUSAN HEDEF, OTURUMU SÜRESİZ TUTMAMALI.
 *
 * ÖLÇÜLEN ARIZA: el sıkışmanın hiçbir sınırı yoktu.
 * ssh.ClientConfig.Timeout bunu yapıyor sanılıyordu — x/crypto o alanı
 * yalnızca ssh.Dial'ın içindeki TCP bağlanmasında okuyor ve biz TCP'yi
 * kendimiz açıp NewClientConn'a veriyoruz.
 *
 * Kimliği doğrulanmış bir kullanıcı bunu kanal başına tekrarlayarak
 * goroutine, soket ve kanal yeri tutabiliyordu; diğer sınırların hiçbiri
 * yetişmiyor (gelen el sıkışma süresi kaldırılmış, idle/lifetime
 * koruyucuları Session.Run'a kadar kurulmuyor).
 */
func TestSilentTargetDoesNotHoldTheSessionForever(t *testing.T) {
	shortDialTimeout(t, 300*time.Millisecond)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Kabul et ve HİÇBİR ŞEY söyleme: çökmüş bir sshd, karadelik yapan
	// bir ara cihaz ya da kasten sessiz bir makine.
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		accepted <- c
	}()

	start := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := dialer(context.Background(), targetAt(t, l, hostSigner(t).PublicKey()),
			"ayse", hostSigner(t))
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("sessiz hedefe bağlantı başarılı sayıldı")
		}
		if el := time.Since(start); el > 5*time.Second {
			t.Errorf("el sıkışma %v sürdü; sınır %v — sınır uygulanmıyor", el, dialTimeout)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sessiz hedef oturumu SÜRESİZ tutuyor — el sıkışmanın üst sınırı yok")
	}

	if c := <-accepted; c != nil {
		c.Close()
	}
}

/*
 * ⚠️ VE SÜRE, EL SIKIŞMADAN SONRA KALDIRILMIŞ OLMALI.
 *
 * Soket süresi kalıcı: kaldırılmasaydı yukarıdaki düzeltme, çalışan
 * HER oturuma dialTimeout kadar bir ömür koyardı — kullanıcının kabuğu
 * yirmi saniye sonra sebepsiz kopardı. Asılı hedefi kesen düzeltmenin
 * en olası yan etkisi tam olarak budur, o yüzden ayrı ölçülüyor.
 */
func TestHandshakeDeadlineIsLiftedForTheSession(t *testing.T) {
	const limit = 300 * time.Millisecond
	shortDialTimeout(t, limit)

	hk := hostSigner(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	scfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	scfg.AddHostKey(hk)

	serverUp := make(chan struct{})
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		sc, chans, reqs, err := ssh.NewServerConn(c, scfg)
		if err != nil {
			c.Close()
			return
		}
		close(serverUp)
		go ssh.DiscardRequests(reqs)
		for nc := range chans {
			nc.Reject(ssh.Prohibited, "test")
		}
		sc.Close()
	}()

	conn, err := dialer(context.Background(), targetAt(t, l, hk.PublicKey()),
		"ayse", hostSigner(t))
	if err != nil {
		t.Fatalf("bağlanılamadı: %v", err)
	}
	defer conn.Close()

	select {
	case <-serverUp:
	case <-time.After(5 * time.Second):
		t.Fatal("sunucu tarafı el sıkışmayı bitirmedi")
	}

	// Sınırın GEÇMESİNİ bekle, sonra bağlantıyı kullan.
	time.Sleep(2 * limit)

	// Kanal reddedilecek (sunucu öyle kurulu) — önemli olan cevabın
	// GELMESİ: süre kaldırılmamış olsaydı soket çoktan ölmüş olurdu ve
	// hata "use of closed network connection" / "i/o timeout" olurdu.
	_, _, err = conn.client.OpenChannel("session", nil)
	var oce *ssh.OpenChannelError
	if err == nil {
		t.Fatal("kanal açıldı — test sunucusu reddetmeliydi")
	}
	if !asOpenChannelError(err, &oce) {
		t.Fatalf("el sıkışmadan %v sonra bağlantı ölmüş: %v — "+
			"soket süresi kaldırılmamış, çalışan oturumlar dialTimeout "+
			"sonunda sessizce kopar", 2*limit, err)
	}
}

// asOpenChannelError, hatanın "sunucu kanalı reddetti" olup olmadığını
// söyler. errors.As sarmalayıcısı: hedef tipi işaretçi-işaretçi.
func asOpenChannelError(err error, target **ssh.OpenChannelError) bool {
	e, ok := err.(*ssh.OpenChannelError)
	if ok {
		*target = e
	}
	return ok
}
