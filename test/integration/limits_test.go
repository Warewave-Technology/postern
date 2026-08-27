//go:build integration

package integration

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/config"
)

// Tarayıcı girişi, handshake süresi ONDAN KISA olsa bile tamamlanmalı.
//
// Bu testin varlık sebebi tuzağın kendisi: OOB onayı handshake'in İÇİNDE
// bekleniyor. Düz bir handshake son tarihi eklemek, her tarayıcı girişini
// ortasından keserdi — ve kesilme bir ağ arızası gibi görünürdü. Süre
// yalnızca istemci giriş linkini aldıktan SONRA uzatılıyor
// (internal/sshd/limits.go), yani ucuz yol ucuz kalıyor.
//
// Uzatma kaldırılırsa ya da yanlış sıraya konursa BU TEST DÜŞER.
func TestOOBLoginSurvivesShortHandshakeTimeout(t *testing.T) {
	// Handshake süresi 6 sn, OOB onayı için 60 sn: onay penceresi
	// handshake penceresinin on katı.
	tuneConfig = func(c *config.Config) {
		c.Listen.HandshakeTimeout = 6 * time.Second
	}
	t.Cleanup(func() { tuneConfig = nil })

	sshAddr, _, hostPub, db := oobBastion(t, 60*time.Second)

	client, err := kiClient(sshAddr, hostPub, func(loginURL, userCode string) error {
		// Handshake süresinden UZUN bekle: uzatma yoksa sunucu tam
		// burada bağlantıyı düşürür.
		time.Sleep(8 * time.Second)
		return approveInBrowser(loginURL, userCode)
	})
	if err != nil {
		t.Fatalf("kısa handshake süresiyle OOB girişi düştü: %v "+
			"(extendDeadline çağrılmıyor ya da challenge'dan önce çağrılıyor olabilir)", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	out, err := sess.Output("id -un")
	sess.Close()
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "postern" {
		t.Errorf("hedefteki hesap = %q", got)
	}

	recorded, err := db.Sessions(context.Background(), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(recorded) != 1 {
		t.Errorf("%d oturum kaydı, 1 bekleniyordu", len(recorded))
	}
}

// IP başına sınır: kotayı aşan bağlantı kabul edilmemeli, kapanan bir
// bağlantı yer açmalı.
//
// İkinci yarı olmadan test, sayacın arttığını doğrular ama azaldığını
// doğrulamaz — ve azalmayan bir sayaç bastion'ı zamanla kilitler.
func TestPerIPConnectionLimit(t *testing.T) {
	caKeyPath, caPub := newTestCA(t)
	tgt := startCertTarget(t, caPub)
	tc := tgt.target()
	tc.Name = "web01"

	addr, hostPub, signer := withConfig(t, caKeyPath, func(c *config.Config) {
		c.Listen.MaxConnsPerIP = 2
	}, tc)
	_ = hostPub

	dial := func() (*ssh.Client, error) {
		return ssh.Dial("tcp", addr, &ssh.ClientConfig{
			User:            "yigit:web01",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         10 * time.Second,
		})
	}

	c1, err := dial()
	if err != nil {
		t.Fatalf("ilk bağlantı: %v", err)
	}
	c2, err := dial()
	if err != nil {
		c1.Close()
		t.Fatalf("ikinci bağlantı: %v", err)
	}

	// Üçüncüsü reddedilmeli. Sunucu goroutine açmadan kapatıyor, yani
	// istemci handshake sırasında EOF görür.
	if c3, err := dial(); err == nil {
		c3.Close()
		c1.Close()
		c2.Close()
		t.Fatal("üçüncü bağlantı kabul edildi, max_conns_per_ip=2")
	}

	// Yer aç ve tekrar dene.
	c1.Close()

	// Sunucunun release'i defer'da; kapanmanın işlenmesi için kısa bir
	// pencere tanı.
	var c4 *ssh.Client
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c4, err = dial(); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if c4 == nil {
		c2.Close()
		t.Fatal("bağlantı kapandıktan sonra hâlâ reddediliyor — release çalışmıyor")
	}
	c4.Close()
	c2.Close()
}

// Boşta kalan oturum kapatılmalı VE denetim satırı düzgün kapanmalı.
//
// İkinci yarı en az birincisi kadar önemli: oturumu "çalışıyor" işaretli
// bırakan bir zaman aşımı, kaynak hatasını denetim hatasıyla takas
// etmiş olurdu.
func TestIdleSessionIsClosedAndRecorded(t *testing.T) {
	caKeyPath, caPub := newTestCA(t)
	tgt := startCertTarget(t, caPub)
	tc := tgt.target()
	tc.Name = "web01"

	tuneConfig = func(c *config.Config) {
		c.Session.IdleTimeout = 3 * time.Second
	}
	t.Cleanup(func() { tuneConfig = nil })

	srv, hostPub, signer, db := newBastionOpts(t, caKeyPath, false, tc)
	addr := startBastion(t, srv)

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "yigit:web01",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	// PTY + açık stdin: pty olmadan uzak kabuk stdin kapanır kapanmaz
	// kendiliğinden çıkar ve test "boşta kalma sınırı çalıştı" diye
	// YANLIŞ sebepten geçerdi.
	if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty: %v", err)
	}
	if _, err := sess.StdinPipe(); err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("Shell: %v", err)
	}

	// Hiçbir şey yazma, hiçbir şey okuma: oturum boşta.
	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("boşta oturum kapatılmadı")
	}

	// Kapanma sınırın ÖNCESİNDE olduysa sebep boşta kalma değildir —
	// test bir şey ispatlamıyor demektir.
	if elapsed := time.Since(start); elapsed < 2*time.Second {
		t.Fatalf("oturum %v içinde kapandı, boşta kalma sınırı 3s — "+
			"başka bir sebeple kapanmış, test bir şey ispatlamıyor", elapsed)
	} else {
		t.Logf("oturum %v boşta kaldıktan sonra kapandı", elapsed)
	}

	// Denetim satırı kapanmış olmalı.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		recorded, err := db.Sessions(context.Background(), "", 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(recorded) == 1 && !recorded[0].EndedAt.IsZero() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Error("oturum kapandı ama denetim satırı 'çalışıyor' kaldı")
}

var _ = net.Dial
