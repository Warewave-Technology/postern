//go:build integration

package integration

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/config"
)

/*
 * ⚠️ KAPANIŞ, OTURUMU DÜZGÜN KAPATMALI — ve kapatmıyordu.
 *
 * Serve, ctx iptal edilince dinleyiciyi kapatıp hemen dönüyordu:
 * bağlantı goroutine'lerini bekleyen hiçbir şey yoktu. Bedeli
 * kullanıcının kopan oturumundan ibaret değildi — Session.Close hiç
 * çalışmadığı için (1) denetim satırı sonsuza dek "running" kalıyor,
 * (2) kayıt yarım kapanıyor, (3) arşiv kuyruğuna hiç girmiyordu. Yani
 * bir yeniden başlatma, o an bağlı olan herkesin kaydını hem eksik hem
 * YÜKLENEMEZ bırakıyordu; "arşivlenmemiş hiçbir şey budanmaz" kuralı
 * gereği o kayıtlar diskte de kalıyordu.
 *
 * Bu test üçünü birden ölçüyor, çünkü üçü de aynı Close'a bağlı.
 */
func TestShutdownClosesLiveSessionsAndQueuesTheirRecordings(t *testing.T) {
	caKeyPath, caAuthorizedKey := newTestCA(t)
	tgt := startCertTarget(t, caAuthorizedKey)
	tc := tgt.target()
	tc.Name = "web01"

	// Beklemeyi kısalt: testin ölçtüğü şey süre değil, süre dolunca
	// oturumun DÜZGÜN kapanması.
	tuneConfig = func(c *config.Config) {
		c.Shutdown.DrainTimeout = 500 * time.Millisecond
	}
	t.Cleanup(func() { tuneConfig = nil })

	srv, hostPub, signer, db := newBastion(t, caKeyPath, tc)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx, l) }()

	client, err := ssh.Dial("tcp", l.Addr().String(), &ssh.ClientConfig{
		User:            "yigit:web01",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         15 * time.Second,
	})
	if err != nil {
		t.Fatalf("bağlanılamadı: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Start("sleep 300"); err != nil {
		t.Fatalf("uzun komut başlatılamadı: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()

	id := waitForOpenSession(t, db)

	// ⚠️ ÖNCE AKTIĞINI GÖSTER: bu satır olmadan test, oturumun zaten
	// ölü olması yüzünden de geçerdi.
	select {
	case err := <-done:
		t.Fatalf("kapanıştan önce oturum bitmiş: %v", err)
	case <-time.After(500 * time.Millisecond):
	}

	cancel()

	select {
	case <-served:
	case <-time.After(30 * time.Second):
		t.Fatal("Serve dönmedi: drain takıldı")
	}

	/*
	 * ⚠️ ÖLÇÜLEN ŞEY SIRALAMA — ve ilk yazdığım test bunu kaçırdı.
	 *
	 * Aşağıdaki iddiaları `done`u bekledikten SONRA kurmuştum ve test
	 * düzeltme olmadan da geçiyordu: bir testte Serve dönse bile
	 * handleConn goroutine'i yaşamaya devam ediyor, bağlantı sonunda
	 * kopuyor ve Close yine çalışıyor. Süreçte ise Serve'in dönmesi
	 * main'in çıkması demek — o goroutine'ler orada ölüyor.
	 *
	 * Doğru iddia bu yüzden zamanlama değil sıra: SERVE DÖNDÜĞÜ ANDA
	 * oturum çoktan kapanmış olmalı. Drain'in WaitGroup'u tam bunu
	 * garanti ediyor; kaldırıldığında iddia düşüyor.
	 */
	bg := context.Background()

	// 1) Denetim satırı kapandı mı?
	s, err := db.Session(bg, id)
	if err != nil {
		t.Fatal(err)
	}
	if s.Open() {
		t.Error("oturum satırı 'running' kaldı: panel onu süresiz akıyor gösterir")
	}

	// 2) Arşiv kuyruğuna girdi mi? Girmezse kayıt ne yüklenebilir ne
	//    budanabilir — diskte sessizce birikir.
	_, queued, err := db.ArchiveStateOf(bg, id)
	if err != nil {
		t.Fatalf("arşiv durumu okunamadı: %v", err)
	}
	if !queued {
		t.Error("KAPANIŞTA AÇIK OLAN OTURUM ARŞİV KUYRUĞUNA HİÇ GİRMEDİ: " +
			"kaydı ne yüklenebilir ne budanabilir")
	}

	// Kullanıcı tarafı da bitmiş olmalı; buraya gelindiğinde beklemek
	// gerekmemeli.
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Error("oturum istemci tarafında bitmedi")
	}
}
