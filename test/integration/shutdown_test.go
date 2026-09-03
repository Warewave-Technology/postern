//go:build integration

package integration

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/config"
	"github.com/warewave/postern/internal/sshd"
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

/*
 * ⚠️ DRAIN GERÇEKTEN BEKLEMELİ — ve beklemiyordu.
 *
 * Yukarıdaki test kapanışın Session.Close'u çalıştırdığını ölçüyor ve
 * o kadarını doğru ölçüyor. Ölçmediği şey, düzeltmenin ASIL iddiası:
 * "açık oturumlar drain_timeout kadar devam eder, süre dolunca
 * sebebiyle kapatılır". O yarısı çalışmıyordu ve test üstünden geçiyordu.
 *
 * Sebep: bağlantı context'i kapanış sinyalinin ta kendisinden
 * türüyordu, yani SIGTERM her oturumu ANINDA iptal ediyordu (ölçüldü:
 * 5 saniyelik grace'te 253µs). drain sonra boşalmış bir kayıt
 * defterini bekliyor, TerminateAll sıfır oturum kesiyor, kullanıcı
 * hiçbir şey görmüyordu.
 *
 * Bu test iki şeyi birden ölçüyor, çünkü ikisi de aynı kopuşa bağlı:
 * oturum grace boyunca YAŞIYOR mu, ve süre dolunca kullanıcı SEBEBİ
 * görüyor mu.
 */
func TestShutdownGivesLiveSessionsTheirGraceAndTellsThemWhy(t *testing.T) {
	caKeyPath, caAuthorizedKey := newTestCA(t)
	tgt := startCertTarget(t, caAuthorizedKey)
	tc := tgt.target()
	tc.Name = "web01"

	// Ölçülebilir bir grace: t+0'da ölmekle süreyi beklemek arasındaki
	// farkın gürültüden büyük olması gerekiyor.
	const grace = 3 * time.Second
	tuneConfig = func(c *config.Config) { c.Shutdown.DrainTimeout = grace }
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
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	said := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(stdout)
		said <- string(b)
	}()

	if err := sess.Start("sleep 300"); err != nil {
		t.Fatalf("uzun komut başlatılamadı: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()

	waitForOpenSession(t, db)

	// ⚠️ ÖNCE AKTIĞINI GÖSTER: bu olmadan test, oturum zaten ölüyken de
	// geçerdi.
	select {
	case err := <-done:
		t.Fatalf("kapanıştan önce oturum bitmiş: %v", err)
	case <-time.After(500 * time.Millisecond):
	}

	start := time.Now()
	cancel()

	select {
	case <-done:
	case <-time.After(grace + 20*time.Second):
		t.Fatal("oturum hiç bitmedi")
	}
	lived := time.Since(start)

	/*
	 * ⚠️ ASIL İDDİA. Kusurlu sürümde bu süre mikrosaniyelerdi.
	 * Yarısı, saatin gürültüsünden rahatça büyük ve "grace'i bekledi"
	 * demek için yeterli — tam eşitlik beklemek testi zamanlamaya
	 * bağımlı yapardı.
	 */
	if lived < grace/2 {
		t.Errorf("oturum kapanış sinyaliyle birlikte %v içinde öldü; "+
			"drain_timeout %v idi — açık oturumlara verilen süre uygulanmıyor",
			lived, grace)
	}

	// ⚠️ SESSİZ KOPUŞ, AĞ ARIZASINDAN AYIRT EDİLEMEZ. Kullanıcı
	// bastion'ın kapandığını görmeli, yoksa yeniden bağlanıp aynı işi
	// dener.
	select {
	case out := <-said:
		if !strings.Contains(out, "shutting down") {
			t.Errorf("kullanıcıya sebep gitmedi; okuduğu: %q", out)
		}
	case <-time.After(10 * time.Second):
		t.Error("istemcinin çıktı akışı hiç kapanmadı")
	}

	select {
	case <-served:
	case <-time.After(30 * time.Second):
		t.Fatal("Serve dönmedi: drain takıldı")
	}
	shutdownTook := time.Since(start)

	/*
	 * ⚠️ KESTİKTEN SONRAKİ BEKLEME, OTURUM KAPANINCA BİTMELİ.
	 *
	 * ÖLÇÜLEN ARIZA: o bekleme `live.Wait()` idi ve `live` bağlantı
	 * goroutine'lerini sayıyor. Oturum kesildikten sonra bağlantı
	 * yaşamaya devam ettiği için bekleme hiç bitmiyor, her kapanış
	 * closeGrace kadar (5 sn) fazladan sürüyor ve sonunda "recordings
	 * may be incomplete" HATASI yazılıyordu — üstelik yalan: aynı
	 * testler kaydın kapandığını ve arşive girdiğini doğruluyor.
	 *
	 * Süreyle ölçülüyor çünkü ölçülebilir olan bu: log satırını
	 * yakalamak paylaşılan koşum takımını değiştirmeyi gerektirirdi,
	 * gecikme ise doğrudan operatörün beklediği süre.
	 */
	if slack := shutdownTook - grace; slack > 2*time.Second {
		t.Errorf("kapanış grace'ten %v sonra bitti (toplam %v); kesilen "+
			"oturumlar kapandığı hâlde bir şey bekleniyor — operatör her "+
			"yeniden başlatmada bu süreyi ödüyor", slack, shutdownTook)
	}
}

// captureBastion, oobBastionOpts'un kurduğu sunucuyu teste verir.
// tuneConfig ile aynı desen: bu testler paralel koşmuyor.
var captureBastion func(*sshd.Server)

/*
 * ⚠️ KAPANIŞ, PANEL TERMİNALİ OTURUMLARINI DA DRAIN ETMELİ.
 *
 * Drain, `live` WaitGroup'unu bekliyordu ve o yalnızca SSH kapısının
 * bağlantı goroutine'lerini sayıyor. Panel terminali oturumu HTTP
 * sunucusunda yaşıyor ve o sayaca HİÇ girmiyor.
 *
 * ÖLÇÜLDÜ ve bedeli yanlış bir log satırından ağır: canlı bir panel
 * terminali varken Serve 84 µs'de döndü, log "all sessions ended;
 * shutting down" dedi, TerminateAll hiç çağrılmadı. Serve döndüğü an —
 * süreçte main'in çıkmak üzere olduğu an — oturum hâlâ defterde,
 * denetim satırı hâlâ "running", kayıt arşiv kuyruğuna hiç girmemişti.
 *
 * Yani bütün drain çalışmasının kapatmak için var olduğu arıza,
 * ikinci kapıda aynen duruyordu. Bu testin ölçtüğü şey de tam olarak
 * o üçlü: defter boşaldı mı, satır kapandı mı, kayıt kuyruğa girdi mi.
 */
func TestShutdownDrainsWebTerminalSessionsToo(t *testing.T) {
	const grace = 3 * time.Second

	var srv *sshd.Server
	captureBastion = func(s *sshd.Server) { srv = s }
	tuneConfig = func(c *config.Config) { c.Shutdown.DrainTimeout = grace }
	t.Cleanup(func() { captureBastion, tuneConfig = nil, nil })

	_, apiURL, _, db := oobBastionWithTerminal(t)
	if srv == nil {
		t.Fatal("koşum takımı sunucuyu vermedi")
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)

	conn, _, err := dialTerminal(t, client, apiURL, "web01", apiURL)
	if err != nil {
		t.Fatalf("terminal WS açılamadı: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	wsCtx, wsCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer wsCancel()

	// ⚠️ ÖNCE AKTIĞINI GÖSTER: bu olmadan test, oturum zaten ölüyken de
	// geçerdi.
	if err := conn.Write(wsCtx, websocket.MessageBinary, []byte("echo kanit\n")); err != nil {
		t.Fatalf("girdi: %v", err)
	}
	var out strings.Builder
	readDeadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(out.String(), "kanit") {
		if time.Now().After(readDeadline) {
			t.Fatalf("kabuk akmıyor; gelen: %q", out.String())
		}
		typ, data, rerr := conn.Read(wsCtx)
		if rerr != nil {
			t.Fatalf("okuma: %v", rerr)
		}
		if typ == websocket.MessageBinary {
			out.Write(data)
		}
	}

	id := waitForOpenSession(t, db)
	if n := len(srv.LiveSessions().RunningIDs()); n != 1 {
		t.Fatalf("defterde %d oturum var, 1 bekleniyordu", n)
	}

	/*
	 * ⚠️ OKUMAYA DEVAM EDEN BİR İSTEMCİ ŞART — ölçülerek öğrenildi.
	 *
	 * Kapanış yolu kullanıcıya sebebi YAZIYOR ve o yazma websocket'e
	 * gidiyor. Test okumayı bıraktığında yazma tıkanıyor, oturum
	 * kapanamıyor ve defterden düşmüyor: ilk denemede tam olarak bu
	 * oldu ve düzeltme çalışıyorken bile üç iddia birden düştü.
	 *
	 * Gerçek bir tarayıcı sekmesi okumaya devam eder; testin de
	 * etmesi gerekiyor, yoksa ölçtüğü şey kendi kurgusu olur.
	 */
	saw := make(chan string, 1)
	go func() {
		var b strings.Builder
		b.WriteString(out.String())
		for {
			typ, data, rerr := conn.Read(wsCtx)
			if rerr != nil {
				saw <- b.String()
				return
			}
			if typ == websocket.MessageBinary {
				b.Write(data)
			}
		}
	}()

	/*
	 * ⚠️ TAZE BİR DİNLEYİCİ, KİMSE BAĞLANMIYOR. Üretimdeki durum bu:
	 * SIGTERM, hiç SSH bağlantısı yokken ve bir panel terminali
	 * akarken. `live` böylece kesinlikle boş ve kusurlu sürüm anında
	 * "bitti" diyor.
	 */
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	sctx, scancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- srv.Serve(sctx, l) }()
	time.Sleep(200 * time.Millisecond)

	start := time.Now()
	scancel()
	select {
	case <-served:
	case <-time.After(grace + 30*time.Second):
		t.Fatal("Serve dönmedi")
	}
	elapsed := time.Since(start)

	if elapsed < grace/2 {
		t.Errorf("Serve %v'de döndü (grace %v) — panel terminali "+
			"oturumu hiç beklenmedi", elapsed, grace)
	}

	// ⚠️ ÜÇ İDDİA DA DENETİMLE İLGİLİ ve asıl sebep bu: Serve döndüğü
	// anda süreç ölmek üzere. O an bunlar olmadıysa hiç olmayacaklar.
	if n := len(srv.LiveSessions().RunningIDs()); n != 0 {
		t.Errorf("Serve döndü ama defterde %d oturum kaldı", n)
	}
	bg := context.Background()
	s, err := db.Session(bg, id)
	if err != nil {
		t.Fatal(err)
	}
	if s.Open() {
		t.Error("denetim satırı 'running' kaldı: panel onu süresiz akıyor gösterir")
	}
	if _, queued, aerr := db.ArchiveStateOf(bg, id); aerr != nil {
		t.Fatalf("arşiv durumu okunamadı: %v", aerr)
	} else if !queued {
		t.Error("PANEL TERMİNALİ OTURUMU ARŞİV KUYRUĞUNA HİÇ GİRMEDİ: " +
			"kaydı ne yüklenebilir ne budanabilir")
	}

	// ⚠️ SEBEP PANEL KULLANICISINA DA GİTMELİ. SSH tarafında ölçülen
	// şeyin ikinci kapıdaki karşılığı: sessiz kopuş, ağ arızasından
	// ayırt edilemez.
	select {
	case seen := <-saw:
		if !strings.Contains(seen, "shutting down") {
			t.Errorf("panel kullanıcısına sebep gitmedi; okuduğu: %q", seen)
		}
	case <-time.After(10 * time.Second):
		t.Error("panel terminali akışı hiç kapanmadı")
	}
}
