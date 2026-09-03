//go:build integration

package integration

// S4.3'ün "Bitti" kanıtı: tarayıcı oturumuyla açılan WebSocket, hedefte
// gerçek bir kabuk sürüyor; girdi/çıktı akıyor, resize iletiliyor,
// bağlantı kopunca oturum kapanıyor ve denetim kaydına düşüyor.
//
//	go test -tags integration -run TestTerminal -v ./test/integration/

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/Warewave-Technology/postern/internal/model"
)

// dialTerminal, oturum cookie'siyle terminal WS'ini açar.
func dialTerminal(t *testing.T, client *http.Client, apiURL, target, origin string) (*websocket.Conn, *http.Response, error) {
	t.Helper()

	wsURL := strings.Replace(apiURL, "http://", "ws://", 1) + "/api/terminal/" + target

	header := http.Header{}
	if origin != "" {
		header.Set("Origin", origin)
	}
	return websocket.Dial(context.Background(), wsURL, &websocket.DialOptions{
		HTTPClient: client,
		HTTPHeader: header,
	})
}

func TestTerminalEndToEnd(t *testing.T) {
	_, apiURL, _, db := oobBastionWithTerminal(t)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)

	conn, _, err := dialTerminal(t, client, apiURL, "web01", apiURL)
	if err != nil {
		t.Fatalf("terminal WS açılamadı: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Resize: JSON kontrol mesajı, veri akışından ayrı.
	if err := conn.Write(ctx, websocket.MessageText,
		[]byte(`{"type":"resize","cols":100,"rows":30}`)); err != nil {
		t.Fatalf("resize: %v", err)
	}

	// Komut: ham bayt olarak, tıpkı klavyeden gelmiş gibi.
	if err := conn.Write(ctx, websocket.MessageBinary, []byte("echo web-terminal-kaniti\n")); err != nil {
		t.Fatalf("girdi: %v", err)
	}

	// Çıktıyı bekle. Kabuk yankısı ve prompt da geleceği için parça parça
	// biriktirip aranan metni arıyoruz.
	var out strings.Builder
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(out.String(), "web-terminal-kaniti") {
		if time.Now().After(deadline) {
			t.Fatalf("hedef çıktısı gelmedi; şu ana kadar: %q", out.String())
		}
		typ, data, err := conn.Read(ctx)
		if err != nil {
			t.Fatalf("okuma: %v (biriken: %q)", err, out.String())
		}
		if typ == websocket.MessageBinary {
			out.Write(data)
		}
	}

	// Bağlantıyı kapat: oturum kapanmalı ve denetim kaydı tamamlanmalı.
	conn.Close(websocket.StatusNormalClosure, "")

	var closed bool
	for i := 0; i < 100 && !closed; i++ {
		sessions, err := db.Sessions(context.Background(), "", 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(sessions) == 1 && !sessions[0].Open() {
			closed = true
			if sessions[0].Target != "web01" || sessions[0].User != "yigit" {
				t.Errorf("denetim kaydı yanlış: %+v", sessions[0])
			}
			if sessions[0].RecordingPath == "" {
				t.Error("web terminali oturumu kayıtsız — .cast yolu boş")
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !closed {
		t.Fatal("WS kapandıktan sonra denetim kaydı kapanmadı")
	}
}

// Cross-site WebSocket hijacking: kötü niyetli bir sayfa, kurbanın
// cookie'siyle terminale bağlanamamalı. SameSite cookie kuralı WS'i
// KAPSAMAZ — bu yüzden Origin kontrolü zorunlu.
func TestTerminalRejectsForeignOrigin(t *testing.T) {
	_, apiURL, _, _ := oobBastionWithTerminal(t)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)

	conn, resp, err := dialTerminal(t, client, apiURL, "web01", "http://kotu-site.example")
	if err == nil {
		conn.Close(websocket.StatusNormalClosure, "")
		t.Fatal("yabancı Origin ile terminal açıldı — cross-site WS hijacking mümkün")
	}
	if resp != nil && resp.StatusCode != http.StatusForbidden {
		t.Errorf("durum = %d, beklenen 403", resp.StatusCode)
	}
}

// Erişimi olmayan hedefe terminal açılamaz: yetki SSH ile aynı yerden,
// policy'den geliyor.
func TestTerminalDeniesUngrantedTarget(t *testing.T) {
	_, apiURL, _, db := oobBastionWithTerminal(t)

	// Yetkisiz bir hedef ekle (role bağlanmıyor).
	if _, err := db.CreateTarget(context.Background(), yasakTarget()); err != nil {
		t.Fatal(err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)

	/*
	 * ⚠️ SOKET AÇILIYOR VE SEBEBİYLE KAPANIYOR — VE BU BİR DÜZELTME.
	 *
	 * Bu test eskiden el sıkışmanın 403 ile başarısız olmasını
	 * sabitliyordu. Sunucu tarafında doğru görünüyordu ama TARAYICIDA
	 * hiçbir şey ifade etmiyordu: WebSocket el sıkışması 101 dışında
	 * bir şeyle bitince tarayıcı durum kodunu da gövdeyi de
	 * JavaScript'e vermiyor (WHATWG bunu kasten yapıyor). Panelde
	 * görünen tek şey "[disconnected]" idi.
	 *
	 * Sebep artık kapanış çerçevesiyle geliyor; tarayıcı CloseEvent'in
	 * code ve reason alanlarını veriyor.
	 */
	conn, _, err := dialTerminal(t, client, apiURL, "yasak01", apiURL)
	if err != nil {
		t.Fatalf("soket hiç açılmadı: %v — sebep taşınamaz", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	_, _, readErr := conn.Read(context.Background())
	if readErr == nil {
		t.Fatal("yetkisiz hedefe terminal açıldı")
	}
	if got := websocket.CloseStatus(readErr); got != 4403 {
		t.Errorf("kapanış kodu = %d, 4403 bekleniyordu: %v", got, readErr)
	}
	if !strings.Contains(readErr.Error(), "do not have access") {
		t.Errorf("sebep kullanıcıya ulaşmıyor: %v", readErr)
	}
}

/*
 * ⚠️ HEDEF BİZİ REDDEDİYORSA EKRAN BUNU SÖYLEMELİ.
 *
 * ÖLÇÜLEN ARIZA: hedefi bu bastion'ın CA'sına güvenecek şekilde
 * yapılandırmamış bir kurulumda, panelde kabuk düğmesine basan
 * kullanıcının gördüğü tek şey "[disconnected]" idi. Sunucu sebebi
 * biliyor ve günlüğüne yazıyordu; ekranda özelliğin BOZUK olduğunu
 * düşündüren boş bir satır kalıyordu.
 *
 * Burada hedef GERÇEKTEN başka bir CA'ya güveniyor, yani reddi gerçek
 * bir OpenSSH sunucusu veriyor.
 */
func TestTerminalSaysWhyTheTargetRefusedUs(t *testing.T) {
	_, apiURL, _, db := oobBastionWithTerminal(t)

	// Bizim CA'mıza DEĞİL, başkasına güvenen bir hedef.
	rogue := testAuthority(t)
	stranger := startCertTarget(t, rogue.AuthorizedKey())
	tc := stranger.target()
	tc.Name = "yabanci01"
	if _, err := db.CreateTarget(context.Background(), tc); err != nil {
		t.Fatal(err)
	}
	if err := db.GrantTarget(context.Background(), "ops", "yabanci01"); err != nil {
		t.Fatal(err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)

	conn, _, err := dialTerminal(t, client, apiURL, "yabanci01", apiURL)
	if err != nil {
		t.Fatalf("soket hiç açılmadı: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	_, _, readErr := conn.Read(context.Background())
	if readErr == nil {
		t.Fatal("bize güvenmeyen hedefe oturum açıldı")
	}
	if got := websocket.CloseStatus(readErr); got != 4503 {
		t.Errorf("kapanış kodu = %d, 4503 bekleniyordu: %v", got, readErr)
	}
	/*
	 * Cümle NE YAPILACAĞINI söylemeli. "session unavailable" teknik
	 * olarak doğruydu ve okuyan kişiye hiçbir şey vermiyordu — üstelik
	 * bu ekranı gören kişi çoğu zaman hedefi henüz yapılandırmamış
	 * olan operatörün ta kendisi.
	 */
	for _, want := range []string{"certificate", "CA"} {
		if !strings.Contains(readErr.Error(), want) {
			t.Errorf("sebep %q içermiyor: %v", want, readErr)
		}
	}
}

// Terminal kapalıyken rota HİÇ yok: kapalı özellik, kapalı yüzey.
func TestTerminalRouteAbsentWhenDisabled(t *testing.T) {
	_, apiURL, _, _ := oobBastion(t, 0) // terminal AÇILMADAN kurulan düzenek

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)

	_, resp, err := dialTerminal(t, client, apiURL, "web01", apiURL)
	if err == nil {
		t.Fatal("terminal kapalıyken WS açıldı")
	}
	if resp != nil && resp.StatusCode != http.StatusNotFound {
		t.Errorf("durum = %d, beklenen 404 (rota yok)", resp.StatusCode)
	}
}

// yasakTarget, hiçbir role bağlanmayan hedef: policy reddetmeli.
func yasakTarget() model.Target {
	return model.Target{
		Name: "yasak01", Host: "127.0.0.1", Port: 2298,
		HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIcLUQM0UcoZdJVh2EokribDvFZyyNyAVURM/LrCugFM",
	}
}
