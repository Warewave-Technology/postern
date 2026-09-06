package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/proxy"
)

/*
 * ⚠️ KAPALI ÖZELLİK YÜKSELTMEDEN ÖNCE REDDEDİLİYOR.
 *
 * Soketi açıp sonra kapatmak, kullanıcıya bağlanmış gibi görünen bir
 * bağlantı verip sebebini söylememek olurdu — tarayıcı başarısız bir
 * WebSocket el sıkışmasının gövdesini JavaScript'e vermiyor, ama HTTP
 * cevabını veriyor.
 */
func TestFileBrowserIsRefusedWhenTheFlagIsOff(t *testing.T) {
	// ⚠️ logger VERİLİYOR: üretimde New() her zaman kuruyor, dolayısıyla
	// eksik olan üretim kodu değil testin kurulumuydu.
	s := &Server{
		sftpPanel: false,
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/sftp/web01", nil)
	s.serveChannel(rec, req, true)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("durum %d, 403 bekleniyordu", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "sftp_panel") {
		t.Errorf("sebep hangi ayarın kapalı olduğunu söylemiyor: %s", rec.Body.String())
	}
}

/*
 * SFTP kanalı, terminalin iki isteği yerine TEK bir subsystem isteği
 * gönderiyor.
 *
 * ⚠️ NEDEN ÖNEMLİ: kanalın broker'a ne söylediği, yol politikasının ve
 * denetimin devreye girip girmediğini belirliyor. pty+shell gönderen bir
 * kanal SFTP taşımaz; subsystem gönderen kanal beginSFTP'yi tetikler ve
 * geri kalan her şey (politika, defter, zincir) kendiliğinden çalışır.
 */
func TestSFTPChannelAsksForTheSubsystem(t *testing.T) {
	ready := make(chan (<-chan *ssh.Request), 1)
	hold := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		_, reqs := newWSChannelSFTP(context.Background(), c, nil)
		ready <- reqs
		<-hold
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cli, _, err := websocket.Dial(ctx, "ws"+srv.URL[4:], nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { close(hold); _ = cli.CloseNow() }()

	reqs := <-ready

	req := <-reqs
	if req.Type != "subsystem" {
		t.Fatalf("ilk istek %q, subsystem bekleniyordu", req.Type)
	}

	var sub proxy.SubsystemRequest
	if err := ssh.Unmarshal(req.Payload, &sub); err != nil {
		t.Fatalf("gövde çözülemedi: %v", err)
	}
	if sub.Name != "sftp" {
		t.Errorf("alt sistem %q", sub.Name)
	}

	/*
	 * ⚠️ WantReply FALSE OLMALI ve bu bir sınır, tercih değil.
	 *
	 * İstek sentetik: gerçek bir SSH bağlantısından gelmiyor ve
	 * cevaplanamıyor. true olsaydı broker cevabı yazmaya kalkar ve
	 * mux'ı olmayan bir Request üzerinde PANİKLERDİ. Bedeli
	 * wschannel.go'da yazılı: hedef alt sistemi reddederse broker
	 * bunu öğrenemiyor.
	 */
	if req.WantReply {
		t.Error("sentetik istek cevap istiyor — broker mux'sız Request üzerinde panikler")
	}

	// Terminalin pty+shell'i GÖNDERİLMEMELİ: SFTP kanalında kabuk yok.
	select {
	case extra := <-reqs:
		t.Fatalf("fazladan istek gönderildi: %q", extra.Type)
	default:
	}
}

// Terminal kanalı eskisi gibi pty + shell gönderiyor: SFTP varyantı onu
// değiştirmemeli.
func TestTerminalChannelStillAsksForAShell(t *testing.T) {
	ready := make(chan (<-chan *ssh.Request), 1)
	hold := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		_, reqs := newWSChannel(context.Background(), c, nil)
		ready <- reqs
		<-hold
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cli, _, err := websocket.Dial(ctx, "ws"+srv.URL[4:], nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { close(hold); _ = cli.CloseNow() }()

	reqs := <-ready
	if r1 := <-reqs; r1.Type != "pty-req" {
		t.Fatalf("ilk istek %q", r1.Type)
	}
	if r2 := <-reqs; r2.Type != "shell" {
		t.Fatalf("ikinci istek %q", r2.Type)
	}
}
