package httpapi

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/warewave/postern/internal/events"
)

/*
 * Kapanışın canlı bir akış yüzünden ASILMADIĞINI ölçer.
 *
 * Bu test bir kuruntudan değil, ölçülmüş bir arızadan doğdu: SIGTERM
 * alan postern ölmüyordu. http.Server.Shutdown etkin bağlantıların
 * bitmesini bekler ve istek bağlamlarını iptal etmez; olay akışı
 * işleyicisi de kendiliğinden hiç bitmez. Süreç ayakta kalıyor,
 * paneli açık operatör ölmüş sandığı sürecin akışından ESKİ sayıları
 * "Live" rozetiyle okumaya devam ediyordu.
 *
 * Kimlik zinciri BİLEREK atlanıyor (handleEvents doğrudan bağlanıyor):
 * ölçülen şey yetki değil, işleyicinin kapanışı duyup dönmesi.
 */
func TestShutdownDoesNotHangOnLiveStream(t *testing.T) {
	s := New(nil, nil, nil, slog.New(slog.DiscardHandler))
	s.UseEventBus(events.New(4, 8))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /events", s.handleEvents)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()

	// Akışı gerçekten aç: ilk paket ("retry:") gelene kadar bekle, ki
	// Shutdown çağrıldığında ETKİN bir bağlantı olduğundan emin olalım.
	// Bunu beklemeden ölçmek, testi kapanışın değil zamanlamanın
	// sınadığı bir teste dönüştürürdü.
	req, err := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/events", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	defer resp.Body.Close()
	if _, err := bufio.NewReader(resp.Body).ReadString('\n'); err != nil && err != io.EOF {
		t.Fatalf("ilk paket okunamadı: %v", err)
	}

	s.BeginShutdown()

	// Süre sınırı ürünün son çaresinden (5s) KISA: testin bittiğini
	// görmek yetmez, HIZLI bittiğini görmek gerek. Sınıra dayanan bir
	// kapanış, düzeltmenin çalışmadığı anlamına gelir.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("kapanış canlı akış yüzünden asıldı: %v", err)
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("kapanış %v sürdü; akış dönmesi söylenince hemen dönmeliydi", el)
	}
}
