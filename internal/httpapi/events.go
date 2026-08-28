package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/warewave/postern/internal/events"
)

// heartbeatEvery, akışta hiçbir olay yokken gönderilen yorum satırının
// aralığı.
//
// Vekiller ve yük dengeleyiciler sessiz bağlantıları genelde 30-60
// saniyede kapatıyor. Yorum satırı ("\n:\n") istemci tarafında hiçbir
// olay üretmiyor ama bağlantıyı canlı tutuyor; olmadan panel dakikada
// bir sessizce kopup yeniden bağlanırdı.
const heartbeatEvery = 20 * time.Second

// UseEventBus, canlı olay akışını açar.
//
// Çağrılmazsa /api/admin/events rotası HİÇ kurulmaz — kapalı özellik,
// kapalı yüzey. Panel de akışı açamayınca "live" yerine "polling"
// diyor, sessizce boş bir akış göstermiyor.
func (s *Server) UseEventBus(b *events.Bus) { s.bus = b }

// registerEventRoutes, akış rotasını bağlar.
func (s *Server) registerEventRoutes(mux *http.ServeMux) {
	if s.bus == nil {
		return
	}
	// Diğer yönetim uçlarıyla AYNI zincir: oturum + admin + same-origin.
	// sameOrigin Sec-Fetch-Site'a bakıyor ve tarayıcı bunu EventSource
	// istekleri için de damgalıyor, yani akış zincirden düşmüyor.
	admin := func(h http.HandlerFunc) http.Handler {
		return noStore(s.requireSession(s.requireAdmin(s.sameOrigin(h))))
	}
	mux.Handle("GET /api/admin/events", admin(s.handleEvents))
	mux.Handle("GET /api/admin/events/stats", admin(s.handleLiveStats))
}

// handleEvents, Server-Sent Events akışı.
//
// ⚠️ NEDEN SSE, WEBSOCKET DEĞİL: akış tek yönlü (sunucu → panel) ve
// EventSource, connect-src 'self' altında ek bir CSP izni istemiyor.
// WebSocket ikinci bir yükseltme yolu, ikinci bir Origin kontrolü ve
// ikinci bir kapatma protokolü demekti — tek yönlü bir sayaç akışı için
// fazlası.
//
// Akış çerezle yetkilendiği için siteler arası okunabilir mi diye
// bakıldı: EventSource başka bir kaynaktan açılabilir, ama Access-
// Control-Allow-Origin göndermediğimiz için CORS içeriği saldırgan
// sayfaya vermiyor. Üstüne sameOrigin katmanı da duruyor — tarayıcı
// Sec-Fetch-Site'ı EventSource isteklerinde de damgalıyor.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		// Akış yazılamıyorsa hemen söyle: yarım açık bir bağlantı
		// bırakmak, panelde "bağlı ama sessiz" görünürdü.
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	ch, cancel, ok := s.bus.Subscribe()
	if !ok {
		// Kapasite dolu. 503 + Retry-After: panel bunu görüp yoklamaya
		// düşüyor, boş bir akışa bakıp "hiçbir şey olmuyor" demiyor.
		w.Header().Set("Retry-After", "30")
		http.Error(w, "too many live listeners", http.StatusServiceUnavailable)
		return
	}
	defer cancel()

	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Connection", "keep-alive")
	// Vekilin arabelleğe almasını engelle: nginx varsayılanı akışı
	// tamponlayıp olayları toplu gönderiyor, "canlı" olmaktan çıkarıyor.
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	// İlk paket hemen: panel bağlantının kurulduğunu ilk olayı beklemeden
	// bilsin (ilk olay saatler sonra gelebilir).
	fmt.Fprintf(w, "retry: 3000\n\n")
	flusher.Flush()

	ticker := time.NewTicker(heartbeatEvery)
	defer ticker.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return

		case e := <-ch:
			b, err := json.Marshal(e)
			if err != nil {
				// Tek bir olayın serileşmemesi akışı düşürmemeli.
				s.logger.Error("event encode failed", "error", err)
				continue
			}
			// Olay adı türün kendisi: istemci addEventListener ile
			// süzebilsin diye. Veri tek satır — JSON'da ham yeni satır
			// olamayacağı için SSE çerçevesi bozulmuyor.
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Kind, b)
			flusher.Flush()

		case <-ticker.C:
			fmt.Fprint(w, ": keep-alive\n\n")
			flusher.Flush()
		}
	}
}

// handleLiveStats, akışın kendi sağlığı.
//
// Kaç dinleyici var ve kaç olay DÜŞTÜ. İkincisi önemli: eksik bir akışa
// "tam" diye bakmak, olmamış saymaktır.
func (s *Server) handleLiveStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.bus.Stats())
}
