package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/events"
	"github.com/Warewave-Technology/postern/internal/store"
)

/*
 * ⚠️ KAPATILAN HESABIN AÇIK OLAY AKIŞI SÜRMEMELİ.
 *
 * Yetki zinciri (requireSession → requireAdmin → sameOrigin) yalnızca
 * BAĞLANIRKEN koşuyor; sonrası sonsuz bir döngü ve nabız, vekillerin
 * bağlantıyı düşürmesini de engelliyor. Ölçülen sonuç: `state =
 * deleted` yapılmış bir yöneticinin açık bıraktığı sekme, kimin hangi
 * hedefe hangi adresten hangi OS kullanıcısı olarak bağlandığını CANLI
 * almaya devam ediyordu. Aynı çerezle YENİ bir istek 401 alıyor, akış
 * almıyordu — ve akışı ne panel ne CLI düşürebiliyordu.
 *
 * SSH tarafında aynı sınıf her kanalda soruluyor (proxy.Open), panelde
 * her istekte (accountStillOpen). Uzun ömürlü akış ikisinin arasından
 * geçiyordu.
 */
func TestLiveEventStreamStopsWhenTheAccountIsDeleted(t *testing.T) {
	s, db := dbServer(t)
	ctx := context.Background()

	s.bus = events.New(8, 4)
	s.closing = make(chan struct{})

	// Nabız aralığı hesabın yeniden sorulduğu yer; testin 20 saniye
	// beklemesi gerekmesin.
	eski := heartbeatEvery
	heartbeatEvery = 100 * time.Millisecond
	t.Cleanup(func() { heartbeatEvery = eski })

	if _, err := db.CreateUser(ctx, "ayse", "ayse@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}
	id, err := db.AccountID(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}

	// handleEvents'in gördüğü şekliyle bir istek: middleware kimliği
	// context'e koymuş oluyor.
	rctx := context.WithValue(context.Background(), ctxUser, "ayse")
	rctx = context.WithValue(rctx, ctxAccountID, id)
	rctx, cancel := context.WithTimeout(rctx, 30*time.Second)
	defer cancel()

	r := httptest.NewRequest(http.MethodGet, "/api/admin/events", nil).WithContext(rctx)
	w := newFlushRecorder()

	done := make(chan struct{})
	go func() {
		s.handleEvents(w, r)
		close(done)
	}()

	// Akış kurulsun.
	waitFor(t, func() bool { return strings.Contains(w.body(), "retry:") },
		"akış hiç açılmadı")

	// ⚠️ İşten çıkarmanın tek kolu. Akış AÇIK kalıyor.
	if serr := db.SetAccountState(ctx, "ayse", store.StateDeleted); serr != nil {
		t.Fatal(serr)
	}

	select {
	case <-done:
		// Doğru cevap: akış kendini kapattı.
	case <-time.After(15 * time.Second):
		t.Fatal("kapatılmış hesabın canlı olay akışı sürüyor — ayrılan " +
			"yönetici kimin nereye bağlandığını canlı izlemeye devam ediyor " +
			"ve akışı ne panel ne CLI düşürebiliyor")
	}
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(msg)
}

// flushRecorder, SSE akışı için http.Flusher uygulayan ve gövdesi
// eşzamanlı okunabilen bir kaydedici. httptest.ResponseRecorder
// Flusher'ı uyguluyor ama gövdesini kilitsiz veriyor; akış ayrı bir
// goroutine'de yazdığı için burada kendi kilidimiz var.
type flushRecorder struct {
	mu   sync.Mutex
	buf  strings.Builder
	code int
	hdr  http.Header
}

func newFlushRecorder() *flushRecorder {
	return &flushRecorder{hdr: http.Header{}, code: 200}
}

func (f *flushRecorder) Header() http.Header { return f.hdr }
func (f *flushRecorder) WriteHeader(c int)   { f.code = c }
func (f *flushRecorder) Flush()              {}

func (f *flushRecorder) Write(b []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.buf.Write(b)
}

func (f *flushRecorder) body() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.buf.String()
}
