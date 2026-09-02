package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

/*
 * ⚠️ /healthz VERİTABANINA DOKUNMAMALI.
 *
 * Tek bir "sağlık ucu veritabanını yoklasın" tasarımı, kimlik
 * istemeyen bir yolu doğrudan veritabanına bağlamak olurdu. Bu test,
 * birinin ileride "aynı şey" diyerek ikisini birleştirmesini
 * engelliyor: store nil iken bile 200 dönmeli.
 */
func TestHealthzTouchesNothing(t *testing.T) {
	// store YOK: dokunsaydı panik ederdi.
	s := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	w := httptest.NewRecorder()
	s.handleHealthz(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("durum = %d, 200 bekleniyordu", w.Code)
	}
	if !strings.Contains(w.Body.String(), "ok") {
		t.Errorf("gövde = %q", w.Body.String())
	}
	// Vekil önbelleğe alırsa ölmüş bir süreç ayakta görünür.
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", w.Header().Get("Cache-Control"))
	}
}

// pinger, yoklama sayısını sayan sahte depo.
type pinger struct {
	mu    sync.Mutex
	calls int
	err   error
	delay time.Duration
}

func (p *pinger) Ping(ctx context.Context) error {
	p.mu.Lock()
	p.calls++
	d, err := p.delay, p.err
	p.mu.Unlock()
	if d > 0 {
		time.Sleep(d)
	}
	return err
}

func (p *pinger) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

/*
 * ⚠️ KİMLİKSİZ UÇ VERİTABANINI YORAMAMALI.
 *
 * Bu, ucun kimlik istememesinin bedelini bağlayan tek şey: istek hızı
 * ne olursa olsun veritabanına giden yük sabit. Önbellek burada hız
 * için değil, GÜVENLİK için.
 */
func TestReadyzRateLimitsTheDatabase(t *testing.T) {
	p := &pinger{}
	s := newHealthServer(t, p)

	for range 50 {
		w := httptest.NewRecorder()
		s.handleReadyz(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("durum = %d", w.Code)
		}
	}

	if n := p.count(); n != 1 {
		t.Errorf("50 istek %d yoklama üretti — kimliksiz uç veritabanını yorabilir", n)
	}
}

// Aynı anda gelen istekler de tek yoklama açmalı.
func TestReadyzCollapsesConcurrentProbes(t *testing.T) {
	p := &pinger{delay: 50 * time.Millisecond}
	s := newHealthServer(t, p)

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			s.handleReadyz(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		}()
	}
	wg.Wait()

	if n := p.count(); n > 1 {
		t.Errorf("eşzamanlı istekler %d yoklama açtı — önbellek boşken sürü etkisi", n)
	}
}

/*
 * ⚠️ HATA SEBEBİ GÖVDEYE YAZILMIYOR.
 *
 * Uç kimlik istemiyor; veritabanı hata metni DSN parçaları ya da ana
 * makine adları taşıyabiliyor. Operatörün bakacağı yer log.
 */
func TestReadyzSaysNotReadyWithoutTheReason(t *testing.T) {
	p := &pinger{err: errFake("dial tcp 10.1.2.3:5432: connection refused")}
	s := newHealthServer(t, p)

	w := httptest.NewRecorder()
	s.handleReadyz(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("durum = %d, 503 bekleniyordu", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "10.1.2.3") || strings.Contains(body, "5432") ||
		strings.Contains(body, "dial") {
		t.Errorf("iç ayrıntı gövdeye sızdı: %q", body)
	}
	if !strings.Contains(body, "not ready") {
		t.Errorf("gövde = %q", body)
	}
}

type errFake string

func (e errFake) Error() string { return string(e) }

/*
 * ⚠️ İSTEMCİNİN VAZGEÇMESİ SONUCU BOZMAMALI.
 *
 * Yoklama isteğin bağlamına bağlı olsaydı, bağlantıyı kesen bir
 * istemci önbelleğe "hata" yazdırırdı ve sağlıklı bir bastion bir
 * saniye boyunca hasta görünürdü — kendi kendine yaratılan bir kesinti.
 */
func TestReadyzSurvivesAClientThatGivesUp(t *testing.T) {
	p := &pinger{}
	s := newHealthServer(t, p)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // istemci gitti

	if err := s.dbReady(ctx); err != nil {
		t.Fatalf("iptal edilmiş bağlam yoklamayı bozdu: %v", err)
	}
}

// newHealthServer, sahte yoklayıcıyla bir sunucu kurar.
func newHealthServer(t *testing.T, p *pinger) *Server {
	t.Helper()
	return &Server{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		ping:   p.Ping,
	}
}
