package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/warewave/postern/internal/store"
)

func quietServer() *Server {
	return &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

/*
 * ⚠️ ROTA GERÇEKTEN BAĞLI MI.
 *
 * Bu deponun tekrar eden arızası tam olarak bu: yazılmış, testi olan ve
 * HİÇBİR YERDEN ÇAĞRILMAYAN kod. store.FileHistory'nin kendisi ilk
 * günden test ediliyordu; eksik olan onu dışarı açan satırdı. Handler'ı
 * doğrudan çağıran bir test, o satır silinse bile geçmeye devam ederdi.
 */
func TestFileHistoryRouteIsRegistered(t *testing.T) {
	mux := http.NewServeMux()
	quietServer().registerAdminRoutes(mux)

	req := httptest.NewRequest(http.MethodGet,
		"/api/admin/files?path=/etc/shadow", nil)
	_, pattern := mux.Handler(req)
	if pattern != "GET /api/admin/files" {
		t.Fatalf("rota kayıtlı değil: eşleşen desen %q", pattern)
	}
}

/*
 * ⚠️ ADMIN ZİNCİRİNİN İÇİNDE.
 *
 * Bir yolun geçmişi BAŞKALARININ ne yaptığını gösteriyor. Uç, oturum
 * kontrolünün dışında kalsaydı, kimliksiz bir istek dosya adlarıyla
 * birlikte kim-ne-yaptı listesi çekebilirdi.
 */
func TestFileHistoryRefusesWithoutASession(t *testing.T) {
	mux := http.NewServeMux()
	quietServer().registerAdminRoutes(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/api/admin/files?path=/etc/shadow", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("kimliksiz istek %d aldı, 401 bekleniyordu: %s",
			rec.Code, rec.Body.String())
	}
}

/*
 * ⚠️ ÖLÇÜTSÜZ ARAMA "SONUÇ YOK" DEĞİL.
 *
 * Boş bir isteği boş bir listeyle cevaplamak, denetçiye aradığı
 * dosyaya dokunulmadığını söylemek olurdu — oysa henüz hiçbir şey
 * aranmadı. İkisi aynı ekrana çıkarsa, sorulmamış bir soru
 * cevaplanmış görünür.
 *
 * ⚠️ MESAJ DA ÖLÇÜLÜYOR, YALNIZCA DURUM KODU DEĞİL. store'un kendi
 * koruması da 400 üretiyor (savunma katmanı olarak orada duruyor), ama
 * metni "store.FileHistory: no criteria: store: invalid value" oluyor:
 * iç fonksiyon adını istemciye gösteren ve ne yapılacağını söylemeyen
 * bir cevap. Handler'ın koruması tam da bunun için var; testi yalnızca
 * koda bakarsa o koruma silindiğinde geçmeye devam eder.
 */
func TestFileHistoryRefusesAQueryWithNoCriteria(t *testing.T) {
	for _, q := range []string{"", "?path=", "?path=%20%20", "?user=&target="} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/admin/files"+q, nil)
		quietServer().adminFileHistory(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("%q → %d, 400 bekleniyordu", q, rec.Code)
			continue
		}
		body := rec.Body.String()
		if !strings.Contains(body, "at least one of path, user or target") {
			t.Errorf("%q → cevap ne istendiğini söylemiyor: %s", q, body)
		}
		if strings.Contains(body, "store.") {
			t.Errorf("%q → iç fonksiyon adı gövdeye sızdı: %s", q, body)
		}
	}
}

/*
 * ⚠️ AĞAÇ ARAMASI BİR YOL İSTİYOR.
 *
 * under=1'i sessizce yok sayıp kullanıcı süzgeciyle devam etmek,
 * operatöre sormadığı soruyu cevaplamak olurdu — ve cevap dolu
 * geleceği için yanlış olduğu anlaşılmazdı.
 */
func TestFileHistoryRefusesUnderWithoutAPath(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/api/admin/files?under=1&user=ayse", nil)
	quietServer().adminFileHistory(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("yolsuz ağaç araması %d aldı, 400 bekleniyordu: %s",
			rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "needs a path") {
		t.Errorf("sebep söylenmiyor: %s", rec.Body.String())
	}
}

// Anlamsız bir limit sessizce varsayılana düşmüyor: 5 yerine "beş"
// yazan istemci, istediğini aldığını sanmamalı.
func TestFileHistoryRefusesANonsenseLimit(t *testing.T) {
	for _, raw := range []string{"bes", "0", "-3"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet,
			"/api/admin/files?path=/x&limit="+raw, nil)
		quietServer().adminFileHistory(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("limit=%q → %d, 400 bekleniyordu", raw, rec.Code)
		}
	}
}

/*
 * ⚠️ TAVANI AŞAN LİMİT, `truncated`I YALANCI YAPMAMALI.
 *
 * store limiti sessizce kırpıyor. İstemcinin geçtiği sayıyı olduğu gibi
 * cevaba yazsaydık, limit=5000 diyen bir istemci 200 satır alır ve
 * "5000 istedim, 200 geldi, demek ki hepsi bu" diye okurdu — kesilmiş
 * bir denetim listesini tam sanmak, bu ekranın en pahalı hatası.
 */
func TestFileHistoryClampsTheLimitItReports(t *testing.T) {
	got, valid := historyLimit("5000")
	if !valid {
		t.Fatal("tavanı aşan limit reddedildi; kırpılması gerekiyordu")
	}
	if got != store.FileHistoryMaxLimit {
		t.Fatalf("limit = %d, tavan %d bekleniyordu",
			got, store.FileHistoryMaxLimit)
	}

	// Verilmeyen limit varsayılana düşüyor ve varsayılan da tavanı aşmıyor.
	if d, ok := historyLimit(""); !ok || d != store.FileHistoryDefaultLimit {
		t.Fatalf("varsayılan limit = %d/%v", d, ok)
	}
}
