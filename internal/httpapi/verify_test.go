package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/verify"
)

/*
 * ⚠️ BU DOSYADAKİ İDDİALARIN ORTAK TEMASI: HAK EDİLMEMİŞ ONAY.
 *
 * Göç 034'ün panelden istediği şey "doğrulandı" ile "doğrulanamaz"ı ayrı
 * göstermek. Ayrımı kaybeden her yol, hiç doğrulanmamış bir kaydı
 * doğrulanmış gösterir — ve o, hiçbir şey göstermemekten kötüdür.
 */

func verifyServer(t *testing.T) *Server {
	t.Helper()

	return &Server{
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		verifySlots: make(chan struct{}, verifySlots),
	}
}

/*
 * ⚠️ SÜREN OTURUM "MÜHÜRSÜZ" DEĞİL.
 *
 * Zincir başı oturum KAPANIRKEN yazılıyor. Açık bir oturumu mühürsüz diye
 * göstermek, çalışan her kabuğu şüpheli gösterirdi — ve panelde en çok
 * görülen satırlar onlar.
 */
func TestOpenSessionIsInProgressNotUnsealed(t *testing.T) {
	s := verifyServer(t)
	r := httptest.NewRequest("POST", "/", nil)

	got := s.verifyRecording(r, model.Session{
		ID: "x", RecordingPath: "/tmp/x.cast",
		// EndedAt sıfır → oturum açık.
	})

	if got.Local != verifyRunning {
		t.Fatalf("durum = %q, %q bekleniyordu", got.Local, verifyRunning)
	}
	if got.Local == verifyUnsealed || got.Local == verifyChanged {
		t.Error("açık oturum şüpheli gösteriliyor")
	}
	if !strings.Contains(got.Detail, "when it closes") {
		t.Errorf("sebep söylenmiyor: %q", got.Detail)
	}
}

/*
 * ⚠️ ZİNCİRİ OLMAYAN KAYIT BİR ALARM DEĞİL.
 *
 * Göç 034'ten önce kapanmış her oturumun başı boş. İlk yükseltmede bu,
 * geçmişin TAMAMI demek; panel onu "bozuk" gibi çizerse operatör
 * kimsenin yapmadığı bir şey için alarma geçer.
 */
func TestSessionWithoutAChainIsUnsealedNotChanged(t *testing.T) {
	s := verifyServer(t)
	r := httptest.NewRequest("POST", "/", nil)

	got := s.verifyRecording(r, model.Session{
		ID: "x", RecordingPath: "/tmp/x.cast",
		EndedAt: time.Unix(1757066400, 0),
	})

	if got.Local != verifyUnsealed {
		t.Fatalf("durum = %q", got.Local)
	}
	if got.Local == verifyChanged {
		t.Fatal("zinciri olmayan kayıt 'değişmiş' diye raporlandı")
	}
	// Sebep İKİ olasılığı da söylemeli: eski kayıt ya da yeni kapanmış.
	if !strings.Contains(got.Detail, "before chains existed") {
		t.Errorf("sebep: %q", got.Detail)
	}
}

// Kaydı olmayan oturum ayrı bir durum: "kayıt yok" ile "zincir yok"
// karıştırılırsa, hiç kaydedilmemiş bir oturum mühürsüz görünür.
func TestSessionWithoutARecordingIsItsOwnState(t *testing.T) {
	s := verifyServer(t)
	got := s.verifyRecording(httptest.NewRequest("POST", "/", nil),
		model.Session{ID: "x", EndedAt: time.Unix(1757066400, 0)})

	if got.Local != verifyNotStored {
		t.Fatalf("durum = %q, %q bekleniyordu", got.Local, verifyNotStored)
	}
}

/*
 * ⚠️ İKİ EKSEN AYRI KALMALI.
 *
 * Yerel zincirin tutması ile arşivin onaylaması iki ayrı iddia. Tek bir
 * alanda birleştirmek, "yerel tuttu ama arşiv çelişiyor" durumunu
 * gizlerdi — ki o, en güçlü kurcalama işareti.
 */
func TestLocalAndOffBoxAreSeparateFields(t *testing.T) {
	s := verifyServer(t)
	s.archiveDest.Endpoint = "" // arşiv kapalı

	got := s.verifyRecording(httptest.NewRequest("POST", "/", nil),
		model.Session{ID: "x", EndedAt: time.Unix(1757066400, 0)})

	if got.OffBox.State != verify.OffBoxUnchecked.String() {
		t.Errorf("kutu dışı durumu = %q", got.OffBox.State)
	}
	// Yerel sonuç kutu dışı sonucu EZMEMELİ ve tersi de.
	if got.Local == got.OffBox.State {
		t.Error("iki eksen aynı alana çökmüş görünüyor")
	}
}

/*
 * ⚠️ YUVA DOLUYKEN BEKLENMİYOR, REDDEDİLİYOR.
 *
 * Beklemek, isteği tutan goroutine'i ve bağlantıyı da tutmak demek; bu
 * sunucuda WriteTimeout bilerek yok (web terminali saatlerce açık
 * kalıyor), yani biriken istekleri kesen hiçbir şey olmazdı.
 */
func TestVerifyRefusesWhenAllSlotsAreBusy(t *testing.T) {
	s := verifyServer(t)
	for range verifySlots {
		s.verifySlots <- struct{}{}
	}

	rec := httptest.NewRecorder()
	s.handleVerifyRecording(rec, httptest.NewRequest("POST", "/api/admin/sessions/x/verify", nil))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("durum %d, 429 bekleniyordu", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "try again") {
		t.Errorf("ne yapılacağı söylenmiyor: %s", rec.Body.String())
	}
}

/*
 * Cevap ALANLARININ adı sözleşme: panel bunlara bakıyor ve bir alanın
 * sessizce adı değişirse ekran "bilinmeyen durum" çizer.
 */
func TestVerifyResultShape(t *testing.T) {
	s := verifyServer(t)
	got := s.verifyRecording(httptest.NewRequest("POST", "/", nil),
		model.Session{ID: "x", EndedAt: time.Unix(1757066400, 0)})

	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"local", "off_box"} {
		if _, ok := m[want]; !ok {
			t.Errorf("cevapta %q alanı yok: %s", want, b)
		}
	}
	off, _ := m["off_box"].(map[string]any)
	if _, ok := off["state"]; !ok {
		t.Errorf("off_box.state yok: %s", b)
	}
}
