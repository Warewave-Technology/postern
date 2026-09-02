package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/warewave/postern/internal/config"

	"github.com/warewave/postern/internal/archive"
)

/*
 * ⚠️ ARŞİV ANAHTARLARI GENEL AYARLAR YOLUNDAN GEÇMEMELİ.
 *
 * Oradaki sınıflandırma fail-open: haritada olmayan bir anahtar
 * sessizce "sır değil" sayılıp DÜZ METİN saklanıyor
 * (federation.go:210). Bu test, birinin ileride "kolay olsun" diye
 * arşiv anahtarlarını knownSettingKeys'e eklemesini engelliyor —
 * o an gizli anahtar açık metne düşerdi ve cevap 200 olurdu.
 */
func TestArchiveKeysAreNotAcceptedByTheGenericSettingsPath(t *testing.T) {
	for _, k := range []string{archive.KeyAccessKeyID, archive.KeySecretAccessKey} {
		if _, allowed := knownSettingKeys[k]; allowed {
			t.Errorf("%q genel ayarlar yolundan kabul ediliyor — "+
				"fail-open sınıflandırma yüzünden sır düz metne düşebilir", k)
		}
	}
}

/*
 * ⚠️ SIRRIN ADI, "sır olmayan" yarımdan AYIRT EDİLEBİLİR OLMALI.
 *
 * İkisi de aynı önekte duruyor ve biri mühürleniyor. Adların
 * karışması, yanlış yarımın mühürlenmesi demek olurdu.
 */
func TestArchiveKeyNamesAreDistinct(t *testing.T) {
	if archive.KeyAccessKeyID == archive.KeySecretAccessKey {
		t.Fatal("iki anahtar aynı ada sahip")
	}
	if archive.KeySecretAccessKey == "" || archive.KeyAccessKeyID == "" {
		t.Fatal("anahtar adı boş")
	}
}

/*
 * ⚠️ KORUMA SUNUCUDA, ARAYÜZDE DEĞİL.
 *
 * Panel host kimliği kullanılıyorken formu çizmiyor — ama gizlemek bir
 * yetki kontrolü değil. Bu deponun kendi kuralı (adminAddKey'deki nota
 * bak): uç açık kalsaydı curl ile yazılabilir ve host'un koyduğu
 * anahtar sessizce gölgelenebilirdi.
 *
 * Bu testi bir mutasyon yazdırdı: sunucudaki reddi kaldırdım, panel
 * testleri geçmeye devam etti.
 */
func TestArchiveCredentialRefusesWhenTheHostOwnsIt(t *testing.T) {
	s := &Server{
		archiveDest:       config.ArchiveConfig{Endpoint: "https://x", Bucket: "k"},
		archiveHostSecret: "host-tarafindan-verilmis",
		logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	body := `{"access_key_id":"AKIA","secret_access_key":"s"}`
	req := httptest.NewRequest(http.MethodPut, "/api/admin/archive/credential",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.adminSetArchiveCredential(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("durum = %d, 409 bekleniyordu — host anahtarı panelden gölgelenebilir", w.Code)
	}
	if !strings.Contains(w.Body.String(), "from the host") {
		t.Errorf("sebep söylenmiyor: %s", w.Body.String())
	}
}

// Hedef yapılandırılmamışken kimlik kabul edilmemeli: yazılan bir
// anahtarın hiçbir işe yaramadığı, kaydedildikten sonra anlaşılırdı.
func TestArchiveCredentialRefusesWithoutADestination(t *testing.T) {
	s := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	req := httptest.NewRequest(http.MethodPut, "/api/admin/archive/credential",
		strings.NewReader(`{"access_key_id":"A","secret_access_key":"B"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.adminSetArchiveCredential(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("durum = %d, 409 bekleniyordu", w.Code)
	}
	if !strings.Contains(w.Body.String(), "no archive destination") {
		t.Errorf("sebep söylenmiyor: %s", w.Body.String())
	}
}

// Silme de aynı korumaya tabi: host'un anahtarı panelden düşürülemez.
func TestArchiveCredentialClearRefusesWhenTheHostOwnsIt(t *testing.T) {
	s := &Server{
		archiveHostSecret: "host",
		logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	req := httptest.NewRequest(http.MethodDelete, "/api/admin/archive/credential", nil)
	w := httptest.NewRecorder()

	s.adminClearArchiveCredential(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("durum = %d, 409 bekleniyordu", w.Code)
	}
}
