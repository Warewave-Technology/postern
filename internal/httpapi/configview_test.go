package httpapi

/*
 * Salt-okunur yapılandırma ekranının kapıları.
 *
 * ⚠️ BU DOSYADAKİ İLK TEST, EKRANIN VAROLUŞ ŞARTI. Beyaz listeyi
 * koruyan şey burası: yapılandırmaya eklenen her yeni alan ya
 * gösterilenlerde ya gizlenenlerde olmak zorunda, yoksa test düşüyor.
 * Sınıflandırmayı zorunlu kılmayan bir ekran, bir gün eklenen
 * `smtp.password`ü de yazardı — ve bunu kimse fark etmezdi, çünkü ekran
 * çalışmaya devam ederdi.
 */

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/Warewave-Technology/postern/v2/internal/config"
)

func TestEveryConfigFieldIsClassifiedAsShownOrWithheld(t *testing.T) {
	var unclassified, both []string
	seen := map[string]bool{}
	for _, l := range configLeaves(reflect.ValueOf(config.Config{}), "") {
		seen[l.key] = true
		_, shown := shownConfig[l.key]
		_, hidden := hiddenConfig[l.key]
		switch {
		case shown && hidden:
			both = append(both, l.key)
		case !shown && !hidden:
			unclassified = append(unclassified, l.key)
		}
	}
	if len(unclassified) > 0 {
		t.Errorf("sınıflandırılmamış alan(lar): %v\n"+
			"Yeni bir yapılandırma alanı ya shownConfig'e (bir notla) ya "+
			"hiddenConfig'e (bir sebeple) yazılmalı.", unclassified)
	}
	if len(both) > 0 {
		t.Errorf("hem gösterilen hem gizlenen: %v", both)
	}

	// Ters yön: listede olup yapılandırmada olmayan anahtar, silinmiş bir
	// ayarın ekranda yaşamaya devam etmesi demek.
	for k := range shownConfig {
		if !seen[k] {
			t.Errorf("gösterilenlerde var, yapılandırmada yok: %q", k)
		}
	}
	for k := range hiddenConfig {
		if !seen[k] {
			t.Errorf("gizlenenlerde var, yapılandırmada yok: %q", k)
		}
	}
}

/*
 * ⚠️ SIRRIN KENDİSİ CEVABIN HİÇBİR YERİNDE GEÇMİYOR. Gizlenen alanların
 * ADI listeleniyor (yoksa operatör ayarın hiç yazılmadığını sanar), ama
 * değeri hiçbir alana sızmamalı — ne değer alanına, ne nota.
 */
func TestTheConfigViewNeverCarriesASecretValue(t *testing.T) {
	s, _ := dbServer(t)
	s.UseConfig(config.Config{
		Database: config.DatabaseConfig{DSN: "postgres://postern:hunter2@db/postern"},
		OIDC:     config.OIDCConfig{IssuerURL: "https://idp.example", ClientSecret: "s3cr3t-client"},
		HTTP:     config.HTTPConfig{Addr: ":8088"},
	}, "/etc/postern/config.yaml")

	r := httptest.NewRequest(http.MethodGet, "/api/admin/config", nil)
	w := httptest.NewRecorder()
	s.adminConfig(w, asAdmin(r))
	if w.Code != http.StatusOK {
		t.Fatalf("durum: %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, secret := range []string{"hunter2", "s3cr3t-client", "postgres://"} {
		if strings.Contains(body, secret) {
			t.Errorf("sır cevaba sızdı: %q\n%s", secret, body)
		}
	}

	var out struct {
		Path     string `json:"path"`
		Groups   []configGroup
		Withheld []configEntry
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Path != "/etc/postern/config.yaml" {
		t.Errorf("dosyanın yolu yazılmamış: %q", out.Path)
	}

	// Gizlenenler adıyla ve sebebiyle duruyor.
	names := map[string]string{}
	for _, e := range out.Withheld {
		names[e.Key] = e.Note
		if e.Value != "" {
			t.Errorf("gizlenen alan bir değer taşıyor: %+v", e)
		}
	}
	for _, k := range []string{"database.dsn", "oidc.client_secret"} {
		if names[k] == "" {
			t.Errorf("%s gizlenenlerde sebebiyle görünmüyor: %+v", k, out.Withheld)
		}
	}

	// Gösterilen bir değer gerçekten geliyor.
	var addr string
	for _, g := range out.Groups {
		for _, e := range g.Entries {
			if e.Key == "http.addr" {
				addr = e.Value
			}
		}
	}
	if addr != ":8088" {
		t.Errorf("http.addr okunmuyor: %q", addr)
	}
}

/*
 * ⚠️ YAZILMAMIŞ İLE BOŞ AYRI CÜMLELER. İşaretçi alan "yazılmadı,
 * varsayılan geçerli"; boş dizge ise "yazıldı ve boş". İkisini aynı
 * göstermek, operatöre yazdığı bir ayarı yazmamış gibi okutur.
 */
func TestUnsetAndEmptyReadDifferently(t *testing.T) {
	yes := true
	s, _ := dbServer(t)
	s.UseConfig(config.Config{Auth: config.AuthConfig{PublicKeyLogin: &yes}}, "c.yaml")

	r := httptest.NewRequest(http.MethodGet, "/api/admin/config", nil)
	w := httptest.NewRecorder()
	s.adminConfig(w, asAdmin(r))

	var out struct{ Groups []configGroup }
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	got := map[string]string{}
	for _, g := range out.Groups {
		for _, e := range g.Entries {
			got[e.Key] = e.Value
		}
	}
	if got["auth.public_key_login"] != "true" {
		t.Errorf("yazılmış işaretçi: %q", got["auth.public_key_login"])
	}
	if got["auth.totp_window"] != "(default)" {
		t.Errorf("yazılmamış işaretçi: %q", got["auth.totp_window"])
	}
	if got["http.addr"] != "(not set)" {
		t.Errorf("yazılmış ama boş dizge: %q", got["http.addr"])
	}
}

/* Yapılandırma bağlanmadıysa rota hiç kurulmuyor; kurulduysa kapıların
 * arkasında. */
func TestTheConfigRouteIsOnlyWiredWhenThereIsAConfig(t *testing.T) {
	s, _ := dbServer(t)
	mux := http.NewServeMux()
	s.registerConfigRoutes(mux)
	req := httptest.NewRequest(http.MethodGet, "/api/admin/config", nil)
	if _, pattern := mux.Handler(req); pattern != "" {
		t.Errorf("yapılandırma yokken rota kuruldu: %q", pattern)
	}

	s.UseConfig(config.Config{}, "c.yaml")
	mux = http.NewServeMux()
	s.registerConfigRoutes(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code == http.StatusOK {
		t.Errorf("oturumsuz istek geçti: %d", w.Code)
	}
}

/*
 * ⚠️ HER BÖLÜMÜN OKUNUR BİR BAŞLIĞI VAR. "target_probe" bir yapı adı,
 * bir başlık değil; aradığı ayarı bilmeyen biri ham anahtara bakarak
 * doğru tabloyu bulamaz. Yeni bir bölüm eklendiğinde bu test, başlığın
 * da yazılmasını hatırlatıyor.
 */
func TestEveryConfigGroupHasAReadableTitle(t *testing.T) {
	for _, l := range configLeaves(reflect.ValueOf(config.Config{}), "") {
		if _, shown := shownConfig[l.key]; !shown {
			continue
		}
		group := "general"
		if i := strings.Index(l.key, "."); i >= 0 {
			group = l.key[:i]
		}
		if groupTitles[group] == "" {
			t.Errorf("başlıksız bölüm: %q (anahtar %q)", group, l.key)
		}
	}
}
