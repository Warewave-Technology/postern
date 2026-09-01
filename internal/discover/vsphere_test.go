package discover

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

/*
 * fakeVC, vCenter REST API'sinin keşfin kullandığı uçlarını taklit
 * eder.
 *
 * ⚠️ GERÇEK BİR vCenter'A KARŞI ÇALIŞTIRILMADI ve bunu yazmak önemli:
 * buradaki doğrulama, VMware'in BELGELEDİĞİ cevap şekillerine karşı.
 * Şekiller doğruysa istemci doğru; şekil değişirse bu testler
 * yakalamaz. Proxmox tarafı da aynı seviyede — fark, orada şekilleri
 * çalışan bir kurulumdan görebilmemiz.
 */
func fakeVC(t *testing.T, sessions *atomic.Int32) *httptest.Server {
	t.Helper()
	const sessionID = "sess-123"

	mux := http.NewServeMux()
	mux.HandleFunc("/api/session", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			u, p, ok := r.BasicAuth()
			if !ok || u != "svc@vsphere.local" || p != "gizli" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			sessions.Add(1)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(sessionID)
		case http.MethodDelete:
			sessions.Add(-1)
			w.WriteHeader(http.StatusNoContent)
		}
	})

	guard := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("vmware-api-session-id") != sessionID {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}

	mux.HandleFunc("/api/vcenter/vm", guard(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[
			{"vm":"vm-101","name":"web-01","power_state":"POWERED_ON"},
			{"vm":"vm-102","name":"db-01","power_state":"POWERED_ON"},
			{"vm":"vm-103","name":"kapali","power_state":"POWERED_OFF"},
			{"vm":"vm-104","name":"etiketsiz","power_state":"POWERED_ON"}
		]`))
	}))
	mux.HandleFunc("/api/cis/tagging/tag", guard(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`["tag-a","tag-b","tag-c"]`))
	}))
	mux.HandleFunc("/api/cis/tagging/tag/", guard(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "tag-a"):
			_, _ = w.Write([]byte(`{"name":"ops","category_id":"cat-role"}`))
		case strings.HasSuffix(r.URL.Path, "tag-b"):
			_, _ = w.Write([]byte(`{"name":"dba","category_id":"cat-role"}`))
		default:
			// Başka kategoriden bir etiket: rol çıkarmayı etkilememeli.
			_, _ = w.Write([]byte(`{"name":"prod","category_id":"cat-env"}`))
		}
	}))
	mux.HandleFunc("/api/cis/tagging/category/", guard(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "cat-role") {
			_, _ = w.Write([]byte(`{"name":"role"}`))
			return
		}
		_, _ = w.Write([]byte(`{"name":"env"}`))
	}))
	mux.HandleFunc("/api/cis/tagging/tag-association", guard(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[
			{"object_id":{"id":"vm-101","type":"VirtualMachine"},"tag_ids":["tag-a","tag-c"]},
			{"object_id":{"id":"vm-102","type":"VirtualMachine"},"tag_ids":["tag-b"]},
			{"object_id":{"id":"vm-104","type":"VirtualMachine"},"tag_ids":["tag-c"]}
		]`))
	}))
	mux.HandleFunc("/api/vcenter/vm/vm-101/guest/identity",
		guard(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"ip_address":"10.0.0.5"}`))
		}))
	mux.HandleFunc("/api/vcenter/vm/vm-102/guest/identity",
		guard(func(w http.ResponseWriter, _ *http.Request) {
			// ⚠️ Döngü adresi: elenmeli, makine ADINA düşülmeli.
			_, _ = w.Write([]byte(`{"ip_address":"127.0.0.1"}`))
		}))
	mux.HandleFunc("/api/vcenter/vm/vm-104/guest/identity",
		guard(func(w http.ResponseWriter, _ *http.Request) {
			// VMware Tools yok: 404. Keşif düşmemeli.
			w.WriteHeader(http.StatusNotFound)
		}))

	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newVC(t *testing.T, srv *httptest.Server) *VSphere {
	t.Helper()
	v, err := NewVSphere(VSphereConfig{
		BaseURL: srv.URL, Username: "svc@vsphere.local", Password: "gizli",
		CAFile: caFileFor(t, srv),
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

/*
 * ⚠️ vSPHERE ETİKETİ GERÇEKTEN ANAHTAR/DEĞER: kategori anahtar, etiket
 * değer. Yine de Proxmox'la AYNI biçimde ("kategori=etiket") dışarı
 * veriliyor ki rol çıkarma mantığı tek olsun — iki kaynak için iki
 * ayrı mantık, ikisinin zamanla ayrışması demekti.
 */
func TestVSphereMachines(t *testing.T) {
	var sessions atomic.Int32
	srv := fakeVC(t, &sessions)
	v := newVC(t, srv)

	ms, err := v.Machines(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 4 {
		t.Fatalf("%d makine: %+v", len(ms), ms)
	}

	by := map[string]Machine{}
	for _, m := range ms {
		by[m.Name] = m
	}

	if role, tagged := RoleFromTags(by["web-01"].Tags, "role"); role != "ops" || !tagged {
		t.Errorf("web-01 rolü = %q %v (etiketler %v)", role, tagged, by["web-01"].Tags)
	}
	if role, _ := RoleFromTags(by["db-01"].Tags, "role"); role != "dba" {
		t.Errorf("db-01 rolü = %q", role)
	}
	// ⚠️ Başka kategorideki etiket rol vermiyor: yalnızca env=prod
	// taşıyan makine unknown'a gidiyor.
	if role, tagged := RoleFromTags(by["etiketsiz"].Tags, "role"); role != UnknownRole || tagged {
		t.Errorf("etiketsiz makine = %q %v (etiketler %v)",
			role, tagged, by["etiketsiz"].Tags)
	}

	if by["web-01"].Host != "10.0.0.5" {
		t.Errorf("adres = %q", by["web-01"].Host)
	}
	// Döngü adresi elendi.
	if by["db-01"].Host != "" {
		t.Errorf("döngü adresi kabul edildi: %q", by["db-01"].Host)
	}
	// VMware Tools olmayan makine keşfi DÜŞÜRMEDİ.
	if by["etiketsiz"].Host != "" {
		t.Errorf("araçsız makinede adres = %q", by["etiketsiz"].Host)
	}
	// Kapalı makineye adres sorulmadı.
	if by["kapali"].Running || by["kapali"].Host != "" {
		t.Errorf("kapalı makine = %+v", by["kapali"])
	}

	/*
	 * ⚠️ OTURUM KAPATILDI.
	 *
	 * Her koşuda vCenter'da bir oturum bırakmak, sunucuda birikip
	 * yönetici konsolunu kirletir — ve orada duran her oturum, süresi
	 * dolana kadar KULLANILABİLİR bir kimliktir.
	 */
	if n := sessions.Load(); n != 0 {
		t.Fatalf("%d oturum açık kaldı", n)
	}
}

// Düz http reddediliyor: oturum kimliği her istekte başlıkta gidiyor.
func TestVSphereRefusesPlainHTTP(t *testing.T) {
	_, err := NewVSphere(VSphereConfig{
		BaseURL: "http://vc.example", Username: "u", Password: "p",
	})
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("düz http kabul edildi: %v", err)
	}
}

func TestVSphereRequiresCredentials(t *testing.T) {
	for _, c := range []VSphereConfig{
		{BaseURL: "https://vc", Password: "p"},
		{BaseURL: "https://vc", Username: "u"},
		{Username: "u", Password: "p"},
	} {
		if _, err := NewVSphere(c); err == nil {
			t.Errorf("eksik alanla kabul edildi: %+v", c)
		}
	}
}

// TLS doğrulaması varsayılan olarak AÇIK.
func TestVSphereVerifiesTLSByDefault(t *testing.T) {
	var sessions atomic.Int32
	srv := fakeVC(t, &sessions)

	v, err := NewVSphere(VSphereConfig{
		BaseURL: srv.URL, Username: "svc@vsphere.local", Password: "gizli",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Machines(context.Background()); err == nil {
		t.Fatal("kendi imzaladığı sertifika doğrulanmadan kabul edildi")
	}
}

/*
 * ⚠️ ESKİ vCenter SESSİZCE YANLIŞ DAVRANMIYOR.
 *
 * /api yolları 7.0 U2 ile geldi; öncesinde /rest var ve şekilleri
 * farklı. 404'ü "makine yok" diye okumak, boş bir envanteri başarı
 * gibi gösterirdi.
 */
func TestVSphereSaysWhenTheVersionIsTooOld(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
	t.Cleanup(srv.Close)

	v, err := NewVSphere(VSphereConfig{
		BaseURL: srv.URL, Username: "u", Password: "p", CAFile: caFileFor(t, srv),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Machines(context.Background())
	if err == nil || !strings.Contains(err.Error(), "7.0 U2") {
		t.Fatalf("sürüm uyarısı yok: %v", err)
	}
}
