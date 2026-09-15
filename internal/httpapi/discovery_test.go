package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/auth"
	"github.com/Warewave-Technology/postern/internal/discover"
	"github.com/Warewave-Technology/postern/internal/secret"
	"github.com/Warewave-Technology/postern/internal/store"
)

func discoveryServer(t *testing.T, withBox bool) (*Server, *store.Store) {
	t.Helper()
	s, db := dbServer(t)
	if withBox {
		box, err := secret.Init(filepath.Join(t.TempDir(), "secret.key"))
		if err != nil {
			t.Fatal(err)
		}
		db.UseSecretBox(box)
	}
	s.UseDiscovery(discover.NewService(db, slog.New(slog.NewTextHandler(io.Discard, nil)), nil))
	return s, db
}

// probeSource, test ucunun bağlandığı sahte platform.
type probeSource struct{ machines []discover.Machine }

func (probeSource) Name() string { return "fake" }
func (p probeSource) Machines(context.Context) ([]discover.Machine, error) {
	return p.machines, nil
}

/*
 * ⚠️ TEST UCU HİÇBİR ŞEY YAZMIYOR ve düzenlemede boş sır yerine KAYITLI
 * sırla bağlanıyor. Ulaşılamayan kaynak 502 ve sebep; geçersiz form 400.
 */
func TestTheSourceFormCanBeTestedBeforeItIsSaved(t *testing.T) {
	s, db := discoveryServer(t, true)
	ctx := context.Background()
	var gotSecret string
	s.UseDiscovery(discover.NewService(db, slog.New(slog.NewTextHandler(io.Discard, nil)),
		func(src store.DiscoverySource, secret string) (discover.Source, error) {
			gotSecret = secret
			if strings.Contains(src.URL, "down.example") {
				return nil, errors.New("dial tcp: connection refused")
			}
			return probeSource{machines: []discover.Machine{
				{Name: "web-01", Host: "10.0.0.5", Running: true, Tags: []string{"role_ops", "env_prod"}, Key: "qemu/101"},
				{Name: "db-01", Running: false, Tags: []string{"role_dba"}, Key: "qemu/102"},
				{Name: "other", Running: true, Key: "qemu/103"},
			}}, nil
		}))

	body := strings.Replace(sourceBody, `"tag_key":"role"`, `"tag_key":"role","name_pattern":"web-*, db-*"`, 1)
	w, out := callDiscovery(t, s, s.adminTestDiscoverySource, http.MethodPost, body, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("test: %d %s", w.Code, w.Body.String())
	}
	if out["machines"] != float64(3) || out["running"] != float64(2) || out["with_address"] != float64(1) ||
		out["matching"] != float64(2) || out["tagged"] != float64(2) || gotSecret != "gizli-jeton" {
		t.Errorf("sayımlar: %v (sır %q)", out, gotSecret)
	}
	if sources, _ := db.DiscoverySources(ctx); len(sources) != 0 {
		t.Fatalf("TEST KAYNAK YAZDI: %+v", sources)
	}

	// Düzenleme: id var, sır boş → kayıtlı sır.
	_, created := callDiscovery(t, s, s.adminCreateDiscoverySource, http.MethodPost, sourceBody, nil)
	id, _ := created["id"].(string)
	gotSecret = ""
	edit := strings.Replace(sourceBody, `"secret":"gizli-jeton"`, `"secret":"","id":"`+id+`"`, 1)
	if w, _ = callDiscovery(t, s, s.adminTestDiscoverySource, http.MethodPost, edit, nil); w.Code != http.StatusOK || gotSecret != "gizli-jeton" {
		t.Errorf("düzenlemede kayıtlı sır kullanılmadı: %d %q", w.Code, gotSecret)
	}
	// Yeni kaynakta sır boş → 400, bağlanma denenmiyor.
	gotSecret = "dokunulmadı"
	blank := strings.Replace(sourceBody, `"secret":"gizli-jeton"`, `"secret":""`, 1)
	if w, _ = callDiscovery(t, s, s.adminTestDiscoverySource, http.MethodPost, blank, nil); w.Code != http.StatusBadRequest || gotSecret != "dokunulmadı" {
		t.Errorf("sırsız test: %d %q", w.Code, gotSecret)
	}
	down := strings.Replace(sourceBody, "https://pve.example:8006", "https://down.example", 1)
	if w, _ = callDiscovery(t, s, s.adminTestDiscoverySource, http.MethodPost, down, nil); w.Code != http.StatusBadGateway ||
		!strings.Contains(w.Body.String(), "connection refused") {
		t.Errorf("ulaşılamayan kaynak: %d %s", w.Code, w.Body.String())
	}
}

func callDiscovery(t *testing.T, s *Server, h http.HandlerFunc, method, body string, path map[string]string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(method, "/api/admin/discovery", strings.NewReader(body))
	for k, v := range path {
		r.SetPathValue(k, v)
	}
	w := httptest.NewRecorder()
	h(w, asAdmin(r))
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

const sourceBody = `{"name":"lab","kind":"proxmox","url":"https://pve.example:8006","username":"postern@pve!d",` +
	`"secret":"gizli-jeton","tag_key":"role","port":22,"interval_seconds":3600}`

/*
 * ⚠️ SIR HİÇBİR CEVAPTA YOK — ekranın tek isteği dahil — ve boş sırla
 * güncelleme kayıtlı sırrı koruyor. Anahtarsız bastion'da kaynak
 * yazılamıyor ve ekran bunu formu açmadan söylüyor.
 */
func TestDiscoverySourceSecretsNeverLeaveTheServer(t *testing.T) {
	s, db := discoveryServer(t, true)

	w, out := callDiscovery(t, s, s.adminCreateDiscoverySource, http.MethodPost, sourceBody, nil)
	if w.Code != http.StatusOK || out["id"] == "" {
		t.Fatalf("kaynak açılmadı: %d %s", w.Code, w.Body.String())
	}
	id, _ := out["id"].(string)

	w, out = callDiscovery(t, s, s.adminDiscovery, http.MethodGet, "", nil)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "gizli") {
		t.Fatalf("SIR CEVAPTA: %d %s", w.Code, w.Body.String())
	}
	sources, _ := out["sources"].([]any)
	first, _ := sources[0].(map[string]any)
	if first["secret_set"] != true || first["name"] != "lab" || out["secrets_available"] != true {
		t.Errorf("liste: %v", out)
	}

	upd := strings.Replace(sourceBody, `"secret":"gizli-jeton",`, `"secret":"",`, 1)
	upd = strings.Replace(upd, `"name":"lab"`, `"name":"lab2"`, 1)
	if w, _ = callDiscovery(t, s, s.adminUpdateDiscoverySource, http.MethodPut, upd, map[string]string{"id": id}); w.Code != http.StatusOK {
		t.Fatalf("güncelleme: %d %s", w.Code, w.Body.String())
	}
	if plain, _ := db.DiscoverySourceSecret(t.Context(), id); plain != "gizli-jeton" {
		t.Errorf("boş sırla güncelleme sırrı değiştirdi: %q", plain)
	}
	upd = strings.Replace(sourceBody, `"gizli-jeton"`, `"yeni"`, 1)
	if w, _ = callDiscovery(t, s, s.adminUpdateDiscoverySource, http.MethodPut, upd, map[string]string{"id": id}); w.Code != http.StatusOK {
		t.Fatalf("güncelleme: %d %s", w.Code, w.Body.String())
	}
	if plain, _ := db.DiscoverySourceSecret(t.Context(), id); plain != "yeni" {
		t.Errorf("yeni sır yazılmadı: %q", plain)
	}

	// Geçersiz kaynak 400 ve gerekçe; defterde açılış ve güncelleme var.
	bad := strings.Replace(sourceBody, "https://", "http://", 1)
	if w, _ = callDiscovery(t, s, s.adminCreateDiscoverySource, http.MethodPost, bad, nil); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "https://") {
		t.Errorf("http adres: %d %s", w.Code, w.Body.String())
	}
	seen := map[string]bool{}
	logs, _ := db.AdminLog(t.Context(), 20)
	for _, e := range logs {
		seen[e.Action] = true
		if strings.Contains(e.Details, "gizli") || strings.Contains(e.Details, "yeni") && e.Action == "discovery.source_create" {
			t.Errorf("sır defterde: %+v", e)
		}
	}
	if !seen["discovery.source_create"] || !seen["discovery.source_update"] {
		t.Errorf("defter: %v", seen)
	}

	if w, _ = callDiscovery(t, s, s.adminDeleteDiscoverySource, http.MethodDelete, "", map[string]string{"id": id}); w.Code != http.StatusOK {
		t.Errorf("silme: %d", w.Code)
	}
	if w, _ = callDiscovery(t, s, s.adminDeleteDiscoverySource, http.MethodDelete, "", map[string]string{"id": id}); w.Code != http.StatusNotFound {
		t.Errorf("ikinci silme: %d", w.Code)
	}

	// Anahtarsız bastion: kaynak yazılamıyor, ekran söylüyor.
	s2, _ := discoveryServer(t, false)
	if w, _ = callDiscovery(t, s2, s2.adminCreateDiscoverySource, http.MethodPost, sourceBody, nil); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "secret key") {
		t.Errorf("anahtarsız kaynak: %d %s", w.Code, w.Body.String())
	}
	if _, out = callDiscovery(t, s2, s2.adminDiscovery, http.MethodGet, "", nil); out["secrets_available"] != false {
		t.Errorf("secrets_available: %v", out["secrets_available"])
	}
}

// Kayıt ucu: seçili makine hedef oluyor, rolü ve etiketiyle; olmayan rol
// 400 ve hiçbir şey yazılmıyor; yok sayma ucu değişen sayısını dönüyor.
func TestDiscoveredMachinesAreRegisteredThroughTheAPI(t *testing.T) {
	s, db := discoveryServer(t, true)
	ctx := context.Background()
	sid, err := db.CreateDiscoverySource(ctx, store.DiscoverySource{
		Name: "lab", Kind: "proxmox", URL: "https://pve:8006", Username: "a!b", TagKey: "role", Port: 22, Enabled: true, CreatedBy: "ops",
	}, "s")
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, _ := ssh.NewPublicKey(pub)
	now := time.Now()
	if err := db.SaveDiscoveredMachine(ctx, store.DiscoveredMachine{
		SourceID: sid, Ref: "qemu/101", Name: "web-01", Host: "10.0.0.5", Running: true, Role: "web", Tagged: true,
		HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))), LastSeen: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateRole(ctx, "ops"); err != nil {
		t.Fatal(err)
	}

	refs := `"machines":[{"source_id":"` + sid + `","ref":"qemu/101"}]`
	w, _ := callDiscovery(t, s, s.adminRegisterDiscovered, http.MethodPost, `{`+refs+`,"roles":["yok"]}`, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("olmayan rol: %d %s", w.Code, w.Body.String())
	}
	if _, err := db.Target(ctx, "web-01"); err == nil {
		t.Fatal("reddedilen istek hedef yazdı")
	}
	w, out := callDiscovery(t, s, s.adminRegisterDiscovered, http.MethodPost,
		`{`+refs+`,"roles":["ops"],"tag_roles":true,"labels":{"env":"prod"}}`, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("kayıt: %d %s", w.Code, w.Body.String())
	}
	results, _ := out["results"].([]any)
	first, _ := results[0].(map[string]any)
	if first["target"] != "web-01" || first["error"] != nil {
		t.Errorf("sonuç: %v", first)
	}
	if tgt, err := db.Target(ctx, "web-01"); err != nil || tgt.Host != "10.0.0.5" {
		t.Errorf("hedef: %+v (%v)", tgt, err)
	}
	if labels, _ := db.TargetLabels(ctx, "web-01"); labels["env"] != "prod" {
		t.Errorf("etiket: %v", labels)
	}
	_, out = callDiscovery(t, s, s.adminDiscovery, http.MethodGet, "", nil)
	machines, _ := out["machines"].([]any)
	m, _ := machines[0].(map[string]any)
	if m["target"] != "web-01" || m["fingerprint"] != ssh.FingerprintSHA256(sshPub) || m["role"] != "web" {
		t.Errorf("makine satırı: %v", m)
	}

	w, out = callDiscovery(t, s, s.adminIgnoreDiscovered, http.MethodPost, `{`+refs+`,"ignored":true}`, nil)
	if w.Code != http.StatusOK || out["changed"] != float64(1) {
		t.Errorf("yok sayma: %d %v", w.Code, out)
	}
	w, _ = callDiscovery(t, s, s.adminDiscoveryRuns, http.MethodGet, "", map[string]string{"id": "yok"})
	if w.Code != http.StatusNotFound {
		t.Errorf("olmayan kaynağın koşuları: %d", w.Code)
	}
}

/*
 * ⚠️ KAPILAR ROTADA: yönetici olmayan 403, çapraz köken 403 — hedef ve
 * rol bağı yazan uçlar için üçü de ölçülüyor. Hizmet bağlı değilse uç
 * hiç yok.
 */
func TestDiscoveryEndpointsAreBehindTheAdminAndSameOriginGates(t *testing.T) {
	db := migratedStore(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	bare := New(auth.NewOIDCHolder(), auth.NewLogins(auth.NewOIDCHolder()), db, logger)
	r := httptest.NewRequest(http.MethodGet, "/api/admin/discovery", nil)
	w := httptest.NewRecorder()
	bare.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("hizmet bağlı değilken uç var: %d", w.Code)
	}

	s := New(auth.NewOIDCHolder(), auth.NewLogins(auth.NewOIDCHolder()), db, logger)
	s.UseDiscovery(discover.NewService(db, logger, nil))
	ctx := t.Context()
	if _, err := db.CreateUser(ctx, "veli", "", "veli"); err != nil {
		t.Fatal(err)
	}
	token, err := s.createWebSession(ctx, "veli")
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path, site string) int {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(`{"machines":[]}`))
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		if site != "" {
			r.Header.Set("Sec-Fetch-Site", site)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w.Code
	}
	endpoints := []struct{ method, path string }{
		{http.MethodGet, "/api/admin/discovery"},
		{http.MethodPost, "/api/admin/discovery/sources"},
		{http.MethodPost, "/api/admin/discovery/test"},
		{http.MethodPost, "/api/admin/discovery/sources/yok/run"},
		{http.MethodPost, "/api/admin/discovery/register"},
		{http.MethodPost, "/api/admin/discovery/ignore"},
	}
	for _, ep := range endpoints {
		if code := call(ep.method, ep.path, "same-origin"); code != http.StatusForbidden {
			t.Errorf("%s %s yönetici olmayana %d verdi", ep.method, ep.path, code)
		}
	}
	if err := db.SetUserAdmin(ctx, "veli", true); err != nil {
		t.Fatal(err)
	}
	for _, ep := range endpoints[1:] {
		if code := call(ep.method, ep.path, "cross-site"); code != http.StatusForbidden {
			t.Errorf("%s %s çapraz kökene %d verdi", ep.method, ep.path, code)
		}
	}
	if code := call(http.MethodGet, "/api/admin/discovery", "same-origin"); code != http.StatusOK {
		t.Errorf("yönetici + aynı köken: %d", code)
	}
	if code := call(http.MethodPost, "/api/admin/discovery/register", "same-origin"); code != http.StatusBadRequest {
		t.Errorf("boş kayıt isteği: %d, 400 bekleniyordu", code)
	}
}

/*
 * ⚠️ ROZETİN SAYDIĞI ŞEY, LİSTEDE "yeni" GÖRÜNENLE AYNI OLMAK ZORUNDA.
 * Başka bir şey sayan bir rozet, tıklayanı listede o kadar satır
 * bulamayınca bir daha bakmamaya iter: kayıtlı, yok sayılan, kaynakta
 * kalmayan, sorunlu ve anahtarı okunamamış makineler sayılmıyor.
 */
func TestTheBadgeCountsOnlyMachinesThatCanBeRegistered(t *testing.T) {
	s, db := discoveryServer(t, true)
	ctx := t.Context()
	w, out := callDiscovery(t, s, s.adminCreateDiscoverySource, http.MethodPost, sourceBody, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("kaynak: %d %s", w.Code, w.Body.String())
	}
	id, _ := out["id"].(string)

	now := time.Now()
	save := func(ref, name, key, problem string, ignored bool, missing bool) {
		m := store.DiscoveredMachine{
			SourceID: id, Ref: ref, Name: name, Running: true,
			HostKey: key, Problem: problem, LastSeen: now,
		}
		if err := db.SaveDiscoveredMachine(ctx, m); err != nil {
			t.Fatal(err)
		}
		if ignored {
			if _, _, err := db.SetDiscoveredMachineIgnored(ctx, id, ref, true); err != nil {
				t.Fatal(err)
			}
		}
		if missing {
			if err := db.MarkDiscoveredMachineMissing(ctx, id, ref, now); err != nil {
				t.Fatal(err)
			}
		}
	}
	save("qemu/1", "sayilir-1", "ssh-ed25519 AAAA", "", false, false)
	save("qemu/2", "sayilir-2", "ssh-ed25519 BBBB", "", false, false)
	save("qemu/3", "yoksayilan", "ssh-ed25519 CCCC", "", true, false)
	save("qemu/4", "kayip", "ssh-ed25519 DDDD", "", false, true)
	save("qemu/5", "anahtarsiz", "", "not running, so its host key cannot be read", false, false)
	save("qemu/6", "sorunlu", "ssh-ed25519 EEEE", "a target named x already exists", false, false)

	/*
	 * Rozeti besleyen liste artık bildirimler ucu; "yeni" tanımının
	 * ölçüldüğü yer de orası. Sayı DEĞİL satırlar sınanıyor: rozette
	 * doğru sayıyı gösterip listede yanlış makineleri saymak da aynı
	 * güveni bozardı.
	 */
	w, out = callDiscovery(t, s, s.adminNotifications, http.MethodGet, "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("bildirimler: %d %s", w.Code, w.Body.String())
	}
	items, _ := out["items"].([]any)
	var waiting []string
	for _, it := range items {
		m, _ := it.(map[string]any)
		if m["kind"] == "discovery.new" {
			sum, _ := m["summary"].(string)
			waiting = append(waiting, sum)
		}
	}
	if len(waiting) != 2 {
		t.Errorf("bekleyen makineler: %v, ikisi bekleniyordu — %s", waiting, w.Body.String())
	}
	for _, s := range waiting {
		if !strings.HasPrefix(s, "sayilir-") {
			t.Errorf("kaydedilemeyecek bir makine bildirime girdi: %q", s)
		}
	}
}
