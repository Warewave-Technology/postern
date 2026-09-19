package httpapi

/*
 * Geçici erişim uçları. Makineye giden yolun kendisi test/integration'da
 * gerçek OpenSSH ile ölçülüyor; burada ölçülen şey uçların kapıları,
 * doğrulaması ve başarısız bir koşunun cevaba nasıl girdiği.
 */

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/v2/internal/auth"
	"github.com/Warewave-Technology/postern/v2/internal/jit"
	"github.com/Warewave-Technology/postern/v2/internal/model"
	"github.com/Warewave-Technology/postern/v2/internal/store"
)

func jitServer(t *testing.T) (*Server, *store.Store, string, int, string) {
	t.Helper()
	s, db := dbServer(t)
	authority := manageCA(t)
	s.UseManagement(authority)
	s.UseJIT(jit.New(db, authority, nil, slog.New(slog.NewTextHandler(io.Discard, nil))))

	host, port, hostKey, _ := managedHost(t, authority, debianAnswers())
	if _, err := db.CreateTarget(t.Context(), model.Target{
		Name: "web01", Host: host, Port: port, HostKey: hostKey,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser(t.Context(), "ayse", "", "ayse"); err != nil {
		t.Fatal(err)
	}

	return s, db, host, port, hostKey
}

func asAdmin(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxUser, "ops"))
}

func postGrant(t *testing.T, s *Server, target, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/admin/targets/"+target+"/grants", strings.NewReader(body))
	r.SetPathValue("name", target)
	w := httptest.NewRecorder()
	s.adminCreateGrant(w, asAdmin(r))
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)

	return w, out
}

/*
 * ⚠️ KAPALIYKEN UÇ YOK. Yönetim açık ama jit bağlanmamışsa bile uç
 * kurulmamalı: root'la hesap açan bir yol, yarım kablolanmış bir sunucuda
 * "var ama 500 dönüyor" olarak durmamalı.
 */
func TestGrantRoutesExistOnlyWhenTheServiceIsWired(t *testing.T) {
	s := &Server{}
	s.UseManagement(manageCA(t))
	mux := http.NewServeMux()
	s.registerJITRoutes(mux)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/targets/web01/grants", nil)
	if _, pattern := mux.Handler(req); pattern != "" {
		t.Errorf("hizmet yokken uç kuruldu: %q", pattern)
	}

	s.UseJIT(&jit.Service{})
	mux = http.NewServeMux()
	s.registerJITRoutes(mux)
	if _, pattern := mux.Handler(req); pattern == "" {
		t.Error("hizmet varken uç kurulmadı")
	}
}

/*
 * ⚠️ DOĞRULAMA HEDEFE GİTMEDEN, 400 İLE. Süre sınırı, boş kullanıcı, kaçış
 * riski taşıyan sudo kuralı: üçü de bağlantı açılmadan reddedilmeli ve
 * cümle operatörün düzelteceği alanı söylemeli.
 */
func TestGrantRequestIsValidatedBeforeTheTargetIsTouched(t *testing.T) {
	s, db, _, _, _ := jitServer(t)

	for name, body := range map[string]string{
		"boş kullanıcı":    `{"username":"","duration":"2h"}`,
		"bozuk süre":       `{"username":"ayse","duration":"iki saat"}`,
		"çok kısa":         `{"username":"ayse","duration":"1m"}`,
		"çok uzun":         `{"username":"ayse","duration":"1000h"}`,
		"kaçış veren sudo": `{"username":"ayse","duration":"2h","sudo":{"commands":[{"path":"/usr/bin/vim"}]}}`,
	} {
		w, out := postGrant(t, s, "web01", body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: durum = %d, 400 bekleniyordu: %s", name, w.Code, w.Body.String())
		}
		if out["error"] == "" {
			t.Errorf("%s: sebep yok", name)
		}
	}

	w, _ := postGrant(t, s, "yok", `{"username":"ayse","duration":"2h"}`)
	if w.Code != http.StatusNotFound {
		t.Errorf("bilinmeyen hedef: durum = %d", w.Code)
	}

	grants, _ := db.JITGrantsForTarget(t.Context(), "web01", 10)
	if len(grants) != 0 {
		t.Errorf("reddedilen istek kayıt bıraktı: %d", len(grants))
	}
	logs, _ := db.AdminLog(t.Context(), 20)
	for _, e := range logs {
		if strings.HasPrefix(e.Action, "jit.") {
			t.Errorf("reddedilen istek deftere yazıldı: %+v", e)
		}
	}
}

/*
 * ⚠️ HEDEFTE YARIM KALAN KOŞU ADIM ADIM CEVABA GİRİYOR. Sahte hedef
 * `useradd`i tanımıyor (127); plan grup ve hesap adımlarını üretiyor,
 * ilki düşüyor, gerisi denenmiyor. Cevap 502 ve hangi adımın nerede
 * kaldığını taşıyor; kayıt hemen vadesi dolmuş, denetim defteri denemeyi
 * ve sonucu ayrı satırlarda tutuyor.
 */
func TestAFailedGrantReportsEveryStepAndFallsDue(t *testing.T) {
	s, db, _, _, _ := jitServer(t)

	w, out := postGrant(t, s, "web01", `{"username":"ayse","groups":["dba"],"duration":"2h"}`)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("durum = %d: %s", w.Code, w.Body.String())
	}
	steps, _ := out["steps"].([]any)
	if len(steps) == 0 {
		t.Fatalf("adımlar cevapta yok: %s", w.Body.String())
	}
	first, _ := steps[0].(map[string]any)
	if first["outcome"] != "failed" || first["kind"] != "group.add" {
		t.Errorf("ilk adım = %+v, group.add/failed bekleniyordu", first)
	}
	last, _ := steps[len(steps)-1].(map[string]any)
	if last["outcome"] != "not attempted" {
		t.Errorf("son adım = %+v, 'not attempted' bekleniyordu", last)
	}

	grants, err := db.JITGrantsForTarget(t.Context(), "web01", 10)
	if err != nil || len(grants) != 1 {
		t.Fatalf("kayıt = %v (%v)", grants, err)
	}
	g := grants[0]
	if !g.AppliedAt.IsZero() || !g.Due(time.Now()) {
		t.Errorf("yarım kalan hak uygulanmış/vadesi gelmemiş görünüyor: %+v", g)
	}
	if out["grant"] == nil {
		t.Error("cevapta kayıt yok; operatör süpürücünün neyi toplayacağını göremez")
	}
	// cleanup_groups söylenmemişse evet; açıkça hayır denmişse hayır.
	if !g.CleanupGroups {
		t.Error("cleanup_groups verilmeyince temizleme kapalı kaydedildi")
	}
	postGrant(t, s, "web01", `{"username":"ayse","groups":["dba"],"duration":"2h","cleanup_groups":false}`)
	// İki kayıt aynı milisaniyede açılabiliyor; sıra değil sayı sayılıyor.
	grants, _ = db.JITGrantsForTarget(t.Context(), "web01", 10)
	off := 0
	for _, g := range grants {
		if !g.CleanupGroups {
			off++
		}
	}
	if len(grants) != 2 || off != 1 {
		t.Errorf("cleanup_groups:false kaydedilmedi: %+v", grants)
	}

	seen := map[string]bool{}
	logs, _ := db.AdminLog(t.Context(), 20)
	for _, e := range logs {
		seen[e.Action] = true
	}
	if !seen["jit.grant"] || !seen["jit.grant.failed"] {
		t.Errorf("denetim defteri deneme ve sonucu ayrı satırlarda tutmuyor: %v", seen)
	}
}

// Listeleme hedefi doğruluyor; geri alma bilinmeyen ve çoktan geri alınmış
// hakka doğru durumla cevap veriyor.
func TestGrantListAndRevokeAnswerAboutTheRightGrant(t *testing.T) {
	s, db, _, _, _ := jitServer(t)
	ctx := t.Context()

	r := httptest.NewRequest(http.MethodGet, "/api/admin/targets/yok/grants", nil)
	r.SetPathValue("name", "yok")
	w := httptest.NewRecorder()
	s.adminListGrants(w, asAdmin(r))
	if w.Code != http.StatusNotFound {
		t.Errorf("bilinmeyen hedefin listesi: %d", w.Code)
	}

	now := time.Now()
	id, err := db.CreateJITGrant(ctx, store.JITGrant{
		Username: "ayse", Target: "web01", OSUser: "ayse", GrantedBy: "ops",
		GrantedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.MarkJITGrantRevoked(ctx, id, "gone", now); err != nil {
		t.Fatal(err)
	}

	r = httptest.NewRequest(http.MethodGet, "/api/admin/targets/web01/grants", nil)
	r.SetPathValue("name", "web01")
	w = httptest.NewRecorder()
	s.adminListGrants(w, asAdmin(r))
	var list struct {
		Grants []store.JITGrant `json:"grants"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list.Grants) != 1 || list.Grants[0].ID != id {
		t.Errorf("liste = %s (%v)", w.Body.String(), err)
	}

	revoke := func(id string) int {
		r := httptest.NewRequest(http.MethodPost, "/api/admin/grants/"+id+"/revoke", nil)
		r.SetPathValue("id", id)
		w := httptest.NewRecorder()
		s.adminRevokeGrant(w, asAdmin(r))
		return w.Code
	}
	if code := revoke("yok"); code != http.StatusNotFound {
		t.Errorf("bilinmeyen hak: %d", code)
	}
	if code := revoke(id); code != http.StatusConflict {
		t.Errorf("çoktan geri alınmış hak: %d, 409 bekleniyordu", code)
	}
}

/*
 * ⚠️ KAPILAR ROTADA — yönetim denetimiyle aynı ders: handler doğrudan
 * çağrılınca requireAdmin ve sameOrigin hiç koşmuyor. Root'la hesap açan
 * uç için üçü de ölçülüyor: yönetici olmayan 403, çapraz köken 403,
 * yönetici + aynı köken kapıdan geçip handler'ın kendi cevabını alıyor.
 */
func TestGrantEndpointsAreBehindTheAdminAndSameOriginGates(t *testing.T) {
	db := migratedStore(t)
	s := New(auth.NewOIDCHolder(), auth.NewLogins(auth.NewOIDCHolder()), db,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	authority := manageCA(t)
	s.UseManagement(authority)
	s.UseJIT(jit.New(db, authority, nil, slog.New(slog.NewTextHandler(io.Discard, nil))))

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
		r := httptest.NewRequest(method, path, strings.NewReader(`{"username":"veli","duration":"2h"}`))
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		if site != "" {
			r.Header.Set("Sec-Fetch-Site", site)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w.Code
	}

	for _, ep := range []struct{ method, path string }{
		{http.MethodPost, "/api/admin/targets/yok/grants"},
		{http.MethodGet, "/api/admin/targets/yok/grants"},
		{http.MethodPost, "/api/admin/grants/yok/revoke"},
	} {
		if code := call(ep.method, ep.path, "same-origin"); code != http.StatusForbidden {
			t.Errorf("%s %s yönetici olmayana %d verdi, 403 bekleniyordu", ep.method, ep.path, code)
		}
	}
	if err := db.SetUserAdmin(ctx, "veli", true); err != nil {
		t.Fatal(err)
	}
	for _, ep := range []struct{ method, path string }{
		{http.MethodPost, "/api/admin/targets/yok/grants"},
		{http.MethodPost, "/api/admin/grants/yok/revoke"},
	} {
		if code := call(ep.method, ep.path, "cross-site"); code != http.StatusForbidden {
			t.Errorf("%s %s çapraz kökene %d verdi, 403 bekleniyordu", ep.method, ep.path, code)
		}
		// Karşı örnek: kapılardan geçince handler'ın 404'ü.
		if code := call(ep.method, ep.path, "same-origin"); code != http.StatusNotFound {
			t.Errorf("%s %s yönetici + aynı köken %d verdi, 404 bekleniyordu", ep.method, ep.path, code)
		}
	}
}

/*
 * ⚠️ HEDEFTE AÇIK HESABI OLAN KİŞİ SİLİNMİYOR. Kayıt gidip hesap kalsaydı
 * "bu makinede kim var" sorusu panelde cevapsız kalırdı. Yönetici
 * revoke_grants=true ile geri almayı bilerek istiyor; hedef ulaşılamazsa
 * kişi YİNE silinmiyor — makinede hesap var, postern'de sahibi yok, tam
 * olarak kaçınılan şey.
 */
func TestAUserWithOpenTemporaryAccountsIsNotDeleted(t *testing.T) {
	s, db, _, _, hostKey := jitServer(t)
	ctx := t.Context()

	/*
	 * ⚠️ ULAŞILAMAYAN HEDEF, "HESABI OLMAYAN HEDEF" DEĞİL. İlk hâli sahte
	 * hedefi kullanıyordu; orada hesap yok, geri alma haklı olarak
	 * "hesap zaten gitmiş" diye BAŞARIYOR ve kişi siliniyordu — test
	 * ölçmek istediğini ölçmüyordu. Kapalı bir port, geri almanın
	 * gerçekten bitmediği tek deterministik hâl.
	 */
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, p, _ := net.SplitHostPort(l.Addr().String())
	closedPort, _ := strconv.Atoi(p)
	l.Close()
	if _, err := db.CreateTarget(ctx, model.Target{
		Name: "kapali", Host: "127.0.0.1", Port: closedPort, HostKey: hostKey,
	}); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	id, err := db.CreateJITGrant(ctx, store.JITGrant{
		Username: "ayse", Target: "kapali", OSUser: "ayse", GrantedBy: "ops",
		GrantedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.MarkJITGrantApplied(ctx, id, true, "4 applied", now); err != nil {
		t.Fatal(err)
	}

	del := func(query string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodDelete, "/api/admin/users/ayse"+query, nil)
		r.SetPathValue("name", "ayse")
		w := httptest.NewRecorder()
		s.adminDeleteUser(w, asAdmin(r))
		return w
	}

	if w := del(""); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "revoke_grants=true") {
		t.Errorf("açık hakkı olan kişi: %d %s", w.Code, w.Body.String())
	}
	if _, err := db.User(ctx, "ayse"); err != nil {
		t.Fatalf("kişi silindi: %v", err)
	}

	// Geri alma isteniyor ama hedefe ulaşılamıyor: kişi yine silinmiyor ve
	// sebep cevapta.
	w := del("?revoke_grants=true")
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "was not deleted") {
		t.Errorf("geri alma düşünce kişi silindi ya da sebep yok: %d %s", w.Code, w.Body.String())
	}
	if _, err := db.User(ctx, "ayse"); err != nil {
		t.Fatalf("başarısız geri almadan sonra kişi silindi: %v", err)
	}

	// Hak kapanınca silme geçiyor.
	if err := db.MarkJITGrantRevoked(ctx, id, "gone", now); err != nil {
		t.Fatal(err)
	}
	if w := del(""); w.Code != http.StatusOK {
		t.Errorf("hakları kapanmış kişi silinemedi: %d %s", w.Code, w.Body.String())
	}
}

/*
 * ⚠️ DEFTERE YAZILAMIYORSA HEDEFE HİÇ GİDİLMİYOR — yönetim denetimiyle aynı
 * kural, bu kez root'la hesap AÇAN yol için. Bağlantı sayacı sıfır kalmalı:
 * ret hedefte değil, defterde.
 */
func TestAGrantIsNotAttemptedWithoutAnAuditRow(t *testing.T) {
	s, db, dsn := dbServerDSN(t)
	authority := manageCA(t)
	s.UseManagement(authority)
	s.UseJIT(jit.New(db, authority, nil, slog.New(slog.NewTextHandler(io.Discard, nil))))
	host, port, hostKey, conns := managedHost(t, authority, debianAnswers())
	ctx := t.Context()
	if _, err := db.CreateTarget(ctx, model.Target{Name: "web01", Host: host, Port: port, HostKey: hostKey}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser(ctx, "ayse", "", "ayse"); err != nil {
		t.Fatal(err)
	}

	dropTable(t, dsn, "admin_log")

	w, _ := postGrant(t, s, "web01", `{"username":"ayse","duration":"2h"}`)
	if w.Code < 500 {
		t.Errorf("defter yazılamazken istek %d aldı: %s", w.Code, w.Body.String())
	}
	if n := conns.Load(); n != 0 {
		t.Errorf("defter yazılamadığı hâlde hedefe %d bağlantı açıldı", n)
	}
	if grants, _ := db.JITGrantsForTarget(ctx, "web01", 10); len(grants) != 0 {
		t.Errorf("defter yazılamadığı hâlde hak kaydedildi: %d", len(grants))
	}
}

/*
 * ⚠️ SEKME BÜTÜN HEDEFLERİ LİSTELİYOR, EN YENİ ÖNCE. Hedef başına liste
 * kalıyor; sekmenin sorusu "kimin nerede açık hesabı var" ve o soru tek
 * ekranda cevaplanmalı.
 */
func TestAllGrantsListSpansTargetsNewestFirst(t *testing.T) {
	s, db, host, port, hostKey := jitServer(t)
	ctx := t.Context()
	if _, err := db.CreateTarget(ctx, model.Target{
		Name: "db01", Host: host, Port: port, HostKey: hostKey,
	}); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	old, err := db.CreateJITGrant(ctx, store.JITGrant{
		Username: "ayse", Target: "web01", OSUser: "ayse", GrantedBy: "ops",
		GrantedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := db.CreateJITGrant(ctx, store.JITGrant{
		Username: "ayse", Target: "db01", OSUser: "ayse", GrantedBy: "ops",
		GrantedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodGet, "/api/admin/grants", nil)
	w := httptest.NewRecorder()
	s.adminListAllGrants(w, asAdmin(r))
	var list struct {
		Grants []store.JITGrant `json:"grants"`
		Now    time.Time        `json:"now"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("cevap okunamadı: %v — %s", err, w.Body.String())
	}
	if len(list.Grants) != 2 || list.Grants[0].ID != fresh || list.Grants[1].ID != old {
		t.Errorf("liste = %s; %s sonra %s bekleniyordu", w.Body.String(), fresh, old)
	}
	if list.Now.IsZero() {
		t.Error("now yok: panel vadeyi sunucunun saatine göre okur")
	}
}

/*
 * ⚠️ SEKME YALNIZCA HİZMET BAĞLIYKEN ÇİZİLİYOR ve panel bunu /api/me'den
 * öğreniyor. Bayrak olmadan sekme her kurulumda görünür ve uçları olmayan
 * bir bastion'da her tıklama 404 olurdu.
 */
func TestMeSaysWhetherTemporaryAccessIsOn(t *testing.T) {
	s, db := dbServer(t)
	if _, err := db.CreateUser(t.Context(), "ops", "", "ops"); err != nil {
		t.Fatal(err)
	}
	me := func() map[string]any {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/api/me", nil)
		w := httptest.NewRecorder()
		s.handleMe(w, asAdmin(r))
		out := map[string]any{}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("cevap okunamadı: %v — %s", err, w.Body.String())
		}
		return out
	}

	if on, _ := me()["jit_enabled"].(bool); on {
		t.Error("hizmet bağlı değilken jit_enabled true")
	}
	authority := manageCA(t)
	s.UseManagement(authority)
	s.UseJIT(jit.New(db, authority, nil, slog.New(slog.NewTextHandler(io.Discard, nil))))
	if on, _ := me()["jit_enabled"].(bool); !on {
		t.Error("hizmet bağlıyken jit_enabled false")
	}
}

/*
 * ⚠️ GEÇİCİ HAK DA KOMUT BAŞINA HESAP TAŞIYOR.
 *
 * ÖLÇÜLDÜ: gövdenin kendi kopyası komutun hesabını hiç okumuyordu, yani
 * panelden verilebilen tek şey root'tu — "pg_ctl reload"u postgres olarak
 * vermenin yolu yoktu. Dar seçeneği sunmayan bir ekran geniş olanı
 * yazdırır. İki yön de ölçülüyor: geçerli bir hesap hedefe gitmeden
 * reddedilmiyor, bozuk bir hesap ise 400 ile ve hedefe hiç dokunulmadan
 * reddediliyor — ikincisi yalnızca alan GERÇEKTEN okunuyorsa olabilir.
 */
func TestAGrantCarriesTheAccountEachCommandRunsAs(t *testing.T) {
	s, db, _, _, _ := jitServer(t)

	bad := `{"username":"ayse","duration":"2h","sudo":{"commands":` +
		`[{"path":"/usr/bin/pg_ctl","args":["reload"],"run_as":"post gres"}]}}`
	w, out := postGrant(t, s, "web01", bad)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bozuk hesap: durum = %d, 400 bekleniyordu: %s", w.Code, w.Body.String())
	}
	if msg, _ := out["error"].(string); !strings.Contains(msg, "post gres") {
		t.Errorf("sebep hesabı söylemiyor: %q", msg)
	}

	/*
	 * Geçerli hesap: doğrulama geçiyor, yani ret artık hedefe GİDİLDİKTEN
	 * sonraki bir hata (sahte hedef useradd tanımıyor: 502). 400 dönerse
	 * kural doğrulamada takılmış demektir.
	 */
	good := `{"username":"ayse","duration":"2h","sudo":{"commands":` +
		`[{"path":"/usr/bin/pg_ctl","args":["reload"],"run_as":"postgres"}]}}`
	w, out = postGrant(t, s, "web01", good)
	if w.Code == http.StatusBadRequest {
		t.Errorf("geçerli hesap reddedildi: %s", w.Body.String())
	}
	if msg, _ := out["error"].(string); strings.Contains(msg, "sudo rule refused") {
		t.Errorf("geçerli hesap kural doğrulamasında düştü: %q", msg)
	}

	// Reddedilen istek hedefte de defterde de iz bırakmıyor.
	grants, _ := db.JITGrantsForTarget(t.Context(), "web01", 10)
	for _, g := range grants {
		if g.Username == "ayse" && g.RevokedAt.IsZero() && g.ExpiresAt.After(time.Now()) {
			t.Errorf("yarım kalan hak açık kaldı: %+v", g)
		}
	}
}
