package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Warewave-Technology/postern/internal/auth"
)

func callRoleSudo(t *testing.T, s *Server, h http.HandlerFunc, method, role, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "/api/admin/roles/"+role+"/sudo", strings.NewReader(body))
	r.SetPathValue("name", role)
	w := httptest.NewRecorder()
	h(w, asAdmin(r))

	return w
}

/*
 * ⚠️ KURAL YAZILIYOR, OKUNUYOR, DEFTERE DÜŞÜYOR — VE KOMUTLARIYLA
 * DÜŞÜYOR. "bir sudo kuralı verildi" diyen bir denetim satırı, neyin
 * verildiğini söylemiyor; rolün sudo'su bu üründe erişimin kendisi kadar
 * ağır bir karar.
 */
func TestRoleSudoRuleIsWrittenReadAndAudited(t *testing.T) {
	s, db := dbServer(t)
	if _, err := db.CreateRole(t.Context(), "dba"); err != nil {
		t.Fatal(err)
	}

	body := `{"commands":[{"path":"/usr/sbin/nginx","args":["-s","reload"]}]}`
	if w := callRoleSudo(t, s, s.adminSetRoleSudo, http.MethodPut, "dba", body); w.Code != http.StatusOK {
		t.Fatalf("yazma: %d %s", w.Code, w.Body.String())
	}

	w := callRoleSudo(t, s, s.adminRoleSudo, http.MethodGet, "dba", "")
	var got sudoRuleView
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != http.StatusOK {
		t.Fatalf("okuma: %d %s (%v)", w.Code, w.Body.String(), err)
	}
	if len(got.Commands) != 1 || got.Commands[0].Command != "/usr/sbin/nginx -s reload" ||
		got.Commands[0].RunAs != "root" || got.UpdatedBy == "" || got.UpdatedAt.IsZero() {
		t.Errorf("kural: %+v", got)
	}

	logs, err := db.AdminLog(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	var line string
	for _, e := range logs {
		if e.Action == "role.sudo_set" {
			line = e.Entity + " " + e.Details + " by " + e.Actor
		}
	}
	if !strings.Contains(line, "dba") || !strings.Contains(line, "/usr/sbin/nginx -s reload") ||
		strings.HasSuffix(line, "by ") {
		t.Errorf("denetim satırı komutu ya da aktörü taşımıyor: %q", line)
	}
}

/*
 * ⚠️ KAÇIŞ RİSKİ 422 VE SEBEBİYLE. Operatör onay kutusunu işaretleyecekse
 * neyi onayladığını görmek zorunda; "invalid value" diyen bir cevap onu
 * körlemesine onaylamaya iter.
 */
func TestRoleSudoRefusalSaysWhichCommandAndWhy(t *testing.T) {
	s, db := dbServer(t)
	if _, err := db.CreateRole(t.Context(), "ops"); err != nil {
		t.Fatal(err)
	}

	escape := `{"commands":[{"path":"/usr/bin/vim"}]}`
	w := callRoleSudo(t, s, s.adminSetRoleSudo, http.MethodPut, "ops", escape)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "vim") {
		t.Fatalf("kaçış kuralı: %d %s", w.Code, w.Body.String())
	}
	if w := callRoleSudo(t, s, s.adminRoleSudo, http.MethodGet, "ops", ""); w.Code != http.StatusNotFound {
		t.Errorf("reddedilen kural yazıldı: %d", w.Code)
	}

	// ⚠️ HER RET ONAYLANAMAZ. Kaçış riski operatörün bilerek kabul
	// edebileceği bir şey; joker DEĞİL. Ekran onay kutusunu bu bayrağa
	// bakarak gösteriyor, ret metnine bakarak değil.
	if !strings.Contains(w.Body.String(), `"acknowledgeable":true`) {
		t.Errorf("kaçış reddi onaylanabilir işaretlenmemiş: %s", w.Body.String())
	}
	wild := `{"commands":[{"path":"/usr/bin/*"}]}`
	w = callRoleSudo(t, s, s.adminSetRoleSudo, http.MethodPut, "ops", wild)
	if w.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(w.Body.String(), `"acknowledgeable":false`) {
		t.Errorf("joker reddi onaylanabilir sayıldı: %d %s", w.Code, w.Body.String())
	}

	okBody := `{"commands":[{"path":"/usr/bin/vim"}],"acknowledged":true}`
	if w := callRoleSudo(t, s, s.adminSetRoleSudo, http.MethodPut, "ops", okBody); w.Code != http.StatusOK {
		t.Fatalf("onaylanan kural reddedildi: %d %s", w.Code, w.Body.String())
	}

	// Silme: kural gidiyor ama cevap hedeflerdeki dosyanın kaldığını söylüyor.
	w = callRoleSudo(t, s, s.adminDeleteRoleSudo, http.MethodDelete, "ops", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "until postern next works on them") {
		t.Errorf("silme cevabı hedefteki dosyadan söz etmiyor: %d %s", w.Code, w.Body.String())
	}
	if w := callRoleSudo(t, s, s.adminDeleteRoleSudo, http.MethodDelete, "ops", ""); w.Code != http.StatusNotFound {
		t.Errorf("ikinci silme: %d", w.Code)
	}
	if w := callRoleSudo(t, s, s.adminSetRoleSudo, http.MethodPut, "yokrol", okBody); w.Code != http.StatusNotFound {
		t.Errorf("olmayan rol: %d", w.Code)
	}
}

/*
 * ⚠️ ROL LİSTESİ KURALI DA TAŞIYOR: ekran her satır için ayrı istek
 * atmasın ve geciken cevabı "kural yok" diye çizmesin.
 */
func TestRoleListCarriesTheSudoRule(t *testing.T) {
	s, db := dbServer(t)
	for _, name := range []string{"dba", "kuralsiz"} {
		if _, err := db.CreateRole(t.Context(), name); err != nil {
			t.Fatal(err)
		}
	}
	// ⚠️ HESAP KOMUT BAŞINA: iki komut, iki hesap, tek kural.
	body := `{"commands":[{"path":"/usr/bin/pg_ctl","args":["reload"],"run_as":"postgres"},` +
		`{"path":"/usr/sbin/nginx","args":["-t"]}]}`
	if w := callRoleSudo(t, s, s.adminSetRoleSudo, http.MethodPut, "dba", body); w.Code != http.StatusOK {
		t.Fatalf("yazma: %d %s", w.Code, w.Body.String())
	}

	r := httptest.NewRequest(http.MethodGet, "/api/admin/roles", nil)
	w := httptest.NewRecorder()
	s.adminListRoles(w, asAdmin(r))
	var rows []struct {
		Name string        `json:"name"`
		Sudo *sudoRuleView `json:"sudo"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("liste: %s (%v)", w.Body.String(), err)
	}
	seen := map[string]*sudoRuleView{}
	for _, row := range rows {
		seen[row.Name] = row.Sudo
	}
	if seen["dba"] == nil || len(seen["dba"].Commands) != 2 ||
		seen["dba"].Commands[0].Command != "/usr/bin/pg_ctl reload" ||
		seen["dba"].Commands[0].RunAs != "postgres" ||
		seen["dba"].Commands[1].RunAs != "root" {
		t.Errorf("kurallı rol: %+v", seen["dba"])
	}
	if _, listed := seen["kuralsiz"]; !listed {
		t.Fatal("kuralsız rol listede yok")
	}
	if seen["kuralsiz"] != nil {
		t.Errorf("kuralsız rol kural taşıyor: %+v", seen["kuralsiz"])
	}
}

/*
 * ⚠️ ROLÜN SUDO'SU YÖNETİCİ KAPISININ ARKASINDA. Bu uçlar hedefte root
 * yetkisi dağıtıyor: sıradan bir oturum okuyamamalı, yazamamalı, ve
 * başka bir siteden tetiklenememeli (sameOrigin).
 */
func TestRoleSudoEndpointsAreBehindTheAdminAndSameOriginGates(t *testing.T) {
	db := migratedStore(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := New(auth.NewOIDCHolder(), auth.NewLogins(auth.NewOIDCHolder()), db, logger)

	ctx := t.Context()
	if _, err := db.CreateUser(ctx, "veli", "", "veli"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateRole(ctx, "dba"); err != nil {
		t.Fatal(err)
	}
	token, err := s.createWebSession(ctx, "veli")
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, site string) int {
		t.Helper()
		r := httptest.NewRequest(method, "/api/admin/roles/dba/sudo",
			strings.NewReader(`{"commands":[{"path":"/bin/true"}]}`))
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		if site != "" {
			r.Header.Set("Sec-Fetch-Site", site)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)

		return w.Code
	}

	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		if code := call(m, "same-origin"); code != http.StatusForbidden {
			t.Errorf("%s yönetici olmayan oturuma açık: %d", m, code)
		}
	}
	if err := db.SetUserAdmin(ctx, "veli", true); err != nil {
		t.Fatal(err)
	}
	if code := call(http.MethodPut, "cross-site"); code != http.StatusForbidden {
		t.Errorf("başka siteden yazma kabul edildi: %d", code)
	}
	if code := call(http.MethodPut, "same-origin"); code != http.StatusOK {
		t.Errorf("yönetici yazamadı: %d", code)
	}
}

/*
 * ⚠️ RİSK SATIRIN KENDİSİNDE. Tablonun altındaki "burada bir komut kabul
 * edildi" notu, altı komutluk bir kuralda hangisinin riskli olduğunu
 * söylemiyordu; okuyan ya hepsinden şüpheleniyor ya hiçbirinden. Cevap
 * artık komut başına sebebi taşıyor ve risksiz komut onu taşımıyor.
 */
func TestRoleSudoMarksWhichCommandIsTheWayOut(t *testing.T) {
	s, db := dbServer(t)
	if _, err := db.CreateRole(t.Context(), "ops"); err != nil {
		t.Fatal(err)
	}

	body := `{"acknowledged":true,"commands":[` +
		`{"path":"/usr/sbin/nginx","args":["-t"]},` +
		`{"path":"/usr/bin/vim"},` +
		`{"path":"/usr/bin/pg_ctl","args":["reload"],"run_as":"postgres"}]}`
	if w := callRoleSudo(t, s, s.adminSetRoleSudo, http.MethodPut, "ops", body); w.Code != http.StatusOK {
		t.Fatalf("yazma: %d %s", w.Code, w.Body.String())
	}

	w := callRoleSudo(t, s, s.adminRoleSudo, http.MethodGet, "ops", "")
	var got sudoRuleView
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("okuma: %s (%v)", w.Body.String(), err)
	}
	risky := map[string]string{}
	for _, c := range got.Commands {
		risky[c.Command] = c.Escape
	}
	if risky["/usr/bin/vim"] == "" {
		t.Errorf("kaçış yolu olan komut işaretlenmemiş: %+v", got.Commands)
	}
	if !strings.Contains(risky["/usr/bin/vim"], "shell") {
		t.Errorf("sebep okunur değil: %q", risky["/usr/bin/vim"])
	}
	if risky["/usr/sbin/nginx -t"] != "" || risky["/usr/bin/pg_ctl reload"] != "" {
		t.Errorf("risksiz komutlar da işaretlenmiş: %+v", got.Commands)
	}
}
