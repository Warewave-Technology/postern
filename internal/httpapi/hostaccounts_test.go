package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/store"
)

type fakeRemover struct {
	called int
	err    error
}

func (f *fakeRemover) Remove(context.Context, string, string, string) error {
	f.called++

	return f.err
}

func hostAcctServer(t *testing.T) (*Server, *store.Store, *fakeRemover) {
	t.Helper()
	s, db := dbServer(t)
	rm := &fakeRemover{}
	s.UseHostAccounts(rm)
	ctx := t.Context()
	if _, err := db.CreateUser(ctx, "ayse", "", "ayse"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateTarget(ctx, model.Target{
		Name: "db01", Host: "10.0.0.1", Port: 22, HostKey: "ssh-ed25519 AAAA",
	}); err != nil {
		t.Fatal(err)
	}

	return s, db, rm
}

/*
 * ⚠️ LİSTE HESABIN KAYNAĞINI TAŞIMAK ZORUNDA.
 *
 * Silme düğmesinin anlamı buna göre değişiyor: postern'in açtığı bir
 * hesabı silmek onu geri almak, başka bir aracın açtığını silmek o
 * aracın sahibi olduğu bir şeyi yok etmek. Kaynağı göstermeyen bir ekran,
 * ikisini aynı düğmeye indirir.
 */
func TestTheWaitingListSaysWhoCreatedEachAccount(t *testing.T) {
	s, db, _ := hostAcctServer(t)
	ctx := t.Context()
	now := time.Now()

	if err := db.SaveHostAccount(ctx, store.HostAccount{
		TargetName: "db01", Username: "ayse", OSUser: "ayse",
		Origin: store.OriginAdopted, State: store.HostAccountLocked,
		AwaitingDecision: true, FirstSeen: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodGet, "/api/admin/host-accounts", nil)
	w := httptest.NewRecorder()
	s.adminHostAccounts(w, asAdmin(r))
	if w.Code != http.StatusOK {
		t.Fatalf("durum: %d %s", w.Code, w.Body.String())
	}

	var out struct {
		Accounts []hostAccountView `json:"accounts"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if len(out.Accounts) != 1 {
		t.Fatalf("liste: %+v", out.Accounts)
	}
	if out.Accounts[0].Origin != store.OriginAdopted {
		t.Errorf("kaynak taşınmıyor: %+v", out.Accounts[0])
	}
	if out.Accounts[0].OSUser != "ayse" {
		t.Errorf("hedefteki hesap adı yok: %+v", out.Accounts[0])
	}
}

/*
 * ⚠️ "KALSIN" HESABI AÇMIYOR. Kilit duruyor; satır yalnızca karar
 * bekleyenler listesinden çıkıyor. Durumu active yapmak, hedefte kilitli
 * duran bir hesabı kayıtta açık göstermek olurdu — ve panel o hesabın
 * kullanılabilir olduğunu söylerdi.
 */
func TestKeepingAnAccountLeavesItLocked(t *testing.T) {
	s, db, _ := hostAcctServer(t)
	ctx := t.Context()
	now := time.Now()

	if err := db.SaveHostAccount(ctx, store.HostAccount{
		TargetName: "db01", Username: "ayse", OSUser: "ayse",
		Origin: store.OriginCreated, State: store.HostAccountLocked,
		AwaitingDecision: true, FirstSeen: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodPost, "/api/admin/host-accounts/db01/ayse/keep", nil)
	r.SetPathValue("target", "db01")
	r.SetPathValue("username", "ayse")
	w := httptest.NewRecorder()
	s.adminKeepHostAccount(w, asAdmin(r))
	if w.Code != http.StatusOK {
		t.Fatalf("durum: %d %s", w.Code, w.Body.String())
	}

	row, err := db.HostAccountFor(ctx, "db01", "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if row.State != store.HostAccountLocked {
		t.Errorf("durum = %q, kilitli kalmalıydı", row.State)
	}
	if row.AwaitingDecision {
		t.Error("karar verildi ama satır hâlâ bekliyor")
	}

	// Ve liste boşaldı.
	lr := httptest.NewRequest(http.MethodGet, "/api/admin/host-accounts", nil)
	lw := httptest.NewRecorder()
	s.adminHostAccounts(lw, asAdmin(lr))
	var out struct {
		Accounts []hostAccountView `json:"accounts"`
	}
	_ = json.Unmarshal(lw.Body.Bytes(), &out)
	if len(out.Accounts) != 0 {
		t.Errorf("karar verilen satır listede: %+v", out.Accounts)
	}
}

/* Uçlar yalnızca özellik açıkken kuruluyor ve yönetici kapısının arkasında. */
func TestHostAccountRoutesExistOnlyWhenTheFeatureIsOn(t *testing.T) {
	s, _ := dbServer(t)
	mux := http.NewServeMux()
	s.registerHostAccountRoutes(mux)
	req := httptest.NewRequest(http.MethodGet, "/api/admin/host-accounts", nil)
	if _, pattern := mux.Handler(req); pattern != "" {
		t.Errorf("özellik kapalıyken uç kuruldu: %q", pattern)
	}

	s.UseHostAccounts(&fakeRemover{})
	mux = http.NewServeMux()
	s.registerHostAccountRoutes(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code == http.StatusOK {
		t.Errorf("oturumsuz istek geçti: %d", w.Code)
	}
}
