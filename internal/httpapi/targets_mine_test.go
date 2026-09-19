package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/v2/internal/model"
	"github.com/Warewave-Technology/postern/v2/internal/store"
)

func asUser(r *http.Request, name string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxUser, name))
}

func myTargets(t *testing.T, s *Server, user string) []targetCard {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/targets", nil)
	w := httptest.NewRecorder()
	s.handleMyTargets(w, asUser(r, user))
	if w.Code != http.StatusOK {
		t.Fatalf("durum = %d: %s", w.Code, w.Body.String())
	}
	var out []targetCard
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("cevap okunamadı: %v — %s", err, w.Body.String())
	}
	return out
}

func myTargetDetail(t *testing.T, s *Server, user, name string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/targets/"+name, nil)
	r.SetPathValue("name", name)
	w := httptest.NewRecorder()
	s.handleMyTargetDetail(w, asUser(r, user))
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

/*
 * ⚠️ SÜRELİ HAK ENVANTERDE GÖRÜNÜYOR VE GEÇİCİ OLDUĞU YAZIYOR. Rolü
 * olmayan kişi hakla erişebildiği hedefi ana ekranında görmezse,
 * bastion'dan geçerek bağlanabildiğini de bilmez; "temporary" olmadan
 * hak bittiğinde kaybolan kutu bir arıza gibi görünür. Yalnızca canlı hak
 * sayılıyor — uygulanmamış ya da vadesi dolmuş hak envantere girmiyor —
 * ve rolle erişilen hedefte alan boş.
 */
func TestTemporaryAccessShowsUpInThePersonsInventory(t *testing.T) {
	s, db, host, port, hostKey := jitServer(t)
	ctx := t.Context()
	for _, name := range []string{"db01", "cache01", "old01"} {
		if _, err := db.CreateTarget(ctx, model.Target{Name: name, Host: host, Port: port, HostKey: hostKey}); err != nil {
			t.Fatal(err)
		}
	}
	// ayse'nin grubu web01'e; db01 yalnızca hakla.
	if _, err := db.CreateGroup(ctx, "web"); err != nil {
		t.Fatal(err)
	}
	if err := db.GrantTarget(ctx, "web", "web01"); err != nil {
		t.Fatal(err)
	}
	if err := db.AssignGroup(ctx, "ayse", "web", time.Time{}); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	mk := func(target string, expires time.Time, applied bool) {
		t.Helper()
		// Vadesi dolmuş hak dün verilmiş: depo vadenin verilişten sonra
		// olmasını istiyor.
		id, err := db.CreateJITGrant(ctx, store.JITGrant{
			Username: "ayse", Target: target, OSUser: "ayse", Groups: []string{"dba"},
			GrantedBy: "ops", GrantedAt: expires.Add(-24 * time.Hour), ExpiresAt: expires,
		})
		if err != nil {
			t.Fatal(err)
		}
		if applied {
			if err := db.MarkJITGrantApplied(ctx, id, true, "4 applied", now); err != nil {
				t.Fatal(err)
			}
		}
	}
	mk("db01", now.Add(2*time.Hour), true)     // canlı
	mk("cache01", now.Add(2*time.Hour), false) // uygulanmamış
	mk("old01", now.Add(-time.Minute), true)   // vadesi dolmuş
	mk("web01", now.Add(2*time.Hour), true)    // rolle de erişiliyor

	cards := myTargets(t, s, "ayse")
	byName := map[string]targetCard{}
	for _, c := range cards {
		byName[c.Name] = c
	}
	if _, ok := byName["cache01"]; ok {
		t.Error("uygulanmamış hakkın hedefi envanterde")
	}
	if _, ok := byName["old01"]; ok {
		t.Error("vadesi dolmuş hakkın hedefi envanterde")
	}
	db01, ok := byName["db01"]
	if !ok || db01.Temporary == nil {
		t.Fatalf("hakla erişilen hedef yok ya da geçici değil: %+v", cards)
	}
	if db01.Temporary.GrantedBy != "ops" || len(db01.Temporary.Groups) != 1 || db01.Temporary.Until == "" {
		t.Errorf("geçici alan eksik: %+v", db01.Temporary)
	}
	if web, ok := byName["web01"]; !ok || web.Temporary != nil {
		t.Errorf("rolle erişilen hedef geçici işaretli ya da yok: %+v", web)
	}

	if code, out := myTargetDetail(t, s, "ayse", "db01"); code != http.StatusOK || out["temporary"] == nil {
		t.Errorf("hakla erişilen hedefin sayfası: %d, temporary=%v", code, out["temporary"])
	}
	if code, _ := myTargetDetail(t, s, "ayse", "old01"); code != http.StatusNotFound {
		t.Errorf("vadesi dolmuş hakkın hedef sayfası %d döndü, 404 bekleniyordu", code)
	}
	if code, out := myTargetDetail(t, s, "ayse", "web01"); code != http.StatusOK || out["temporary"] != nil {
		t.Errorf("rolle erişilen hedef sayfası: %d, temporary=%v", code, out["temporary"])
	}
}
