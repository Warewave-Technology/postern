package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/record"
	"github.com/Warewave-Technology/postern/internal/store"
)

// Liste ve ayrıntı, oturumu grubun değil süreli hakkın açtığını söylüyor;
// rolle açılanda alan hiç yok (omitempty) — "false" çizmek yerine.
func TestSessionListAndDetailSayWhenAccessWasTemporary(t *testing.T) {
	s, db := dbServer(t)
	seedTargets(t, db, "web01")
	ctx := context.Background()
	rs, err := record.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.records = rs
	for _, c := range []struct {
		id   string
		temp bool
	}{{"sess-temp", true}, {"sess-group", false}} {
		f, path, err := rs.Create(c.id)
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
		if err := db.StartSession(ctx, store.SessionStart{
			ID: c.id, Username: "ayse", TargetName: "web01", OSUser: "root",
			SrcIP: "10.0.0.2", StartedAt: time.Now(), RecordingPath: path, Temporary: c.temp,
		}); err != nil {
			t.Fatal(err)
		}
	}
	rows := listSessions(t, s)
	if v := rowOf(t, rows, "sess-temp")["temporary"]; v != true {
		t.Errorf("hakla açılan oturum listede işaretsiz: %v", rowOf(t, rows, "sess-temp"))
	}
	if _, ok := rowOf(t, rows, "sess-group")["temporary"]; ok {
		t.Errorf("rolle açılan oturumda alan var: %v", rowOf(t, rows, "sess-group"))
	}
	rec := callSessionDetail(t, s, "sess-temp")
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("ayrıntı: %d %v %s", rec.Code, err, rec.Body.String())
	}
	if body["temporary"] != true {
		t.Errorf("ayrıntıda işaret yok: %v", body)
	}
}
