package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/warewave/postern/internal/model"
	"github.com/warewave/postern/internal/store"
)

// decode, cevap gövdesini haritaya çevirir.
func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("durum = %d, gövde: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("gövde JSON değil: %v — %s", err, rec.Body.String())
	}
	return out
}

/*
 * ⚠️ `truncated`, EKRANIN EN PAHALI GARANTİSİ VE HİÇBİR GO TESTİ ONU
 * ÖLÇMÜYORDU.
 *
 * ÖLÇÜLDÜ: uçtaki ifade elle `false`'a çevrildiğinde httpapi, store ve
 * cmd dahil BÜTÜN Go testleri yeşil kalıyordu. Panel tarafındaki test
 * ise `api`yi mock'layıp `truncated: true` veriyor ve cümlenin
 * çizildiğini doğruluyor — yani kendi mock'unu doğruluyor, sunucunun ne
 * döndürdüğünü değil.
 *
 * Bayrağın taşıdığı şey şu: kesilmiş bir listeyi tam sanmamak. Yanlış
 * olduğunda ekran, "bu dosyaya bir daha dokunulmamış" diye okunan bir
 * liste gösteriyor — bir denetim aracında verilebilecek en kötü yanlış
 * cevap.
 */
func TestFileHistoryTruncatedTellsTheTruth(t *testing.T) {
	s, db := dbServer(t)

	seedFileEvents(t, db, "/etc/shadow", 5)

	t.Run("sinira dayandiginda true", func(t *testing.T) {
		body := decode(t, callFiles(t, s, "/etc/shadow", "3"))
		if body["truncated"] != true {
			t.Errorf("truncated = %v, true bekleniyordu — 5 olaydan 3'ü "+
				"döndü ve ekran listeyi tam sanacak", body["truncated"])
		}
	})

	t.Run("sinirin altinda false", func(t *testing.T) {
		body := decode(t, callFiles(t, s, "/etc/shadow", "50"))
		if body["truncated"] != false {
			t.Errorf("truncated = %v, false bekleniyordu — liste tam, "+
				"her seferinde uyarmak uyarıyı okunmaz yapar", body["truncated"])
		}
	})
}

/*
 * ⚠️ "BAKAMADIM", "SORUN YOK" DEĞİL — ve bu ekranda fark en pahalısı.
 *
 * adminAuthSourceStatus, eşleme kontrolü çöktüğünde hatayı yalnızca
 * log'a yazıp `unseen_mappings`i boş bırakıyordu. Panel bunu temiz
 * sonuçla birebir aynı çiziyordu. Ekranın tek işi giriş kaynağını
 * değiştirmeye karar vermek ve o, ürünün en kilitlenme eğilimli işlemi.
 *
 * Burada ölçülen şey sunucunun bayrağı GERÇEKTEN kurması: paneldeki
 * test, bayrak verildiğinde doğru cümleyi çizdiğini ölçüyor ama uç onu
 * hiç göndermezse ikisi de yeşil kalırdı.
 */
func TestAuthSourceSaysWhenTheMappingCheckCouldNotRun(t *testing.T) {
	s, _, dsn := dbServerDSN(t)

	rec := httptest.NewRecorder()
	s.adminAuthSourceStatus(rec, httptest.NewRequest(http.MethodGet, "/api/admin/auth/source", nil))
	body := decode(t, rec)
	if body["unseen_error"] != false {
		t.Fatalf("sağlıklı veritabanında unseen_error = %v, false bekleniyordu",
			body["unseen_error"])
	}

	/*
	 * ⚠️ YALNIZCA EŞLEME SORGUSU DÜŞÜRÜLÜYOR — bağlantının tamamı değil.
	 *
	 * Veritabanını kapatmak `loginSource`'u da düşürüyor ve uç 5xx
	 * dönüyor; o yolda bayrağın hiç kurulmaması FARK ETMİYOR, yani
	 * test ölçmek istediği şeyi ölçmüyordu (ölçüldü: bayrağı sabit
	 * `false` yapan mutasyonla test yine geçiyordu).
	 *
	 * Tabloyu düşürmek gerçek bir arıza ve tam olarak doğru yeri
	 * vuruyor: ekranın geri kalanı çiziliyor, yalnızca eşleme kontrolü
	 * cevap veremiyor.
	 */
	dropTable(t, dsn, "group_mappings")

	rec = httptest.NewRecorder()
	s.adminAuthSourceStatus(rec, httptest.NewRequest(http.MethodGet, "/api/admin/auth/source", nil))
	body = decode(t, rec)
	if body["unseen_error"] != true {
		t.Errorf("eşleme sorgusu çöktü ama unseen_error = %v; ekran "+
			"\"kontrol ettim, hepsi yerinde\" ile birebir aynı görünür — "+
			"üstelik giriş kaynağını değiştirme kararının verildiği yerde",
			body["unseen_error"])
	}
	if body["unseen_mappings"] != nil {
		t.Errorf("unseen_mappings = %v; çıkarılamamış bir liste boş "+
			"liste gibi gönderilmemeli", body["unseen_mappings"])
	}
}

// dropTable, tabloyu gerçekten düşürür: tek bir sorgunun çökmesini
// istiyoruz, bağlantının tamamının değil.
func dropTable(t *testing.T, dsn, name string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("DROP TABLE " + name + " CASCADE;"); err != nil {
		t.Fatalf("DROP TABLE %s: %v", name, err)
	}
}

// callFiles, dosya geçmişi ucunu çağırır.
func callFiles(t *testing.T, s *Server, path, limit string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet,
		"/api/admin/files?path="+path+"&limit="+limit, nil)
	rec := httptest.NewRecorder()
	s.adminFileHistory(rec, req)
	return rec
}

// seedFileEvents, aynı yol için n adet SFTP dosya olayı yazar.
func seedFileEvents(t *testing.T, db *store.Store, path string, n int) {
	t.Helper()
	ctx := context.Background()

	if _, err := db.CreateUser(ctx, "ayse", "ayse@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateTarget(ctx, model.Target{
		Name: "web01", Host: "10.0.0.5", Port: 22,
		HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIcLUQM0UcoZdJVh2EokribDvFZyyNyAVURM/LrCugFM",
	}); err != nil {
		t.Fatal(err)
	}

	start := time.Now().Add(-time.Hour)
	for i := range n {
		at := start.Add(time.Duration(i) * time.Minute)
		id := fmt.Sprintf("sess-%02d", i)
		if err := db.StartSession(ctx, store.SessionStart{
			ID: id, Username: "ayse", TargetName: "web01", OSUser: "root",
			SrcIP: "10.0.0.2", StartedAt: at,
		}); err != nil {
			t.Fatalf("StartSession: %v", err)
		}
		if err := db.AddSessionFiles(ctx, id, []store.SessionFile{{
			At: at, Op: "open", Path: path, OK: true,
		}}); err != nil {
			t.Fatalf("AddSessionFiles: %v", err)
		}
	}
}
