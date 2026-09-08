package httpapi

// Liste ucunun taşıdığı iki kanıt sayısı: kayıp ve ret (göç 037/038).

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

// closedSession, kapanmış bir oturum kurup defter işaretini yazar.
func closedSession(t *testing.T, db *store.Store, id string, mark model.SFTPJournal) {
	t.Helper()
	ctx := context.Background()
	startSession(t, db, id, "web01", time.Now())
	if err := db.EndSession(ctx, id, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkSFTPJournal(ctx, id, mark); err != nil {
		t.Fatal(err)
	}
}

// listSessions, liste ucunu çağırıp satırları döndürür.
func listSessions(t *testing.T, s *Server) []map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	s.adminListSessions(rec, httptest.NewRequest(http.MethodGet, "/api/admin/sessions", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("durum = %d, gövde: %s", rec.Code, rec.Body.String())
	}
	var out []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("gövde JSON dizisi değil: %v — %s", err, rec.Body.String())
	}
	return out
}

// rowOf, listede verilen kimliği bulur.
func rowOf(t *testing.T, rows []map[string]any, id string) map[string]any {
	t.Helper()
	for _, r := range rows {
		if r["id"] == id {
			return r
		}
	}
	t.Fatalf("oturum listede yok: %s (%v)", id, rows)
	return nil
}

/*
 * ⚠️ DENETÇİNİN LİSTEYE GELİRKEN SORDUĞU SORU "HANGİSİNİ AÇAYIM" VE
 * LİSTE ONU HİÇ CEVAPLAMIYORDU.
 *
 * /etc/shadow'un reddedildiği bir oturum, hiçbir şey yapılmamış bir
 * oturumla birebir aynı görünüyordu; fark ancak satır açılıp dosya
 * olaylarına bakılınca çıkıyordu. 200 oturumluk bir listede bu, 200
 * tıklama demek — yani pratikte hiç bakılmamak.
 */
func TestSessionListCarriesTheTwoEvidenceCounts(t *testing.T) {
	s, db := dbServer(t)
	seedTargets(t, db, "web01")

	closedSession(t, db, "sess-kanit",
		model.SFTPJournal{Measured: true, Events: 2, Lost: 3, Denied: 4, Counted: true})

	row := rowOf(t, listSessions(t, s), "sess-kanit")

	if row["lost"] != float64(3) {
		t.Errorf("KAYIP LİSTEYE TAŞINMADI: lost = %v", row["lost"])
	}
	if row["denied"] != float64(4) {
		t.Errorf("RET LİSTEYE TAŞINMADI: denied = %v", row["denied"])
	}
}

/*
 * ⚠️ SAYILMAMIŞ RET, SIFIR OLARAK GİTMEMELİ — ve bu ayrım YALNIZCA
 * burada ölçülebiliyor.
 *
 * Göç 038'den önce kapanmış her oturumda sayım yapılmadı. Alan 0 olarak
 * gitseydi panel "hiçbir şey reddedilmedi" diye okurdu; yani yapılmamış
 * bir kontrol yapılmış sayılırdı. Sayılmış bir SIFIR ise gerçek bir
 * cevap ve alanın kendisi cevapta DURMALI: ikisini ayıran tek şey,
 * anahtarın var olup olmaması.
 */
func TestSessionListKeepsUncountedDenialsApartFromZero(t *testing.T) {
	s, db := dbServer(t)
	seedTargets(t, db, "web01")

	// Sayım yapılmamış oturum (göç öncesi ya da SFTP hiç kurulmamış).
	closedSession(t, db, "sess-sayilmadi",
		model.SFTPJournal{Measured: true, Events: 0, Counted: false})

	// Sayılmış ve gerçekten hiç ret olmamış oturum.
	closedSession(t, db, "sess-sifir",
		model.SFTPJournal{Measured: true, Events: 0, Denied: 0, Counted: true})

	rows := listSessions(t, s)

	if _, ok := rowOf(t, rows, "sess-sayilmadi")["denied"]; ok {
		t.Error("SAYILMAYAN RET CEVAPTA GÖRÜNDÜ: bilinmeyen, iyi habere çevrildi")
	}
	zero, ok := rowOf(t, rows, "sess-sifir")["denied"]
	if !ok {
		t.Fatal("SAYILMIŞ SIFIR CEVAPTAN DÜŞTÜ: gerçek bir cevap kayboldu")
	}
	if zero != float64(0) {
		t.Errorf("sayılmış sıfır bozuldu: denied = %v", zero)
	}
}
