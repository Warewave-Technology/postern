package httpapi

// Oturum ayrıntısının "bu liste eksiksiz mi" cevabı (göç 037).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/record"
	"github.com/Warewave-Technology/postern/internal/sftpaudit"
	"github.com/Warewave-Technology/postern/internal/sftpcast"
	"github.com/Warewave-Technology/postern/internal/store"
)

// sessionWithJournal, kaydı olan bir oturum kurar ve defterine satır yazar.
func sessionWithJournal(t *testing.T, s *Server, db *store.Store, id string,
	mark model.SFTPJournal, files []store.SessionFile) {
	t.Helper()
	ctx := context.Background()

	rs, err := record.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.records = rs

	f, path, err := rs.Create(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	seedTargets(t, db, "web01")
	if err := db.StartSession(ctx, store.SessionStart{
		ID: id, Username: "ayse", TargetName: "web01", OSUser: "root",
		SrcIP: "10.0.0.2", StartedAt: time.Now(), RecordingPath: path,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.EndSession(ctx, id, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkSFTPJournal(ctx, id, mark); err != nil {
		t.Fatal(err)
	}
	if len(files) > 0 {
		if err := db.AddSessionFiles(ctx, id, files); err != nil {
			t.Fatal(err)
		}
	}
}

// callSessionDetail, oturum ayrıntısı ucunu çağırır.
func callSessionDetail(t *testing.T, s *Server, id string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/sessions/"+id, nil)
	req.SetPathValue("id", id)
	rec := httptest.NewRecorder()
	s.adminSessionDetail(rec, req)

	return rec
}

/*
 * ⚠️ EKRAN DOSYA LİSTESİNİ EKSİKSİZMİŞ GİBİ GÖSTERİYORDU.
 *
 * Kaydın mühür satırı oturumun kaç dosya olayı ürettiğini söylüyor
 * (proxy/sftpcast.go) ama o sayının programatik bir tüketicisi yoktu.
 * Defterden düşmüş ya da sonradan silinmiş bir satır, panelde yalnızca
 * daha kısa bir liste olarak görünüyordu — ve kısa bir liste, tam bir
 * listeden ayırt edilemez.
 */
func TestSessionDetailSaysWhenTheFileListIsNotComplete(t *testing.T) {
	s, db := dbServer(t)

	sessionWithJournal(t, s, db, "sess-gap",
		// Kayıt üç olay saymış; postern hiçbirini kaybetmemiş.
		model.SFTPJournal{Measured: true, Events: 3},
		[]store.SessionFile{
			{At: time.Now(), Op: "open", Path: "/etc/shadow", OK: true, InRecording: true},
		})

	body := decode(t, callSessionDetail(t, s, "sess-gap"))

	j, ok := body["journal"].(map[string]any)
	if !ok {
		t.Fatalf("cevapta journal bloğu yok: %v", body)
	}
	if j["state"] != "missing" {
		t.Errorf("EKSİK DEFTER TAM GÖSTERİLDİ: state = %v", j["state"])
	}
	if j["events"] != float64(3) || j["rows"] != float64(1) {
		t.Errorf("sayılar taşınmadı: %v", j)
	}
	if j["detail"] == "" {
		t.Error("gerekçe boş: panel yazacak bir cümle bulamaz")
	}
}

/*
 * ⚠️ KANAL DÜZEYİNDEKİ RET SATIRI SAYIMA GİRMEMELİ.
 *
 * Bu satırları ret defteri yazıyor (proxy/lifecycle.go) ve kayıtta
 * karşılıkları YOK. Sayılsalardı, x11 isteği reddedilmiş her SFTP
 * oturumu "defterde mühürden fazla satır var" diye raporlanırdı — yani
 * doğru çalışan bir bastion, kontrolün yanlış alarmıyla suçlanırdı.
 */
func TestSessionDetailDoesNotCountChannelDenialsAgainstTheSeal(t *testing.T) {
	s, db := dbServer(t)

	sessionWithJournal(t, s, db, "sess-ok",
		model.SFTPJournal{Measured: true, Events: 2},
		[]store.SessionFile{
			{At: time.Now(), Op: "open", Path: "/tmp/a", OK: true, InRecording: true},
			{At: time.Now(), Op: "transfer", Path: "/tmp/a", Read: 9, OK: true, InRecording: true},
			{At: time.Now(), Op: "denied.x11-req", OK: false, Detail: "x11 forwarding is off"},
		})

	body := decode(t, callSessionDetail(t, s, "sess-ok"))

	j, ok := body["journal"].(map[string]any)
	if !ok {
		t.Fatalf("cevapta journal bloğu yok: %v", body)
	}
	if j["state"] != "intact" {
		t.Errorf("YANLIŞ ALARM: state = %v, intact bekleniyordu (%v)", j["state"], j["detail"])
	}
	if j["rows"] != float64(2) {
		t.Errorf("rows = %v, 2 bekleniyordu — ret satırı sayılmış", j["rows"])
	}
}

/*
 * ⚠️ ÖLÇÜLMEMİŞ OTURUM ALARM ÜRETMEMELİ.
 *
 * Yükseltmeden önce kapanmış her oturum burada: mühür sayısı yok.
 * Satırlarını "mühürün saymadığı fazlalık" diye göstermek, ilk
 * yükseltmede geçmişin tamamını suçlamak olurdu.
 */
func TestSessionDetailLeavesOlderSessionsAlone(t *testing.T) {
	s, db := dbServer(t)

	sessionWithJournal(t, s, db, "sess-old",
		model.SFTPJournal{},
		[]store.SessionFile{
			{At: time.Now(), Op: "open", Path: "/tmp/a", OK: true},
		})

	body := decode(t, callSessionDetail(t, s, "sess-old"))

	j, ok := body["journal"].(map[string]any)
	if !ok {
		t.Fatalf("cevapta journal bloğu yok: %v", body)
	}
	if j["state"] != "unmeasured" {
		t.Errorf("GÖÇ ÖNCESİ OTURUM SUÇLANDI: state = %v", j["state"])
	}
}

/*
 * ⚠️ DEĞİŞTİRİLMİŞ SATIR PANELDE DE GÖRÜNMELİ.
 *
 * Sayıya bakan bir kontrol bunu göremez: liste tam, satır sayısı doğru,
 * ve değiştirilen satır tam bir denetim kaydı gibi duruyor. Ekranın
 * yalanlaması gereken tam olarak bu görüntü.
 */
func TestSessionDetailSeesAChangedRow(t *testing.T) {
	s, db := dbServer(t)

	// Oturumda gerçekten olan olay /etc/shadow; deftere yazılan satır
	// başka bir yol gösteriyor.
	var seal sftpcast.Seal
	seal.Add(sftpcast.Line(sftpaudit.Event{
		Op: sftpaudit.OpOpen, Path: "/etc/shadow", OK: true,
	}))

	sessionWithJournal(t, s, db, "sess-altered",
		model.SFTPJournal{Measured: true, Events: 1, Digest: seal.Head()},
		[]store.SessionFile{
			{At: time.Now(), Op: "open", Path: "/tmp/notlar", OK: true, InRecording: true},
		})

	body := decode(t, callSessionDetail(t, s, "sess-altered"))

	j, ok := body["journal"].(map[string]any)
	if !ok {
		t.Fatalf("cevapta journal bloğu yok: %v", body)
	}
	if j["state"] != "altered" {
		t.Errorf("DEĞİŞTİRİLMİŞ SATIR GÖRÜLMEDİ: state = %v (%v)", j["state"], j["detail"])
	}
	// Sayılar TUTUYOR: okuyan kişi eksik satır aramasın.
	if j["events"] != float64(1) || j["rows"] != float64(1) {
		t.Errorf("sayılar: %v", j)
	}
	if j["digest_checked"] != true {
		t.Error("özet karşılaştırıldı ama cevap öyle demiyor")
	}
}

/*
 * ⚠️ ÖZETİ HİÇ KARŞILAŞTIRILMAMIŞ OTURUM, KARŞILAŞTIRILMIŞ GİBİ
 * DÖNMEMELİ. Mühürde özet olmayan oturumlar var; onlar için
 * söylenebilecek şey "sayısı tuttu", "içeriği de tuttu" değil.
 */
func TestSessionDetailSaysWhenTheDigestWasNotChecked(t *testing.T) {
	s, db := dbServer(t)

	sessionWithJournal(t, s, db, "sess-nodigest",
		model.SFTPJournal{Measured: true, Events: 1},
		[]store.SessionFile{
			{At: time.Now(), Op: "open", Path: "/tmp/a", OK: true, InRecording: true},
		})

	body := decode(t, callSessionDetail(t, s, "sess-nodigest"))

	j := body["journal"].(map[string]any)
	if j["state"] != "intact" {
		t.Errorf("özetsiz oturum suçlandı: %v", j["state"])
	}
	if j["digest_checked"] != false {
		t.Error("YAPILMAMIŞ KONTROL YAPILMIŞ SAYILDI")
	}
}
