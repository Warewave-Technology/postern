package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/store"
)

/*
 * ⚠️ CLI purge'ü, adı devralan yeni kişiye ÇÖZÜLEN eski oturumu da
 * kapatmalı.
 *
 * Panel purge'ü bellekteki oturumu düşürebiliyordu (af371db). Ama CLI
 * AYRI BİR SÜREÇ: `postern user purge` çalıştığında panel sürecinin
 * bellekteki oturum haritasına dokunamıyor. Oturum yalnızca ADA bağlıysa,
 * ad yeniden yaratıldığında accountStillOpen'ın RefuseIfDeleted(ad)
 * çağrısı YENİ satıra çözülüp nil dönüyordu — ayrılan kişinin sekmesi
 * yeni kişinin hesabında çalışmaya devam ediyordu.
 *
 * Düzeltme oturumu hesap KİMLİĞİNE bağlıyor. Bu test CLI'ın yaptığını
 * store üzerinden birebir yapıyor (SetAccountState + PurgeAccount, panel
 * ucu YOK) ve eski oturumun artık reddedildiğini ölçüyor.
 */
func TestCLIStylePurgeInvalidatesOldPanelSession(t *testing.T) {
	ctx := context.Background()
	db := migratedStore(t)

	if _, err := db.CreateUser(ctx, "ayse", "ayse@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}

	s := New(auth.NewOIDCHolder(), auth.NewLogins(auth.NewOIDCHolder()), db,
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Ayşe'nin oturumu, üretim yoluyla açılıyor (hesap kimliğine bağlı).
	token, err := s.createWebSession(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}

	me := func() int {
		r := httptest.NewRequest(http.MethodGet, "/api/me", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w.Code
	}

	if code := me(); code != http.StatusOK {
		t.Fatalf("oturum baştan çalışmıyor: /api/me = %d", code)
	}

	// ⚠️ CLI'IN YAPTIĞI: store üzerinden, webSessions'a DOKUNMADAN.
	if err := db.SetAccountState(ctx, "ayse", store.StateDeleted); err != nil {
		t.Fatal(err)
	}
	if _, err := db.PurgeAccount(ctx, "ayse", time.Now()); err != nil {
		t.Fatal(err)
	}

	// Aynı adla YENİ kişi.
	if _, err := db.CreateUser(ctx, "ayse", "ayse.yeni@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}

	// ⚠️ ASIL ÖLÇÜM: eski oturum artık reddedilmeli. Ada bağlıyken bu
	// 200 dönüyordu ve dönen kimlik YENİ hesaptı.
	if code := me(); code != http.StatusUnauthorized {
		t.Errorf("CLI purge sonrası eski panel oturumu hâlâ geçerli "+
			"(/api/me = %d): ayrılan kişinin sekmesi, adı devralan yeni "+
			"kişinin hesabında çalışıyor", code)
	}
}

/*
 * ⚠️ HESAP KİMLİĞİNE BAĞLI OLMAYAN OTURUM REDDEDİLİYOR.
 *
 * Kontrolde bir süre "kimlik boşsa ada göre bak" dalı vardı ve gerekçesi
 * şuydu: "yükseltmeden önce açılmış oturumlar herkesi çıkarmasın".
 * Gerekçe yanlıştı — panel oturumları yalnızca bellekte (byToken;
 * kalıcılık yok, tablo yok), yani yükseltme süreci yeniden başlatıp
 * haritayı zaten boşaltıyor ve kimliği boş bir oturum yükseltmeden
 * SONRA var olamaz.
 *
 * O dal hem ulaşılamaz hem de ZAYIF olandı: CLI purge sızıntısı tam
 * olarak ada bakan kontrolden geçiyordu. Bu test, kimliği olmayan bir
 * oturumun artık geçmediğini ölçüyor — fail-closed.
 */
func TestSessionWithoutAccountIDIsRefused(t *testing.T) {
	ctx := context.Background()
	db := migratedStore(t)

	if _, err := db.CreateUser(ctx, "ayse", "ayse@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}

	s := New(auth.NewOIDCHolder(), auth.NewLogins(auth.NewOIDCHolder()), db,
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	// ⚠️ KİMLİK BOŞ: üretim yolları bunu üretmiyor (createWebSession
	// kimliği okuyup hata döndürüyor), o yüzden doğrudan kuruyoruz.
	// Ölçülen şey, böyle bir oturumun yine de geçmemesi.
	token, err := s.webSessions.Create("ayse", "")
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("kimliğe bağlı olmayan oturum geçti (/api/me = %d) — "+
			"oturumun hangi hesaba ait olduğu bilinmeden kabul ediliyor",
			w.Code)
	}
}

/*
 * ⚠️ AYRILAN KİŞİNİN BAYAT SEKMESİ, ADI DEVRALAN KİŞİYİ ÇIKARMAMALI.
 *
 * accountStillOpen reddi KİMLİĞE göre veriyordu ama düşürmeyi ADA göre
 * yapıyordu. Ad serbest bırakıldıktan sonra iki taraf farklı şeye
 * bakıyor: bayat token doğru şekilde reddediliyor, ama aynı çağrı adı
 * devralan yeni kişinin CANLI oturumunu da siliyordu. Yeni çalışan iş
 * ortasında, mesajsız, denetim defterinde açıklaması olmadan panelden
 * atılıyordu — ve bu, ayrılan hesabın bıraktığı her bayat sekme için
 * bir kez daha.
 */
func TestStaleSessionDoesNotEvictTheNewHolderOfTheName(t *testing.T) {
	s, db := dbServer(t)
	ctx := context.Background()

	if _, err := db.CreateUser(ctx, "ayse", "ayse@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}
	eskiID, err := db.AccountID(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	eskiToken, err := s.webSessions.Create("ayse", eskiID)
	if err != nil {
		t.Fatal(err)
	}

	// Ayrılıyor, ad serbest bırakılıyor.
	if err := db.SetAccountState(ctx, "ayse", store.StateDeleted); err != nil {
		t.Fatal(err)
	}
	if _, err := db.PurgeAccount(ctx, "ayse", time.Now()); err != nil {
		t.Fatal(err)
	}

	// Adı yeni bir insan alıyor ve panele giriyor.
	if _, err := db.CreateUser(ctx, "ayse", "yeni@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}
	yeniID, err := db.AccountID(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	yeniToken, err := s.webSessions.Create("ayse", yeniID)
	if err != nil {
		t.Fatal(err)
	}

	// Ayrılan kişinin uyuyan sekmesinden bir istek geliyor.
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/me", nil)
	if s.accountStillOpen(w, r, "ayse", eskiID) {
		t.Fatal("bayat oturum kabul edildi")
	}

	// ⚠️ ASIL İDDİA: yeni sahibin oturumu AYAKTA.
	if _, _, _, err := s.webSessions.ResolveSessionFull(yeniToken); err != nil {
		t.Errorf("adı devralan kişinin canlı oturumu düşürüldü (%v) — "+
			"ayrılan kişinin her bayat sekmesi onu bir kez dışarı atıyor", err)
	}
	// Ve bayat olan gerçekten gitti: ret KALICI olmalı.
	if _, _, _, err := s.webSessions.ResolveSessionFull(eskiToken); err == nil {
		t.Error("bayat oturum bellekte kaldı — bir sonraki istek yine " +
			"veritabanına gidiyor")
	}
}
