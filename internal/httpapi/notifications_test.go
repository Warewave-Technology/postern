package httpapi

/*
 * Bildirimler ucu. Ölçülen şey liste değil, listenin KURALLARI: bekleyen
 * iş kaybolduğunda satır da kaybolmalı, bir kaynak düştüğünde öbürleri
 * yine görünmeli, ve uç yalnızca yöneticiye açık olmalı.
 */

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/store"
)

func notifications(t *testing.T, s *Server) (*httptest.ResponseRecorder, []map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/admin/notifications", nil)
	w := httptest.NewRecorder()
	s.adminNotifications(w, asAdmin(r))

	var body struct {
		Items []map[string]any `json:"items"`
		Count int              `json:"count"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.Count != len(body.Items) {
		t.Errorf("sayı ile satır sayısı ayrışmış: %d ve %d", body.Count, len(body.Items))
	}

	return w, body.Items
}

/*
 * ⚠️ İŞ YAPILINCA BİLDİRİM DE GİDİYOR — "okundu" işareti olmadan.
 *
 * Liste her çağrıda durumdan türetiliyor; kalıcı bir bildirim tablosu
 * olsaydı onaylanmış bir kimliğin satırı, biri onu elle kapatana kadar
 * ekranda kalırdı. Bayat bir uyarı listesi, bir süre sonra okunmayan bir
 * listedir — ölçtüğümüz şey tam olarak bu: satırın kaybolma şartı, işin
 * yapılmış olması.
 */
func TestANotificationDisappearsWhenTheWorkIsDone(t *testing.T) {
	s, db := dbServer(t)
	ctx := t.Context()

	// RecordPending damgayı kendi koyuyor ve DURUM döndürüyor, kimlik
	// değil: kuyruktaki satırın kimliği listeden okunuyor.
	if _, err := db.RecordPending(ctx, store.PendingUser{
		Subject: "oidc|1", Source: "oidc", Username: "hasan", Email: "hasan@example.com",
	}); err != nil {
		t.Fatal(err)
	}
	queue, err := db.ListPending(ctx)
	if err != nil || len(queue) != 1 {
		t.Fatalf("kuyruk: %v %+v", err, queue)
	}
	id := queue[0].ID

	_, items := notifications(t, s)
	if len(items) != 1 || items[0]["kind"] != "identity.pending" {
		t.Fatalf("onay bekleyen kimlik listede yok: %+v", items)
	}
	if sum, _ := items[0]["summary"].(string); !strings.Contains(sum, "hasan") {
		t.Errorf("satır kimi beklettiğini söylemiyor: %q", sum)
	}
	/*
	 * ⚠️ DAMGA BEKLEMENİN BAŞLANGICI, RAPORUN ÜRETİLDİĞİ AN DEĞİL.
	 * Türetilmiş bir listede "şimdi" yazmak kolay ve hiçbir şey
	 * söylemez; üç gündür bekleyen bir onay ile beş dakikalık onay aynı
	 * aciliyette değil. Ölçüsü: satır iki ayrı çağrıda AYNI damgayı
	 * taşımalı — üretim anı olsaydı ikincisi ilerlerdi.
	 */
	first, _ := time.Parse(time.RFC3339Nano, items[0]["at"].(string))
	if !first.Equal(queue[0].FirstSeen) {
		t.Errorf("damga kuyruktaki ilk görülme değil: %s ve %s", first, queue[0].FirstSeen)
	}
	time.Sleep(1100 * time.Millisecond)
	_, again := notifications(t, s)
	second, _ := time.Parse(time.RFC3339Nano, again[0]["at"].(string))
	if !second.Equal(first) {
		t.Errorf("damga her çağrıda ilerliyor: %s sonra %s", first, second)
	}

	if _, err := db.ApprovePending(ctx, id, "hasan", "ops"); err != nil {
		t.Fatal(err)
	}
	if _, items := notifications(t, s); len(items) != 0 {
		t.Errorf("onaylandıktan sonra satır duruyor: %+v", items)
	}
}

/*
 * ⚠️ OKUNAMAYAN HER KAYNAK KENDİ SATIRINI BIRAKIYOR — sayısı sayılıyor.
 *
 * Tek bir sorgunun hatası bütün listeyi boşaltsaydı, keşif tablosundaki
 * bir arıza "onay bekleyen kimlik yok" diye okunurdu: bir arıza, bir
 * güvence gibi görünürdü. Sessizce yutulan bir kaynak da aynı kapıya
 * çıkıyor, çünkü geriye kalan liste eksik olduğunu söylemiyor.
 *
 * ÖLÇÜ ÜÇ SATIR, "en az bir" DEĞİL: kapalı bağlamda üç kaynağın üçü de
 * düşüyor, dolayısıyla üçü de kendi satırını yazmak zorunda. "En az bir"
 * diyen bir eşik, dallardan birinin sessizce silinmesini yakalamıyordu —
 * ölçüldü (mutasyon hayatta kaldı).
 */
func TestEverySourceThatCannotBeReadLeavesItsOwnRow(t *testing.T) {
	s, db := dbServer(t)
	if _, err := db.RecordPending(t.Context(), store.PendingUser{
		Subject: "oidc|2", Source: "oidc", Username: "ayse",
		FirstSeen: time.Now(), LastSeen: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	// Keşif sorgusu düşsün: kapalı bir bağlantı, hatanın en sade hâli.
	closed, cancel := context.WithCancel(t.Context())
	cancel()
	r := httptest.NewRequest(http.MethodGet, "/api/admin/notifications", nil).WithContext(closed)
	w := httptest.NewRecorder()
	s.adminNotifications(w, asAdmin(r))
	if w.Code != http.StatusOK {
		t.Fatalf("durum: %d, liste yine dönmeliydi: %s", w.Code, w.Body.String())
	}
	var body struct {
		Items []map[string]any `json:"items"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)

	/*
	 * ⚠️ SAYI DEĞİL KÜMEsi ölçülüyor. Sabit bir sayı, dördüncü bir
	 * kaynak eklendiğinde testi kırar ve düzeltmenin en kolay yolu
	 * sayıyı büyütmek olur — yani iddia, yeni kaynağın da satır bıraktığı
	 * OLMAKTAN çıkar. Burada beklenen bölümler adlarıyla yazılı: yeni bir
	 * kaynak eklenince bu listeye de eklenmesi gerekiyor, ve bu bilinçli
	 * bir adım.
	 */
	want := map[string]bool{"discovery": false, "pending": false, "jit": false, "hostaccounts": false}
	for _, it := range body.Items {
		if it["kind"] != "error" {
			continue
		}
		if d, _ := it["detail"].(string); d == "" {
			t.Error("okunamayan kaynağın sebebi yazılmamış")
		}
		if sec, _ := it["section"].(string); sec != "" {
			if _, known := want[sec]; !known {
				t.Errorf("bilinmeyen bölüm satır bıraktı: %q", sec)
			}
			want[sec] = true
		}
	}
	for sec, seen := range want {
		if !seen {
			t.Errorf("%q kaynağı okunamadı ama satır bırakmadı", sec)
		}
	}
}

/* Uç yönetici ve aynı köken kapılarının arkasında. */
func TestNotificationsAreBehindTheAdminGate(t *testing.T) {
	s, _ := dbServer(t)
	mux := http.NewServeMux()
	s.registerNotificationRoutes(mux)

	r := httptest.NewRequest(http.MethodGet, "/api/admin/notifications", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code == http.StatusOK {
		t.Errorf("oturumsuz istek geçti: %d", w.Code)
	}
}

/*
 * ⚠️ "YENİ" SAYISI SUNUCUDA, LİSTEYLE AYNI KURALDAN ÇIKIYOR.
 *
 * Rozetin sayısı ile sayfanın içeriği ayrışırsa — "rozet üç diyor ama
 * sayfada iki satır var" — rozete bir daha kimse güvenmez. Ölçülen şey:
 * bakış damgasından SONRA beklemeye başlayan satırlar yeni, öncekiler
 * değil; ve liste her iki hâlde de eksiksiz dönüyor.
 */
func TestOnlyWhatStartedWaitingSinceYouLookedCountsAsNew(t *testing.T) {
	s, db := dbServer(t)
	ctx := t.Context()

	if _, err := db.CreateUser(ctx, "ops", "", "ops"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RecordPending(ctx, store.PendingUser{
		Subject: "oidc|1", Source: "oidc", Username: "hasan", Email: "hasan@example.com",
	}); err != nil {
		t.Fatal(err)
	}

	// Hiç bakılmamış: bekleyen her şey yeni.
	if _, unread, _ := notificationCounts(t, s); unread != 1 {
		t.Fatalf("hiç bakılmamışken unread = %d, 1 bekleniyordu", unread)
	}

	// Bakıldı: satır DURUYOR ama artık yeni değil.
	r := httptest.NewRequest(http.MethodPost, "/api/admin/notifications/read", nil)
	w := httptest.NewRecorder()
	s.adminNotificationsRead(w, asAdmin(r))
	if w.Code != http.StatusNoContent {
		t.Fatalf("read ucu %d döndü", w.Code)
	}

	count, unread, _ := notificationCounts(t, s)
	if count != 1 {
		t.Errorf("bakınca satır kayboldu: count = %d", count)
	}
	if unread != 0 {
		t.Errorf("bakıldıktan sonra unread = %d", unread)
	}
}

/*
 * ⚠️ BİR KİŞİNİN BAKMASI ÖBÜRÜNÜN ROZETİNİ SÖNDÜRMÜYOR. Damga kişi
 * başına; ortak olsaydı, listeyi hiç görmemiş bir yönetici onu hiç
 * göremezdi çünkü rozet çoktan sıfırlanmış olurdu.
 */
func TestOneAdminLookingDoesNotClearAnothersBadge(t *testing.T) {
	s, db := dbServer(t)
	ctx := t.Context()

	for _, n := range []string{"ops", "veli"} {
		if _, err := db.CreateUser(ctx, n, "", n); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.RecordPending(ctx, store.PendingUser{
		Subject: "oidc|1", Source: "oidc", Username: "hasan", Email: "hasan@example.com",
	}); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodPost, "/api/admin/notifications/read", nil)
	s.adminNotificationsRead(httptest.NewRecorder(), asAdmin(r))

	// Öbür yönetici hâlâ yeni görüyor.
	get := httptest.NewRequest(http.MethodGet, "/api/admin/notifications", nil)
	w := httptest.NewRecorder()
	s.adminNotifications(w, get.WithContext(context.WithValue(get.Context(), ctxUser, "veli")))
	var body struct{ Unread int }
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.Unread != 1 {
		t.Errorf("öbür yöneticinin rozeti söndü: unread = %d", body.Unread)
	}
}

// notificationCounts, listeyi ve iki sayacı okur.
func notificationCounts(t *testing.T, s *Server) (int, int, []map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/admin/notifications", nil)
	w := httptest.NewRecorder()
	s.adminNotifications(w, asAdmin(r))

	var body struct {
		Items  []map[string]any `json:"items"`
		Count  int              `json:"count"`
		Unread int              `json:"unread"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)

	return body.Count, body.Unread, body.Items
}
