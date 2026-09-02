//go:build integration

package integration

// Yöneticinin canlı bir oturumu kesmesi.
//
//	go test -tags integration -run TestTerminate -v ./test/integration/

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/store"
)

// adminBrowser, panele yönetici olarak girmiş bir HTTP istemcisi döner.
func adminBrowser(t *testing.T, apiURL string, db *store.Store) *http.Client {
	t.Helper()
	ctx := context.Background()
	if err := db.SetUserAdmin(ctx, "yigit", true); err != nil {
		t.Fatal(err)
	}
	if err := db.AllowIdentityBind(ctx, "yigit", time.Now()); err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, c, apiURL)
	return c
}

/*
 * ⚠️ BU TEST, KESMENİN HİÇBİR ŞEY YAPMADIĞI HÂLDE GEÇMEMELİ.
 *
 * Bir durum kodu testi, çalışan bir kesmeyi hiçbir şeyi değiştirmeyen
 * bir 200'den ayırt EDEMEZ. O yüzden ölçtüğümüz şey uçtaki cevap değil:
 * hedefte gerçekten akan bir oturum var, kesme çağrısından sonra o
 * oturumun SSH tarafı kapanıyor mu?
 *
 * Oturum `sleep 300` çalıştırıyor: kendiliğinden bitmesi imkânsız, yani
 * kapanma tek bir şeyin sonucu olabilir.
 */
func TestTerminateClosesALiveSession(t *testing.T) {
	sshAddr, apiURL, hostPub, db := oobBastion(t, 0)
	ctx := context.Background()

	client, err := kiClient(sshAddr, hostPub, browserSignInForCode)
	if err != nil {
		t.Fatalf("OOB girişi: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Start("sleep 300"); err != nil {
		t.Fatalf("uzun komut başlatılamadı: %v", err)
	}

	// Oturum bitene kadar bekleyen gözcü: kesme çalışmazsa buraya
	// hiçbir şey düşmez ve test zaman aşımıyla düşer.
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()

	id := waitForOpenSession(t, db)

	// ⚠️ ÖNCE AKTIĞINI GÖSTER: bu satır olmadan test, oturumun zaten
	// ölü olması yüzünden de geçerdi.
	select {
	case err := <-done:
		t.Fatalf("oturum kesilmeden önce bitmiş: %v", err)
	case <-time.After(500 * time.Millisecond):
	}

	browser := adminBrowser(t, apiURL, db)
	code, msg := postJSON(t, browser, apiURL+"/api/admin/sessions/"+id+"/terminate", nil)
	if code != http.StatusOK {
		t.Fatalf("terminate = %d (%s)", code, msg)
	}

	select {
	case <-done:
		// Kesildi.
	case <-time.After(20 * time.Second):
		t.Fatal("KESME İŞE YARAMADI: `sleep 300` hâlâ akıyor")
	}

	// Denetim satırı da kapanmalı: aksi hâlde panel oturumu süresiz
	// "çalışıyor" göstermeye devam ederdi.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		s, serr := db.Session(ctx, id)
		if serr == nil && !s.Open() {
			break
		}
		time.Sleep(200 * time.Millisecond)
		if time.Now().After(deadline.Add(-200 * time.Millisecond)) {
			t.Fatal("kesilen oturumun ended_at'i yazılmadı")
		}
	}

	// ⚠️ KİM KESTİ, DEFTERDE OLMALI. Yöneticinin izsiz iş yapabildiği
	// bir yol, denetim iddiasının tamamını boşa çıkarır.
	entries, err := db.AdminLog(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range entries {
		if e.Action == "session.terminate" && e.Entity == id {
			found = true
			if e.Actor == "" {
				t.Error("denetim satırı aktörsüz")
			}
		}
	}
	if !found {
		t.Error("session.terminate denetim satırı yazılmamış")
	}
}

/*
 * ⚠️ BİTMİŞ OTURUM "KESİLDİ" CEVABI ALMAMALI.
 *
 * Aksi hâlde panel, olmamış bir işi olmuş gösterirdi — bu özelliğin en
 * kolay yalan söyleme biçimi.
 */
func TestTerminateRefusesAnEndedSession(t *testing.T) {
	sshAddr, apiURL, hostPub, db := oobBastion(t, 0)

	client, err := kiClient(sshAddr, hostPub, browserSignInForCode)
	if err != nil {
		t.Fatalf("OOB girişi: %v", err)
	}
	s, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Output("echo bitti"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	client.Close()

	id := waitForClosedSession(t, db)

	browser := adminBrowser(t, apiURL, db)
	code, msg := postJSON(t, browser, apiURL+"/api/admin/sessions/"+id+"/terminate", nil)
	if code != http.StatusConflict {
		t.Fatalf("terminate = %d (%s), 409 bekleniyordu", code, msg)
	}
	if !strings.Contains(strings.ToLower(msg), "already ended") {
		t.Errorf("mesaj sebebi söylemiyor: %q", msg)
	}
}

// Bilinmeyen kimlik 404 — ve canlılık bilgisi SIZMAMALI: var olmayan bir
// oturum için "çalışmıyor" demek, kimliğin var olduğunu doğrulardı.
func TestTerminateUnknownSessionIsNotFound(t *testing.T) {
	_, apiURL, _, db := oobBastion(t, 0)
	browser := adminBrowser(t, apiURL, db)

	code, msg := postJSON(t, browser,
		apiURL+"/api/admin/sessions/0123456789abcdef0123456789abcdef/terminate", nil)
	if code != http.StatusNotFound {
		t.Fatalf("terminate = %d (%s), 404 bekleniyordu", code, msg)
	}
}

// Yönetici olmayan kesemez.
func TestTerminateRequiresAdmin(t *testing.T) {
	_, apiURL, _, db := oobBastion(t, 0)
	_ = db

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, c, apiURL)

	code, _ := postJSON(t, c,
		apiURL+"/api/admin/sessions/0123456789abcdef0123456789abcdef/terminate", nil)
	if code != http.StatusForbidden && code != http.StatusUnauthorized {
		t.Fatalf("terminate = %d — yönetici olmayan kesebildi", code)
	}
}

/*
 * waitForOpenSession, AÇIK tek oturumun kimliğini bekler.
 *
 * ⚠️ Açık olanı arıyor: kapanmışını da kabul etseydi, kesme testi
 * zaten bitmiş bir oturumu "kesmeye" çalışır ve kendi konusunu ölçmezdi.
 */
func waitForOpenSession(t *testing.T, db *store.Store) string {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		rows, err := db.Sessions(context.Background(), "", 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if r.Open() {
				return r.ID
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("açık oturum görünmedi")
	return ""
}

// waitForClosedSession, KAPANMIŞ tek oturumun kimliğini bekler.
func waitForClosedSession(t *testing.T, db *store.Store) string {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		rows, err := db.Sessions(context.Background(), "", 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if !r.Open() {
				return r.ID
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("kapanmış oturum görünmedi")
	return ""
}

var _ = ssh.PublicKey(nil)
