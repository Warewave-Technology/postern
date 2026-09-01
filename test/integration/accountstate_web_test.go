//go:build integration

package integration

// Panel oturumunun hesabın durumunu HER İSTEKTE okuduğunun kanıtı.
//
//	go test -tags integration -run TestWebSession -v ./test/integration/

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/warewave/postern/internal/store"
)

/*
 * ⚠️ SİLİNEN HESABIN AÇIK PANELİ ANINDA DURMALI.
 *
 * ÖLÇÜLEN ARIZA: hesap 'deleted' yapıldıktan sonra /api/me hâlâ 200 ve
 * hedef listesiyle dönüyordu; /api/terminal/web01 gerçekten açılıyor ve
 * hedefin karşılama afişi geliyordu ("Welcome to Alpine!"). Yönetici
 * "sil"e basıp SSH kapısının kapandığını görüyor, erişimin bittiğini
 * sanıyordu — oysa açık sekmesi olan kişi kabuk açmaya devam ediyordu.
 * Sınır, web oturumunun 12 saatlik ömrüydü.
 */
func TestWebSessionStopsWhenAccountIsDeleted(t *testing.T) {
	_, apiURL, _, db := oobBastionWithTerminal(t)
	ctx := context.Background()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)

	// ⚠️ ÖNCE ÇALIŞTIĞINI GÖSTER: bu satır olmadan test, girişin
	// sessizce başarısız olması yüzünden de geçerdi.
	if _, status := fetchMe(t, client, apiURL); status != http.StatusOK {
		t.Fatalf("silmeden önce /api/me = %d — test kendi konusunu ölçemez", status)
	}
	conn, _, derr := dialTerminal(t, client, apiURL, "web01", apiURL)
	if derr != nil {
		t.Fatalf("silmeden önce terminal açılamadı: %v — test kendi konusunu ölçemez", derr)
	}
	conn.Close(websocket.StatusNormalClosure, "")

	if err := db.SetAccountState(ctx, kcUser, store.StateDeleted); err != nil {
		t.Fatal(err)
	}

	if _, status := fetchMe(t, client, apiURL); status != http.StatusUnauthorized {
		t.Errorf("/api/me = %d, 401 bekleniyordu — silinmiş hesabın paneli çalışıyor", status)
	}

	// Asıl mesele: kabuk açılabiliyor mu?
	conn2, resp, err := dialTerminal(t, client, apiURL, "web01", apiURL)
	if err == nil {
		conn2.Close(websocket.StatusNormalClosure, "")
		t.Fatal("silinmiş hesap terminal açtı")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		code := 0
		if resp != nil {
			code = resp.StatusCode
		}
		t.Errorf("terminal reddi %d ile geldi, 401 bekleniyordu", code)
	}
}

/*
 * ⚠️ 'inactive' REDDEDİLMEMELİ — VE BU BİLİNÇLİ.
 *
 * Pasifleşme "kaynak bir süredir doğrulamadı" demek; başarılı girişin
 * kendisi o doğrulama (accountstate.go:160). Oturum ara katmanına
 * girişten DAHA SIKI bir kural koymak sıkılaştırma olmazdı: kişi çıkıp
 * yeniden girerek aynı yere gelirdi. Bu test, birinin ileride
 * RefuseIfDeleted'ı ActiveUser'la değiştirip tatilden dönen herkesi
 * yöneticinin kuyruğuna sokmasını engelliyor.
 */
func TestWebSessionSurvivesInactive(t *testing.T) {
	_, apiURL, _, db := oobBastionFresh(t)
	ctx := context.Background()

	if _, err := db.CreateRole(ctx, "ops"); err != nil {
		t.Fatal(err)
	}
	if err := db.GrantTarget(ctx, "ops", "web01"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddGroupMapping(ctx, "sysadmins", "ops", "test"); err != nil {
		t.Fatal(err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)

	if _, status := fetchMe(t, client, apiURL); status != http.StatusOK {
		t.Fatalf("pasifleştirmeden önce /api/me = %d", status)
	}

	if err := db.SetAccountState(ctx, kcUser, store.StateInactive); err != nil {
		t.Fatal(err)
	}

	if _, status := fetchMe(t, client, apiURL); status != http.StatusOK {
		t.Errorf("/api/me = %d, 200 bekleniyordu — 'inactive' kapı dışına atıldı", status)
	}
}
