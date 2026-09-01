//go:build integration

package integration

// S4.1'in "Bitti" kanıtı: tarayıcı IdP üzerinden giriş yapıyor, cookie
// alıyor, /api/me kimliğini söylüyor, logout oturumu düşürüyor.
//
//	go test -tags integration -run TestWebLogin -v ./test/integration/

import (
	"context"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/warewave/postern/internal/store"
)

// browserSignIn, login yolculuğunun tamamını yürütür: /auth/login →
// IdP formu → callback → SPA'ya dönüş. Çerezler jar'da birikir.
func browserSignIn(t *testing.T, client *http.Client, apiURL string) {
	t.Helper()

	resp, err := client.Get(apiURL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login zinciri %d ile bitti; sayfa: %.300s", resp.StatusCode, page)
	}

	m := regexp.MustCompile(`<form[^>]+action="([^"]+)"`).FindSubmatch(page)
	if m == nil {
		t.Fatalf("IdP login formu yok; sayfa: %.500s", page)
	}
	resp, err = client.PostForm(html.UnescapeString(string(m[1])), url.Values{
		"username": {kcUser},
		"password": {kcPassword},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	// Zincirin sonu SPA: callback 302 / verdi, istemci takip etti.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("callback zinciri %d ile bitti; sayfa: %.300s", resp.StatusCode, body)
	}
}

type meResponse struct {
	Name    string   `json:"name"`
	OSUser  string   `json:"os_user"`
	Admin   bool     `json:"admin"`
	Targets []string `json:"targets"`

	// Zorunlu parola değişikliği: panel bunu görürse başka hiçbir şey
	// çizmiyor ve sunucu başka hiçbir uca izin vermiyor.
	MustChangePassword bool `json:"must_change_password"`
}

func fetchMe(t *testing.T, client *http.Client, apiURL string) (meResponse, int) {
	t.Helper()

	resp, err := client.Get(apiURL + "/api/me")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var me meResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
			t.Fatalf("me JSON: %v", err)
		}
	}
	return me, resp.StatusCode
}

func TestWebLoginEndToEnd(t *testing.T) {
	_, apiURL, _, _ := oobBastion(t, 0)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}

	// Oturumsuz /api/me: 401 — SPA bunu görüp login düğmesi gösterecek.
	if _, status := fetchMe(t, client, apiURL); status != http.StatusUnauthorized {
		t.Fatalf("oturumsuz /api/me = %d, beklenen 401", status)
	}

	browserSignIn(t, client, apiURL)

	me, status := fetchMe(t, client, apiURL)
	if status != http.StatusOK {
		t.Fatalf("girişli /api/me = %d", status)
	}
	if me.Name != "yigit" || me.OSUser != "postern" {
		t.Errorf("me = %+v — DB'deki kullanıcıyla eşleşmiyor", me)
	}
	if me.Admin {
		t.Error("admin bayrağı verilmeden true döndü")
	}
	if len(me.Targets) != 1 || me.Targets[0] != "web01" {
		t.Errorf("targets = %v, beklenen [web01]", me.Targets)
	}

	// Logout: oturum düşer, cookie geçersizleşir.
	resp, err := client.Post(apiURL+"/auth/logout", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if _, status := fetchMe(t, client, apiURL); status != http.StatusUnauthorized {
		t.Fatalf("logout sonrası /api/me = %d, beklenen 401", status)
	}
}

// Cookie öznitelikleri sözleşmenin parçası: HttpOnly değilse XSS oturumu
// çalar; bu yüzden test konusu. Callback'in 302 cevabındaki Set-Cookie
// başlığına bakılır — cookie jar öznitelikleri saklamaz.
func TestWebSessionCookieIsHttpOnly(t *testing.T) {
	_, apiURL, _, _ := oobBastion(t, 0)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Yönlendirmeyi callback'in CEVABINDA durdur: "/"e gitmeden Set-Cookie
	// başlığını görebilelim.
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Path == "/" {
				return http.ErrUseLastResponse
			}
			return nil
		}}

	resp, err := client.Get(apiURL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := regexp.MustCompile(`<form[^>]+action="([^"]+)"`).FindSubmatch(page)
	if m == nil {
		t.Fatalf("IdP formu yok; sayfa: %.300s", page)
	}

	resp, err = client.PostForm(html.UnescapeString(string(m[1])), url.Values{
		"username": {kcUser}, "password": {kcPassword},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var found bool
	for _, sc := range resp.Header.Values("Set-Cookie") {
		if !strings.HasPrefix(sc, sessionCookieName+"=") {
			continue
		}
		found = true
		if !regexp.MustCompile(`(?i)httponly`).MatchString(sc) {
			t.Errorf("oturum cookie'si HttpOnly değil: %s", sc)
		}
		if !regexp.MustCompile(`(?i)samesite`).MatchString(sc) {
			t.Errorf("oturum cookie'sinde SameSite yok: %s", sc)
		}
	}
	if !found {
		t.Fatalf("callback cevabında %s cookie'si yok; başlıklar: %v",
			sessionCookieName, resp.Header.Values("Set-Cookie"))
	}
}

const sessionCookieName = "postern_session"

// browserSignInExpectingDenial, giriş zincirini sürer ama sonunda 403
// bekler: IdP kimliği doğruladı, postern erişimi reddetti.
func browserSignInExpectingDenial(t *testing.T, client *http.Client, apiURL string) {
	t.Helper()

	resp, err := client.Get(apiURL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	m := regexp.MustCompile(`<form[^>]+action="([^"]+)"`).FindSubmatch(page)
	if m == nil {
		t.Fatalf("IdP login formu yok; sayfa: %.500s", page)
	}
	resp, err = client.PostForm(html.UnescapeString(string(m[1])), url.Values{
		"username": {kcUser},
		"password": {kcPassword},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("callback zinciri %d ile bitti, beklenen 403; sayfa: %.300s", resp.StatusCode, body)
	}
}

/*
 * ⚠️ ERİŞİMİ OLMAYAN HEDEF, OLMAYAN HEDEFLE AYNI CEVABI VERMELİ.
 *
 * Yeni hedef sayfası (/api/targets/{name}) kullanıcının kendi hedefini
 * gösteriyor. "Bu hedef var ama sana kapalı" demek, adları tek tek
 * deneyen birine ENVANTERİ ÇIKARMA imkânı verirdi — bir bastion'ın
 * gizlemek için var olduğu şeyin ta kendisi. İkisi de 404.
 */
func TestOwnTargetDetailHidesTargetsYouCannotReach(t *testing.T) {
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
	// Kullanıcının ERİŞEMEDİĞİ bir hedef.
	if _, err := db.CreateTarget(ctx, yasakTarget()); err != nil {
		t.Fatal(err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)

	// Erişilebilen hedef: 200 ve adres YOK.
	code, body := meReq(t, client, "GET", apiURL+"/api/targets/web01", "")
	if code != http.StatusOK {
		t.Fatalf("kendi hedefi = %d %s", code, body)
	}
	/*
	 * ⚠️ ADRES SIZMIYOR. Kullanıcı hedefe postern üzerinden bağlanıyor
	 * ve ağ topolojisini bilmesi gerekmiyor; adresi vermek bastion'ın
	 * varlık sebebini panelden delerdi.
	 */
	for _, leak := range []string{"host", "port", "127.0.0.1"} {
		if strings.Contains(body, leak) {
			t.Errorf("hedef detayı %q sızdırıyor: %s", leak, body)
		}
	}

	// Erişilemeyen hedef ve HİÇ OLMAYAN hedef: aynı cevap.
	forbidden, fbody := meReq(t, client, "GET", apiURL+"/api/targets/yasak01", "")
	missing, mbody := meReq(t, client, "GET", apiURL+"/api/targets/hicyok", "")

	if forbidden != http.StatusNotFound {
		t.Errorf("erişilemeyen hedef = %d, 404 bekleniyordu: %s", forbidden, fbody)
	}
	if missing != http.StatusNotFound {
		t.Errorf("olmayan hedef = %d, 404 bekleniyordu: %s", missing, mbody)
	}
	if fbody != mbody {
		t.Errorf("iki cevap AYRIŞIYOR — varlık ele veriliyor:\n var ama kapalı: %s\n hiç yok      : %s",
			fbody, mbody)
	}
}

// Oturum geçmişi YALNIZCA kendisinin: aynı hedefe başkasının ne zaman
// bağlandığı bir denetim sorusu ve yönetici ekranında duruyor.
func TestOwnTargetDetailShowsOnlyYourOwnSessions(t *testing.T) {
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

	// BAŞKA bir kullanıcının aynı hedefteki oturumu.
	if _, err := db.CreateUser(ctx, "baskasi", "", "baskasi"); err != nil {
		t.Fatal(err)
	}
	if err := db.StartSession(ctx, store.SessionStart{
		ID: "digerinin-oturumu", Username: "baskasi", TargetName: "web01",
		OSUser: "baskasi", SrcIP: "10.0.0.9", StartedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	_, body := meReq(t, client, "GET", apiURL+"/api/targets/web01", "")
	if strings.Contains(body, "digerinin-oturumu") || strings.Contains(body, "baskasi") {
		t.Fatalf("başkasının oturumu sızdı: %s", body)
	}
}

/*
 * ⚠️ SAYFA YALNIZCA BU HEDEFTEKİ OTURUMLARI GÖSTERMELİ.
 *
 * Kullanıcının kendi geçmişi tek sorguda geliyor ve hedefe göre
 * eleniyor. Eleme düşerse sayfa "senin bu hedefteki oturumların"
 * başlığı altında BAŞKA hedeflerdekileri de listeler — okuyan kişi
 * bu makineye hiç bağlanmadığı hâlde bağlanmış sanır.
 */
func TestOwnTargetDetailShowsOnlyThisTargetsSessions(t *testing.T) {
	_, apiURL, _, db := oobBastionFresh(t)
	ctx := context.Background()

	if _, err := db.CreateRole(ctx, "ops"); err != nil {
		t.Fatal(err)
	}
	for _, tn := range []string{"web01"} {
		if err := db.GrantTarget(ctx, "ops", tn); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.AddGroupMapping(ctx, "sysadmins", "ops", "test"); err != nil {
		t.Fatal(err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)

	// İkinci bir hedef ve KULLANICININ orada bir oturumu.
	other := yasakTarget()
	other.Name = "baska01"
	if _, err := db.CreateTarget(ctx, other); err != nil {
		t.Fatal(err)
	}
	if err := db.StartSession(ctx, store.SessionStart{
		ID: "baska-hedefteki-oturum", Username: kcUser, TargetName: "baska01",
		OSUser: kcUser, SrcIP: "10.0.0.5", StartedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	_, body := meReq(t, client, "GET", apiURL+"/api/targets/web01", "")
	if strings.Contains(body, "baska-hedefteki-oturum") {
		t.Fatalf("başka hedefteki oturum bu sayfada göründü: %s", body)
	}
}
