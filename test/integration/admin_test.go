//go:build integration

package integration

// S4.2'nin "Bitti" kanıtı: admin, tarayıcı oturumuyla kullanıcı/rol/hedef
// yönetiyor; admin olmayan 403 yiyor; her değişiklik admin_log'a düşüyor.
//
//	go test -tags integration -run TestAdminAPI -v ./test/integration/

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"
)

func adminReq(t *testing.T, client *http.Client, method, url string, body string) (int, string) {
	t.Helper()

	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	// sameOrigin katmanı Sec-Fetch-Site'a bakıyor; gerçek tarayıcı
	// same-origin isteklerde bunu gönderir, testte biz göndeririz.
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestAdminAPIEndToEnd(t *testing.T) {
	_, apiURL, _, db := oobBastion(t, 0)

	// yigit'i CLI'ın yapacağı gibi admin yap (bayrak API'den DEĞİŞMEZ).
	if err := db.SetUserAdmin(context.Background(), "yigit", true); err != nil {
		t.Fatal(err)
	}
	// ⚠️ Bağlanmamış bir YÖNETİCİ hesabını ilk girişin
	// sahiplenmesi artık açık izin istiyor: yalnızca adla
	// devralma ölçülmüş bir saldırıydı (bkz. göç 020).
	if err := db.AllowIdentityBind(context.Background(), "yigit", time.Now()); err != nil {
		t.Fatal(err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)

	// Hedef kaydet → rol aç → hedefi role bağla → kullanıcı aç → rol ata.
	hostKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIcLUQM0UcoZdJVh2EokribDvFZyyNyAVURM/LrCugFM"
	steps := []struct {
		method, path, body string
		want               int
	}{
		{"POST", "/api/admin/targets", fmt.Sprintf(`{"name":"db01","host":"10.0.0.5","port":22,"host_key":%q}`, hostKey), 200},
		{"POST", "/api/admin/roles", `{"name":"dba"}`, 200},
		{"POST", "/api/admin/roles/dba/targets", `{"target":"db01"}`, 200},
		{"POST", "/api/admin/users", `{"name":"ayse","os_user":"ayse","roles":["dba"]}`, 200},
		// Çakışma 409'a eşlenmeli (translateErr sözleşmesinin HTTP hâli).
		{"POST", "/api/admin/roles", `{"name":"dba"}`, 409},
		// Bilinmeyen varlık 404.
		{"DELETE", "/api/admin/targets/yok-boyle", "", 404},
	}
	for i, st := range steps {
		status, body := adminReq(t, client, st.method, apiURL+st.path, st.body)
		if status != st.want {
			t.Fatalf("adım %d (%s %s) = %d, beklenen %d; gövde: %s", i, st.method, st.path, status, st.want, body)
		}
	}

	// Listeler değişikliği görmeli.
	status, body := adminReq(t, client, "GET", apiURL+"/api/admin/users", "")
	if status != 200 || !strings.Contains(body, `"ayse"`) || !strings.Contains(body, `"dba"`) {
		t.Fatalf("users listesi: %d %s", status, body)
	}

	// Ve defter: her değişiklik iz bırakmış olmalı, aktör oturum sahibi.
	status, body = adminReq(t, client, "GET", apiURL+"/api/admin/log", "")
	if status != 200 {
		t.Fatalf("admin log: %d %s", status, body)
	}
	var entries []struct {
		Actor, Via, Action, Entity string
	}
	if err := json.Unmarshal([]byte(body), &entries); err != nil {
		t.Fatalf("log JSON: %v — %s", err, body)
	}
	wantActions := map[string]bool{"target.create": false, "role.create": false, "role.grant": false, "user.create": false}
	for _, e := range entries {
		// Giriş anında yazılan kimlik-bağlama satırı bu testin konusu
		// değil: onu sistem yazıyor (via=sso), yönetici değil.
		if e.Action == "user.idp_bind" {
			continue
		}
		if e.Actor != "yigit" || e.Via != "web" {
			t.Errorf("defter kaydında aktör/kapı yanlış: %+v", e)
		}
		if _, ok := wantActions[e.Action]; ok {
			wantActions[e.Action] = true
		}
	}
	for a, seen := range wantActions {
		if !seen {
			t.Errorf("defterde %q izi yok — başarılı değişiklik kayıtsız kalmış", a)
		}
	}
}

func TestAdminAPIForbidsNonAdmins(t *testing.T) {
	_, apiURL, _, _ := oobBastion(t, 0)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL) // yigit admin DEĞİL

	// Okuma da yazma da kapalı: yetki modeli "admin görür", "herkes görür,
	// admin değiştirir" değil — kullanıcı listesi de saldırgana envanterdir.
	if status, _ := adminReq(t, client, "GET", apiURL+"/api/admin/users", ""); status != http.StatusForbidden {
		t.Fatalf("admin olmayan okuma = %d, beklenen 403", status)
	}
	if status, _ := adminReq(t, client, "POST", apiURL+"/api/admin/roles", `{"name":"kacak"}`); status != http.StatusForbidden {
		t.Fatalf("admin olmayan yazma = %d, beklenen 403", status)
	}
}

// sameOrigin katmanı: site-dışı bir sayfadan tetiklenen istek (tarayıcı
// Sec-Fetch-Site: cross-site damgalar) admin oturumu olsa bile reddedilir.
func TestAdminAPIRejectsCrossSite(t *testing.T) {
	_, apiURL, _, db := oobBastion(t, 0)
	if err := db.SetUserAdmin(context.Background(), "yigit", true); err != nil {
		t.Fatal(err)
	}
	// ⚠️ Bağlanmamış bir YÖNETİCİ hesabını ilk girişin
	// sahiplenmesi artık açık izin istiyor: yalnızca adla
	// devralma ölçülmüş bir saldırıydı (bkz. göç 020).
	if err := db.AllowIdentityBind(context.Background(), "yigit", time.Now()); err != nil {
		t.Fatal(err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)

	req, _ := http.NewRequest("POST", apiURL+"/api/admin/roles", strings.NewReader(`{"name":"csrf-rolu"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site istek = %d, beklenen 403", resp.StatusCode)
	}
}
