//go:build integration

package integration

// Yerel parola kapısının UÇTAN UCA kanıtı.
//
//	go test -tags integration -run TestLocalPassword -v ./test/integration/
//
// ⚠️ BU KAPININ BUGÜNE KADAR HİÇ ENTEGRASYON KAPSAMASI YOKTU ve o gün
// savunulabilirdi: değer makine üretimi 128 bitlik bir sırdı, tek
// kullanıcısı acil durum yöneticisiydi. Kullanıcı parolaları o öncülü
// kaldırıyor — artık burası insanların her gün kullandığı kapı.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"testing"
	"time"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/store"
)

// localSignIn, /auth/local'e POST atar ve HTTP kodunu döner.
func localSignIn(t *testing.T, client *http.Client, apiURL, user, secret string) (int, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": user, "secret": secret})
	req, err := http.NewRequest("POST", apiURL+"/auth/local", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	msg, _ := out["error"].(string)
	return resp.StatusCode, msg
}

func postJSON(t *testing.T, client *http.Client, url string, in any) (int, string) {
	t.Helper()
	body, _ := json.Marshal(in)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	msg, _ := out["error"].(string)
	return resp.StatusCode, msg
}

/*
 * ⚠️ ZORUNLU DEĞİŞİKLİK GERÇEKTEN KAPATIYOR MU.
 *
 * Bu testin ölçtüğü tek şey şu: yöneticinin verdiği — ve dolayısıyla
 * YÖNETİCİNİN DE BİLDİĞİ — bir değerle giren kişi, parolasını
 * değiştirmeden hiçbir şey yapamıyor. Özellikle SSH ANAHTARI EKLEYEMİYOR:
 * hesabın ilk anahtarı hiçbir doğrulama istemeden ekleniyor, yani o uç
 * açık kalsaydı kısıt tam olarak engellemesi gereken şeyi — kalıcı
 * erişim kurmayı — engellemezdi.
 */
func TestLocalPasswordFlowEndToEnd(t *testing.T) {
	_, apiURL, _, db := oobBastionFresh(t)
	ctx := context.Background()

	if _, err := db.CreateUser(ctx, "ayse", "ayse@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}
	secret, verifier, err := auth.NewLocalSecret()
	if err != nil {
		t.Fatal(err)
	}
	// Panelden verilmiş gibi: created_by 'cli' DEĞİL.
	if _, err := db.ReplaceLocalCredential(ctx, "ayse", verifier, "yigit"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting(ctx, auth.KeyLoginSource, "local", false, "test"); err != nil {
		t.Fatal(err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}

	if code, msg := localSignIn(t, client, apiURL, "ayse", secret); code != http.StatusOK {
		t.Fatalf("verilen değerle giriş %d: %s", code, msg)
	}

	me, status := fetchMe(t, client, apiURL)
	if status != http.StatusOK {
		t.Fatalf("/api/me = %d", status)
	}
	if !me.MustChangePassword {
		t.Fatal("verilen değerle giren oturum kısıtlı değil — " +
			"değeri veren kişi hesabı olduğu gibi kullanabilir")
	}

	// ⚠️ ASIL KONTROL: anahtar ekleyemiyor.
	code, _ := postJSON(t, client, apiURL+"/api/me/keys", map[string]string{
		"authorized_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGdeneme deneme",
	})
	if code != http.StatusForbidden {
		t.Fatalf("kısıtlı oturum anahtar ekleyebildi (%d) — "+
			"parolasını değiştirmeden kalıcı SSH erişimi kurulabiliyor", code)
	}

	// Yönetim uçları da kapalı.
	resp, err := client.Get(apiURL + "/api/admin/users")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("kısıtlı oturum yönetim ucunu okuyabildi")
	}

	// Mevcut değer YANLIŞSA değiştiremiyor.
	code, _ = postJSON(t, client, apiURL+"/api/me/password", map[string]string{
		"current": "YANLIS-DEGER", "new": "kirmizi-bisiklet-42",
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("mevcut değer yanlışken parola değişti (%d) — "+
			"değeri gören herkes hesabı tek istekle alabilir", code)
	}

	// Politikayı geçmeyen parola reddediliyor.
	code, msg := postJSON(t, client, apiURL+"/api/me/password", map[string]string{
		"current": secret, "new": "ayse-ayse-ayse",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("kullanıcı adını içeren parola kabul edildi (%d): %s", code, msg)
	}

	// Doğru değer + geçerli parola: kısıt kalkıyor.
	if code, msg := postJSON(t, client, apiURL+"/api/me/password", map[string]string{
		"current": secret, "new": "kirmizi-bisiklet-42",
	}); code != http.StatusOK {
		t.Fatalf("parola değiştirilemedi (%d): %s", code, msg)
	}

	me, status = fetchMe(t, client, apiURL)
	if status != http.StatusOK {
		t.Fatalf("/api/me = %d — parola değişimi oturumu düşürdü", status)
	}
	if me.MustChangePassword {
		t.Fatal("parola değişti ama kısıt kalkmadı")
	}

	// Eski değer ARTIK ÇALIŞMIYOR, yenisi çalışıyor.
	jar2, _ := cookiejar.New(nil)
	c2 := &http.Client{Jar: jar2, Timeout: 30 * time.Second}
	if code, _ := localSignIn(t, c2, apiURL, "ayse", secret); code == http.StatusOK {
		t.Fatal("yöneticinin verdiği eski değer hâlâ çalışıyor")
	}

	jar3, _ := cookiejar.New(nil)
	c3 := &http.Client{Jar: jar3, Timeout: 30 * time.Second}
	if code, msg := localSignIn(t, c3, apiURL, "ayse", "kirmizi-bisiklet-42"); code != http.StatusOK {
		t.Fatalf("yeni parolayla giriş %d: %s", code, msg)
	}
}

/*
 * ⚠️ SIR TUTAN HESAP GECİKMEYE GİRMİYOR.
 *
 * localcred.go:30 "kilitleme YOK" diyor ve gerekçesi şu: kilitleme,
 * kimliği doğrulanmamış birine kurulumun tek yöneticisini dışarıda
 * tutan bir düğme verir. Parolalar için gecikme eklendi; bu test o
 * düğmenin acil durum kapısına DOĞRULTULAMADIĞINI ölçüyor.
 */
func TestGuessingAnAdminSecretNeverThrottlesIt(t *testing.T) {
	_, apiURL, _, db := oobBastionFresh(t)
	ctx := context.Background()

	if _, err := db.CreateUser(ctx, "ops", "ops@warewave.io", "ops"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetUserAdmin(ctx, "ops", true); err != nil {
		t.Fatal(err)
	}
	secret, verifier, err := auth.NewLocalSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddLocalCredential(ctx, "ops", verifier, "cli"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting(ctx, auth.KeyLoginSource, "local", false, "test"); err != nil {
		t.Fatal(err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}

	// Israrlı yanlış denemeler. (Dakikalık kotayı aşmamak için 8 tane;
	// gecikme 4. denemeden sonra başlıyor olurdu.)
	for i := 0; i < 8; i++ {
		code, _ := localSignIn(t, client, apiURL, "ops", "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GG")
		if code == http.StatusTooManyRequests {
			t.Fatalf("%d. denemede yönetici hesabı gecikmeye girdi — "+
				"yabancı biri acil durum kapısını kapatabiliyor", i+1)
		}
	}

	// Gerçek yönetici hâlâ girebiliyor.
	if code, msg := localSignIn(t, client, apiURL, "ops", secret); code != http.StatusOK {
		t.Fatalf("yönetici girişi %d: %s — acil durum kapısı kapanmış", code, msg)
	}
}

// Panelden yönetici hesabına kimlik bilgisi VERİLEMİYOR — uç seviyesinde.
func TestPanelCannotIssueCredentialForAnAdmin(t *testing.T) {
	_, apiURL, _, db := oobBastionFresh(t)
	ctx := context.Background()

	seedRole(t, db)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)
	if err := db.SetUserAdmin(ctx, kcUser, true); err != nil {
		t.Fatal(err)
	}

	if _, err := db.CreateUser(ctx, "ops", "ops@warewave.io", "ops"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetUserAdmin(ctx, "ops", true); err != nil {
		t.Fatal(err)
	}

	code, msg := postJSON(t, client, apiURL+"/api/admin/users/ops/credential", nil)
	if code != http.StatusConflict {
		t.Fatalf("panelden yönetici hesabına kimlik bilgisi verilebildi (%d): %s", code, msg)
	}
	if _, err := db.LocalCredential(ctx, "ops"); err == nil {
		t.Fatal("reddedilmesine rağmen satır yazılmış")
	}

	// Sıradan hesapta çalışıyor.
	if _, err := db.CreateUser(ctx, "ayse", "ayse@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}
	if code, msg := postJSON(t, client, apiURL+"/api/admin/users/ayse/credential", nil); code != http.StatusOK {
		t.Fatalf("sıradan hesaba verme %d: %s", code, msg)
	}
	c, err := db.LocalCredential(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if !c.MustChange {
		t.Fatal("panelden verilen değer 'değiştir' istemiyor")
	}
	_ = store.Credential{}
}

func seedRole(t *testing.T, db *store.Store) {
	t.Helper()
	ctx := context.Background()
	if _, err := db.CreateRole(ctx, "ops"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddGroupMapping(ctx, "sysadmins", "ops", "test"); err != nil {
		t.Fatal(err)
	}
}
