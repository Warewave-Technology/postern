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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/auth"
	"github.com/Warewave-Technology/postern/internal/store"
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

/*
 * ⚠️ HESAP AÇMAK VE GİRİŞ BİLGİSİ VERMEK TEK İŞLEM.
 *
 * Ayrı bir "ver" adımı olarak duruyordu ve o adım unutulabilirdi:
 * postern'de kaydı olan ama hiçbir şekilde giremeyen bir kullanıcı,
 * kimsenin fark etmediği bir yarım iş. Bu test, cevabın gerçekten
 * KULLANILABİLİR bir değer taşıdığını uçtan uca ölçüyor — "bir dize
 * döndü" demek yetmez, o dizeyle giriş yapılabilmeli.
 */
func TestCreatingAUserIssuesAWorkingSignInValue(t *testing.T) {
	_, apiURL, _, db := oobBastionFresh(t)
	ctx := context.Background()

	seedRole(t, db)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)
	if err := db.SetUserAdmin(ctx, kcUser, true); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting(ctx, auth.KeyLoginSource, "local", false, "test"); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(map[string]any{
		"name": "ayse", "os_user": "ayse", "email": "ayse@warewave.io",
	})
	req, _ := http.NewRequest("POST", apiURL+"/api/admin/users", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Secret          string `json:"secret"`
		CredentialError string `json:"credential_error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()

	if out.CredentialError != "" {
		t.Fatalf("sır verilemedi: %s", out.CredentialError)
	}
	if out.Secret == "" {
		t.Fatal("hesap açıldı ama cevap giriş bilgisi taşımıyor — " +
			"yönetici, hiçbir şekilde giremeyen bir kullanıcı bırakır")
	}

	// ⚠️ ASIL ÖLÇÜM: değer GERÇEKTEN çalışıyor mu.
	jar2, _ := cookiejar.New(nil)
	c2 := &http.Client{Jar: jar2, Timeout: 30 * time.Second}
	if code, msg := localSignIn(t, c2, apiURL, "ayse", out.Secret); code != http.StatusOK {
		t.Fatalf("verilen değerle giriş %d: %s", code, msg)
	}
	me, _ := fetchMe(t, c2, apiURL)
	if !me.MustChangePassword {
		t.Fatal("hesapla birlikte verilen değer 'değiştir' istemiyor — " +
			"veren yönetici de biliyor ve bilmeye devam eder")
	}
}

/*
 * ⚠️ YEREL KAPI KAPALIYKEN DEĞER ÜRETİLMİYOR.
 *
 * Dizin ya da kimlik sağlayıcı açıkken yerel kapı kapalı: orada
 * üretilen bir değer hiçbir zaman kullanılamaz, yani yalnızca
 * sızdırılabilecek fazladan bir sır olurdu.
 */
func TestCreatingAUserIssuesNothingWhenTheLocalDoorIsClosed(t *testing.T) {
	_, apiURL, _, db := oobBastionFresh(t)
	ctx := context.Background()

	seedRole(t, db)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)
	if err := db.SetUserAdmin(ctx, kcUser, true); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting(ctx, auth.KeyLoginSource, "oidc", false, "test"); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(map[string]any{"name": "deniz", "os_user": "deniz"})
	req, _ := http.NewRequest("POST", apiURL+"/api/admin/users", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Secret string `json:"secret"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()

	if out.Secret != "" {
		t.Fatal("yerel kapı kapalıyken sır üretildi — kullanılamayan, " +
			"yalnızca sızdırılabilecek fazladan bir değer")
	}
	if _, err := db.LocalCredential(ctx, "deniz"); err == nil {
		t.Fatal("yerel kapı kapalıyken kimlik bilgisi satırı yazılmış")
	}
}

/*
 * ⚠️ PARMAK İZİYLE ANAHTAR SİLME, DOĞRU ANAHTARI SİLMELİ.
 *
 * Detay ekranı anahtarları parmak izleriyle listeliyor ve satır başına
 * bir "kaldır" düğmesi çiziyor. O düğmenin YANLIŞ anahtarı ya da BAŞKA
 * BİR HESABIN anahtarını silmesi, sessizce birinin erişimini kesmek
 * demek — üstelik yönetici sildiğini sandığı anahtarın hâlâ çalıştığını
 * fark etmez.
 */
func TestRemovingAKeyByFingerprintHitsOnlyThatKey(t *testing.T) {
	_, apiURL, _, db := oobBastionFresh(t)
	ctx := context.Background()

	seedRole(t, db)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)
	if err := db.SetUserAdmin(ctx, kcUser, true); err != nil {
		t.Fatal(err)
	}

	for _, n := range []string{"ayse", "deniz"} {
		if _, err := db.CreateUser(ctx, n, n+"@warewave.io", n); err != nil {
			t.Fatal(err)
		}
	}

	// Üç anahtar: ayse'de iki, deniz'de bir.
	keys := map[string][]string{}
	for _, spec := range [][2]string{{"ayse", "bir"}, {"ayse", "iki"}, {"deniz", "uc"}} {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.AddPublicKey(ctx, spec[0], sshPub.Marshal(), spec[1]); err != nil {
			t.Fatal(err)
		}
		keys[spec[0]] = append(keys[spec[0]], ssh.FingerprintSHA256(sshPub))
	}

	// Detay ucu parmak izlerini veriyor mu?
	resp, err := client.Get(apiURL + "/api/admin/users/ayse")
	if err != nil {
		t.Fatal(err)
	}
	var detail struct {
		Keys []struct {
			Fingerprint string `json:"fingerprint"`
		} `json:"keys"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&detail)
	resp.Body.Close()
	if len(detail.Keys) != 2 {
		t.Fatalf("detay %d anahtar döndü, 2 bekleniyordu", len(detail.Keys))
	}

	// ⚠️ BAŞKA HESABIN anahtarının parmak izi REDDEDİLMELİ.
	code, _ := postJSON(t, client, apiURL+"/api/admin/users/ayse/keys/remove",
		map[string]string{"fingerprint": keys["deniz"][0]})
	if code != http.StatusNotFound {
		t.Fatalf("başka hesabın anahtarı ayse üzerinden silinebildi (%d)", code)
	}
	if left, _ := db.PublicKeys(ctx, "deniz"); len(left) != 1 {
		t.Fatal("deniz'in anahtarı silindi")
	}

	// Doğru parmak izi YALNIZCA onu siliyor.
	if code, msg := postJSON(t, client, apiURL+"/api/admin/users/ayse/keys/remove",
		map[string]string{"fingerprint": keys["ayse"][0]}); code != http.StatusOK {
		t.Fatalf("silme %d: %s", code, msg)
	}
	left, err := db.PublicKeys(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 1 {
		t.Fatalf("ayse'de %d anahtar kaldı, 1 bekleniyordu", len(left))
	}
	kept, err := ssh.ParsePublicKey(left[0].Blob)
	if err != nil {
		t.Fatal(err)
	}
	if ssh.FingerprintSHA256(kept) != keys["ayse"][1] {
		t.Fatal("yanlış anahtar silindi")
	}
}

/*
 * ⚠️ KULLANICI KENDİ ANAHTARINI PARMAK İZİYLE KALDIRABİLMELİ.
 *
 * ÖLÇÜLEN AÇIK: uç yalnızca anahtarın METNİNİ kabul ediyordu ve liste
 * ucu metni hiç döndürmüyor — yalnızca parmak izi. Yani panelin, silme
 * ucunun istediği değere sahip olması mümkün değildi: yazılmış,
 * denetlenmiş ve çağrılamaz bir uç. Sonuç, anahtarının ele geçtiğini
 * fark eden kullanıcının onu iptal edememesiydi.
 */
func TestUserCanRemoveTheirOwnKeyByFingerprint(t *testing.T) {
	_, apiURL, _, db := oobBastionFresh(t)
	ctx := context.Background()

	if _, err := db.CreateUser(ctx, "ayse", "ayse@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}
	secret, verifier, err := auth.NewLocalSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddLocalCredential(ctx, "ayse", verifier, "cli"); err != nil {
		t.Fatal(err)
	}
	// Parolayı değiştirmiş bir hesap: kısıtlı oturum bu ucu görmüyor.
	if err := db.SetChosenPassword(ctx, "ayse", verifier, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting(ctx, auth.KeyLoginSource, "local", false, "test"); err != nil {
		t.Fatal(err)
	}

	// İki anahtar: biri silinecek, öbürü DURACAK.
	fps := make([]string, 0, 2)
	for i := 0; i < 2; i++ {
		pub, _, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			t.Fatal(gerr)
		}
		sshPub, kerr := ssh.NewPublicKey(pub)
		if kerr != nil {
			t.Fatal(kerr)
		}
		if err := db.AddPublicKey(ctx, "ayse", sshPub.Marshal(), "k"); err != nil {
			t.Fatal(err)
		}
		fps = append(fps, ssh.FingerprintSHA256(sshPub))
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	if code, msg := localSignIn(t, client, apiURL, "ayse", secret); code != http.StatusOK {
		t.Fatalf("giriş %d: %s", code, msg)
	}

	// Liste parmak izlerini veriyor mu?
	resp, err := client.Get(apiURL + "/api/me/keys")
	if err != nil {
		t.Fatal(err)
	}
	var listed struct {
		Keys []struct {
			Fingerprint string `json:"fingerprint"`
		} `json:"keys"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&listed)
	resp.Body.Close()
	if len(listed.Keys) != 2 {
		t.Fatalf("liste %d anahtar döndü", len(listed.Keys))
	}

	// ⚠️ ASIL ÖLÇÜM: listenin verdiği değerle silinebiliyor mu.
	if code, msg := postJSON(t, client, apiURL+"/api/me/keys/remove",
		map[string]string{"fingerprint": listed.Keys[0].Fingerprint}); code != http.StatusOK {
		t.Fatalf("kendi anahtarını silemedi (%d): %s — liste parmak izi "+
			"veriyor ama uç onu kabul etmiyorsa kullanıcı anahtarını iptal edemez",
			code, msg)
	}

	left, err := db.PublicKeys(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 1 {
		t.Fatalf("%d anahtar kaldı, 1 bekleniyordu", len(left))
	}
	kept, err := ssh.ParsePublicKey(left[0].Blob)
	if err != nil {
		t.Fatal(err)
	}
	if ssh.FingerprintSHA256(kept) == listed.Keys[0].Fingerprint {
		t.Fatal("yanlış anahtar silindi")
	}
	_ = fps
}
