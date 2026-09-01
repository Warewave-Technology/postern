//go:build integration

package integration

/*
 * ⚠️ BU DOSYA TEK BİR CÜMLEYİ ÖLÇÜYOR: dizinden gelen bir kullanıcı,
 * YÖNETİCİYE HİÇ UĞRAMADAN kendi ikinci anahtarını ekleyebiliyor mu?
 *
 * Ölçülen çıkmaz: ikinci anahtar eklemek yeniden kimlik doğrulama
 * istiyor (mykeys.go) ve postern yalnızca YEREL parolayı
 * doğrulayabiliyordu. Kimlik sağlayıcıdan gelen hesapların postern'de
 * bir sırrı yok, dolayısıyla cevap "yöneticine sor" idi — yani dizin
 * kullanan bir kurumda, yani asıl hedef kurulumda, HERKES için.
 *
 * Testler gerçek Keycloak'la giriş yapıyor: kullanıcının postern'de
 * parolası yok ve olmayacak.
 */

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/warewave/postern/internal/totp"
)

// meReq, oturumlu bir JSON isteği yollar.
func meReq(t *testing.T, client *http.Client, method, url, body string) (int, string) {
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
	// sameOrigin katmanı Sec-Fetch-Site'a bakıyor.
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// signedInSSOUser, Keycloak'tan giren, postern'de parolası OLMAYAN bir
// kullanıcı ve erişimi olan bir hedef kurar.
func signedInSSOUser(t *testing.T) (*http.Client, string) {
	t.Helper()
	_, apiURL, _, db := oobBastionFresh(t)

	if _, err := db.CreateRole(t.Context(), "ops"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddGroupMapping(t.Context(), "sysadmins", "ops", "test"); err != nil {
		t.Fatal(err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)
	return client, apiURL
}

// enrol, kayıt akışını yürütür ve sırrı döner.
func enrol(t *testing.T, client *http.Client, apiURL string) string {
	t.Helper()

	code, body := meReq(t, client, "POST", apiURL+"/api/me/totp/begin", `{}`)
	if code != http.StatusOK {
		t.Fatalf("kayıt başlatılamadı: %d %s", code, body)
	}
	var out struct{ Secret, URI string }
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Secret == "" {
		t.Fatal("sır dönmedi")
	}
	if !strings.HasPrefix(out.URI, "otpauth://totp/postern:") {
		t.Errorf("otpauth bağlantısı beklenen biçimde değil: %q", out.URI)
	}

	now := time.Now()
	c, err := totp.Code(out.Secret, now)
	if err != nil {
		t.Fatal(err)
	}
	code, body = meReq(t, client, "POST", apiURL+"/api/me/totp/confirm",
		`{"code":"`+c+`"}`)
	if code != http.StatusNoContent {
		t.Fatalf("onay başarısız: %d %s", code, body)
	}
	return out.Secret
}

const testKey1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP7Uu0h3aFf3TgSCUnpxDPRHYZCxKJXCFj4EGqLcQZbT ilk@dizustu"
const testKey2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHqiWMFDdVBnvJJDqRqPpVCGjjjBWmbYYYNMDYyJPTJy ikinci@masaustu"

/*
 * ⚠️ ASIL İDDİA. Yöneticiye hiç uğramadan: giriş → ilk anahtar → ikinci
 * anahtar REDDEDİLİR → kimlik doğrulayıcı bağla → ikinci anahtar geçer.
 */
func TestSSOUserAddsASecondKeyWithoutAnAdmin(t *testing.T) {
	client, apiURL := signedInSSOUser(t)

	// 1) İlk anahtar serbest: bu kullanıcı henüz SSH'a giremiyor.
	code, body := meReq(t, client, "POST", apiURL+"/api/me/keys",
		`{"authorized_key":`+jsonStr(testKey1)+`}`)
	if code != http.StatusOK {
		t.Fatalf("ilk anahtar reddedildi: %d %s", code, body)
	}

	// 2) İkinci anahtar, kanıtsız REDDEDİLMELİ.
	code, body = meReq(t, client, "POST", apiURL+"/api/me/keys",
		`{"authorized_key":`+jsonStr(testKey2)+`}`)
	if code == http.StatusOK {
		t.Fatal("ikinci anahtar kanıtsız eklendi — kalıcılık koruması yok")
	}

	// 3) Kimlik doğrulayıcı bağla. Parola YOK, yönetici YOK.
	secret := enrol(t, client, apiURL)

	// 4) Panel artık kod isteyeceğini söylemeli.
	code, body = meReq(t, client, "GET", apiURL+"/api/me/keys", "")
	if code != http.StatusOK {
		t.Fatalf("anahtar listesi: %d %s", code, body)
	}
	var keys struct {
		ReauthPossible bool `json:"reauth_possible"`
		ReauthTOTP     bool `json:"reauth_totp"`
	}
	if err := json.Unmarshal([]byte(body), &keys); err != nil {
		t.Fatal(err)
	}
	if !keys.ReauthPossible || !keys.ReauthTOTP {
		t.Fatalf("panel hâlâ 'yöneticine sor' diyor: %s", body)
	}

	/*
	 * 5) İkinci anahtar, kodla GEÇMELİ.
	 *
	 * ⚠️ BİR SONRAKİ ADIMIN KODU KULLANILIYOR ve bu bir test hilesi
	 * değil, kullanıcının fiilen yapacağı şey: onay kodu adımı
	 * TÜKETİYOR (yoksa onay kodu anahtar eklemek için tekrar
	 * kullanılırdı), dolayısıyla aynı 30 saniye içinde aynı kod
	 * geçmiyor. Uygulamanın gösterdiği SONRAKİ kod, ±1 adım
	 * penceresinde zaten geçerli.
	 *
	 * Bu ilk yazımda gözden kaçmıştı; test "aynı kod" gönderip
	 * "already been used" aldı — davranış doğruydu, beklenti yanlış.
	 */
	c, _ := totp.Code(secret, time.Now().Add(totp.Period))
	code, body = meReq(t, client, "POST", apiURL+"/api/me/keys",
		`{"authorized_key":`+jsonStr(testKey2)+`,"code":"`+c+`"}`)
	if code != http.StatusOK {
		t.Fatalf("kodla ikinci anahtar eklenemedi: %d %s — bu paketin "+
			"var olma sebebi tam olarak bu adım", code, body)
	}
}

/*
 * ⚠️ AYNI KOD İKİNCİ KEZ ANAHTAR EKLEYEMEMELİ.
 *
 * Kod 30 saniye geçerli; omuz üstünden okuyan ya da araya giren biri
 * onu yeniden gönderebilir — ve burada ikinci kullanım "bir anahtar
 * daha ekle" demek, yani tam olarak engellenmek istenen kalıcılık.
 */
func TestReplayedCodeCannotAddAnotherKey(t *testing.T) {
	client, apiURL := signedInSSOUser(t)

	code, body := meReq(t, client, "POST", apiURL+"/api/me/keys",
		`{"authorized_key":`+jsonStr(testKey1)+`}`)
	if code != http.StatusOK {
		t.Fatalf("ilk anahtar: %d %s", code, body)
	}
	secret := enrol(t, client, apiURL)

	// Onay adımı tüketildiği için sonraki adımın kodu (bkz. yukarıdaki
	// testin gerekçesi).
	c, _ := totp.Code(secret, time.Now().Add(totp.Period))
	code, body = meReq(t, client, "POST", apiURL+"/api/me/keys",
		`{"authorized_key":`+jsonStr(testKey2)+`,"code":"`+c+`"}`)
	if code != http.StatusOK {
		t.Fatalf("ilk kullanım: %d %s", code, body)
	}

	// AYNI kod, üçüncü bir anahtar için.
	const testKey3 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDQnFxKZQEQJSYqrqXQZLRHYaLnkxmTQXmvxUWnkYPqQ ucuncu@saldirgan"
	code, body = meReq(t, client, "POST", apiURL+"/api/me/keys",
		`{"authorized_key":`+jsonStr(testKey3)+`,"code":"`+c+`"}`)
	if code == http.StatusOK {
		t.Fatal("tekrar edilen kod ikinci bir anahtar ekledi — tekrar koruması yok")
	}
	if !strings.Contains(body, "already been used") {
		t.Errorf("sebep 'tekrar' demiyor: %s", body)
	}
}

/*
 * ⚠️ KAYIT, KORUMAYI ATLATMANIN YOLU OLMAMALI.
 *
 * Bayat bir oturumla kayıt yapılabilseydi, panel oturumunu çalan biri
 * önce kimlik doğrulayıcı bağlar, sonra onunla anahtar ekler ve tam da
 * engellenmek istenen kalıcılığı kurardı — üstelik "ikinci faktörü var"
 * diye daha güvenli görünen bir hesapta.
 */
func TestStaleSessionCannotEnrol(t *testing.T) {
	client, apiURL := signedInSSOUser(t)

	// Oturum TAZE: kayıt mümkün olmalı.
	code, body := meReq(t, client, "GET", apiURL+"/api/me/totp", "")
	if code != http.StatusOK {
		t.Fatalf("durum: %d %s", code, body)
	}
	var st struct {
		CanBegin        bool `json:"can_begin"`
		NeedsFreshLogin bool `json:"needs_fresh_login"`
	}
	if err := json.Unmarshal([]byte(body), &st); err != nil {
		t.Fatal(err)
	}
	if !st.NeedsFreshLogin {
		t.Fatal("SSO hesabı için taze giriş istenmiyor — testin konusu yok")
	}
	if !st.CanBegin {
		t.Fatal("taze oturumla kayıt başlatılamıyor")
	}

	// ⚠️ Tazeliğin GERÇEKTEN kapı olduğunu ölçmek için oturumu
	// eskitmemiz gerekiyor; oturum defteri bellekte ve saati testten
	// oynatılamıyor. Onun yerine tazeliğin YOKLUĞUNU ölçüyoruz:
	// oturumsuz bir istemci kayıt başlatamamalı.
	bare := &http.Client{Timeout: 10 * time.Second}
	code, _ = meReq(t, bare, "POST", apiURL+"/api/me/totp/begin", `{}`)
	if code == http.StatusOK {
		t.Fatal("oturumsuz istek kayıt başlattı")
	}
}

// jsonStr, bir dizgiyi JSON değeri olarak kaçırır.
func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
