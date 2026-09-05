//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/auth"
	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/totp"
)

/*
 * ⚠️ KAPI GERÇEKTEN UYGULUYOR MU.
 *
 * internal/httpapi'deki kardeş test izin listesinin İÇERİĞİNİ sınıyor;
 * bu test kapının kendisini sınıyor. İkisi ayrı arızaları yakalıyor:
 * liste doğru olup middleware'e hiç bağlanmamış olabilir, ya da bağlanıp
 * yanlış oturumlara uygulanabilir.
 */
func TestLocalSessionIsPennedUntilItEnrols(t *testing.T) {
	_, apiURL, _, db := oobBastionFresh(t)
	attachSecretBox(t, db)
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
	// Parolasını seçmiş bir hesap: parola kapısı geçilmiş, sırada ikinci
	// faktör kapısı var. İki kapıyı ayrı ayrı görebilmek için şart.
	if err := db.SetChosenPassword(ctx, "ayse", verifier, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting(ctx, auth.KeyLoginSource, "local", false, "test"); err != nil {
		t.Fatal(err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	if code, msg := localSignIn(t, client, apiURL, "ayse", secret); code != http.StatusOK {
		t.Fatalf("giriş %d: %s", code, msg)
	}

	// /api/me AÇIK ve zorunluluğu söylüyor — panel çizeceği ekranı
	// buradan öğreniyor.
	code, body := meReq(t, client, "GET", apiURL+"/api/me", "")
	if code != http.StatusOK {
		t.Fatalf("/api/me kapalı: %d %s", code, body)
	}
	var me struct {
		MustEnrolTOTP bool     `json:"must_enrol_totp"`
		Targets       []string `json:"targets"`
	}
	if err := json.Unmarshal([]byte(body), &me); err != nil {
		t.Fatal(err)
	}
	if !me.MustEnrolTOTP {
		t.Fatal("must_enrol_totp false — panel kayıt ekranını çizmez")
	}

	/*
	 * ⚠️ ASIL ÖLÇÜM. Bu uç, hesabın İLK anahtarını hiçbir doğrulama
	 * istemeden ekliyor — yani kapı burada tutmuyorsa, "ikinci faktörünü
	 * kurana kadar hiçbir şey yapamazsın" kısıtı tam olarak kalıcı SSH
	 * erişimi kurmanın önündeki tek engeli kaldırmış olur.
	 */
	pub, _, gerr := ed25519.GenerateKey(rand.Reader)
	if gerr != nil {
		t.Fatal(gerr)
	}
	sshPub, kerr := ssh.NewPublicKey(pub)
	if kerr != nil {
		t.Fatal(kerr)
	}
	authorized := string(ssh.MarshalAuthorizedKey(sshPub))
	code, body = meReq(t, client, "POST", apiURL+"/api/me/keys",
		`{"authorized_key":`+jsonStr(authorized)+`}`)
	if code != http.StatusForbidden {
		t.Fatalf("anahtar ekleme %d döndü, 403 bekleniyordu: %s", code, body)
	}

	// 401 DEĞİL: oturum geçerli, kim olduğunu biliyoruz. 401 olsaydı panel
	// kişiyi giriş ekranına atar ve sonsuz döngüye sokardı.
	code, _ = meReq(t, client, "GET", apiURL+"/api/me/keys", "")
	if code != http.StatusForbidden {
		t.Errorf("anahtar listesi %d döndü, 403 bekleniyordu", code)
	}

	// Kayıttan KAÇIŞ yolu olmamalı: kapatarak kurtulunamaz.
	code, _ = meReq(t, client, "POST", apiURL+"/api/me/totp/disable", `{"code":"000000"}`)
	if code != http.StatusForbidden {
		t.Errorf("totp/disable %d döndü, 403 bekleniyordu — kayıttan kaçış yolu açık", code)
	}

	// Kaydı tamamla, kapı açılsın.
	enrolTOTP(t, client, apiURL, secret)

	code, body = meReq(t, client, "GET", apiURL+"/api/me/keys", "")
	if code != http.StatusOK {
		t.Fatalf("kayıttan sonra anahtar listesi hâlâ kapalı: %d %s", code, body)
	}
	code, body = meReq(t, client, "GET", apiURL+"/api/me", "")
	if code != http.StatusOK {
		t.Fatal(body)
	}
	if err := json.Unmarshal([]byte(body), &me); err != nil {
		t.Fatal(err)
	}
	if me.MustEnrolTOTP {
		t.Error("kayıt tamamlandığı hâlde must_enrol_totp hâlâ true")
	}
}

/*
 * ⚠️ KOD, OTURUMDAN ÖNCE.
 *
 * Bu testin ölçtüğü tek şey sıralama. Kod sorulup da oturum ÖNCE
 * açılsaydı, kodu bilmeyen birinin elinde geçerli bir çerez kalırdı ve o
 * çerezin neye eriştiği artık başka kapıların dikkatine kalırdı. Buradaki
 * iddia daha güçlü: kod gelene kadar ortada oturum YOK.
 */
func TestSignInDemandsTheCodeBeforeItOpensASession(t *testing.T) {
	_, apiURL, _, db := oobBastionFresh(t)
	attachSecretBox(t, db)
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
	if err := db.SetChosenPassword(ctx, "ayse", verifier, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting(ctx, auth.KeyLoginSource, "local", false, "test"); err != nil {
		t.Fatal(err)
	}

	// Önce kaydı tamamla: kod sorulması için DOĞRULANMIŞ bir faktör şart.
	jar, _ := cookiejar.New(nil)
	first := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	if code, msg := localSignIn(t, first, apiURL, "ayse", secret); code != http.StatusOK {
		t.Fatalf("ilk giriş %d: %s", code, msg)
	}
	enrolTOTP(t, first, apiURL, secret)

	totpSecret := totpSecretOf(t, db, "ayse")

	// --- Kodsuz giriş: reddedilmeli VE oturum açılmamalı ---------------
	jar2, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar2, Timeout: 30 * time.Second}
	// ⚠️ localSignIn gövdeden yalnızca `error` alanını çıkarıyor; burada
	// işaretin kendisini görmek gerektiği için ham gövdeyi okuyan çağrı.
	code, body := localSignInWithCode(t, client, apiURL, "ayse", secret, "")
	if code != http.StatusUnauthorized {
		t.Fatalf("kodsuz giriş %d döndü, 401 bekleniyordu: %s", code, body)
	}
	if !strings.Contains(body, "totp_required") {
		t.Errorf("cevap makine okunur işaret taşımıyor, panel kod kutusunu çizemez: %s", body)
	}

	// ⚠️ ASIL ÖLÇÜM.
	if c, _ := meReq(t, client, "GET", apiURL+"/api/me", ""); c == http.StatusOK {
		t.Fatal("kod verilmeden oturum açılmış — sıra bozuk")
	}

	// --- Yanlış kod ----------------------------------------------------
	code, body = localSignInWithCode(t, client, apiURL, "ayse", secret, "000000")
	if code == http.StatusOK {
		t.Fatalf("yanlış kodla girildi: %s", body)
	}
	if c, _ := meReq(t, client, "GET", apiURL+"/api/me", ""); c == http.StatusOK {
		t.Fatal("yanlış koddan sonra oturum açılmış")
	}

	/*
	 * --- Doğru kod ----------------------------------------------------
	 *
	 * ⚠️ BİR SONRAKİ ADIMIN KODU. enrolTOTP kaydı ŞU ANKİ adımın koduyla
	 * doğruladı ve o adım tüketildi; aynısını burada göndermek tekrar
	 * koruması tarafından — doğru şekilde — reddedilir. ±1 adım toleransı
	 * sayesinde bir sonraki adımın kodu şimdi de geçerli, ve tüketilmemiş.
	 * Alternatif 30 saniye beklemekti; testi yavaşlatmanın anlamı yok.
	 */
	otp, err := totp.Code(totpSecret, time.Now().Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	code, body = localSignInWithCode(t, client, apiURL, "ayse", secret, otp)
	if code != http.StatusOK {
		t.Fatalf("doğru kodla giriş %d: %s", code, body)
	}
	if c, _ := meReq(t, client, "GET", apiURL+"/api/me", ""); c != http.StatusOK {
		t.Fatalf("girişten sonra /api/me %d", c)
	}

	/*
	 * ⚠️ AYNI KOD İKİNCİ KEZ KULLANILAMAZ. Kod 30 saniye geçerli; omuz
	 * üstünden okuyan ya da araya giren biri onu yeniden gönderebilir ve
	 * bu bağlamda ikinci kullanım "ikinci bir oturum aç" demek.
	 */
	jar3, _ := cookiejar.New(nil)
	replay := &http.Client{Jar: jar3, Timeout: 30 * time.Second}
	code, body = localSignInWithCode(t, replay, apiURL, "ayse", secret, otp)
	if code == http.StatusOK {
		t.Fatalf("tekrar edilen kod ikinci bir oturum açtı: %s", body)
	}
}

// localSignInWithCode, localSignIn'in ikinci faktör kodu taşıyan hâli.
func localSignInWithCode(t *testing.T, client *http.Client, apiURL, user, secret, code string) (int, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"username": user, "secret": secret, "code": code,
	})
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
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

// totpSecretOf, kaydedilmiş sırrı store'dan okur — test kod üretebilsin diye.
func totpSecretOf(t *testing.T, db *store.Store, name string) string {
	t.Helper()
	c, err := db.TOTP(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	return c.Secret
}
