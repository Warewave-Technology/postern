//go:build integration

package integration

import (
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
