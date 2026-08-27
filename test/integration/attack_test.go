//go:build integration

package integration

// Saldırı testleri: güvenlik incelemesinde ileri sürülen iddiaları
// OKUYARAK değil DENEYEREK yerleştiriyoruz.
//
//	go test -tags integration -run TestAttack -v ./test/integration/

import (
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// phishedVictim, KURBANIN tarayıcıda yaptığı şeyi taklit eder ve
// gördüğü onay sayfasını döner.
//
// Gerçek hayatta saldırgan linki kurbana yollar ("BT ekibi: lütfen şu
// bağlantıdan giriş yapın"). Kurban kendi kimliğiyle giriş yapar.
// Saldırganın kazanabilmesi için kurbanın ekranındaki kodu ALIP
// SALDIRGANA GÖNDERMESİ gerekir — bu test onu YAPMAZ, çünkü mesele tam
// olarak o adımın gerekip gerekmediği.
func phishedVictim(loginURL string) (page string, err error) {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	resp, err := client.Get(loginURL)
	if err != nil {
		return "", fmt.Errorf("giriş sayfası: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	m := regexp.MustCompile(`<form[^>]+action="([^"]+)"`).FindSubmatch(body)
	if m == nil {
		return "", fmt.Errorf("IdP giriş formu yok: %.300s", body)
	}

	resp, err = client.PostForm(html.UnescapeString(string(m[1])), url.Values{
		"username": {kcUser},
		"password": {kcPassword},
	})
	if err != nil {
		return "", fmt.Errorf("IdP giriş POST: %w", err)
	}
	confirmPage, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	return string(confirmPage), nil
}

// ⚠️ DEVICE-CODE PHISHING — kapatılmış olmalı.
//
// Saldırgan SSH bağlantısını başlatır, linki kurbana yollar, kurban
// kendi kimliğiyle giriş yapar. Saldırgan bir tık ötede kurbanın
// kimliğiyle oturum açabiliyor muydu?
//
// ESKİ YÖNDE EVET, ve bu test onu uçtan uca gerçekleştiriyordu:
// saldırganın oturumu hedefte kurbanın hesabıyla açılıyor, denetim
// kaydı da onu kurbana yazıyordu. Sebebi, güvenlik kodunun SALDIRGANIN
// TERMİNALİNDE gösterilmesiydi — yani saldırgan kodu zaten biliyordu
// ve linkle birlikte gönderiyordu.
//
// Yeni yönde kod yalnızca KURBANIN TARAYICISINDA beliriyor. Saldırgan
// onu bilmiyor, dolayısıyla kimlik doğrulaması TAMAMLANMAMALI.
func TestAttackOOBDeviceCodePhishingIsRefused(t *testing.T) {
	sshAddr, _, hostPub, db := oobBastion(t, 30*time.Second)

	var victimSaw string

	// Saldırgan: linki kurbana iletir, ama kod elinde YOK. Elindeki
	// tek şeyle — tahminle — devam etmeye çalışır.
	_, err := kiClient(sshAddr, hostPub, func(loginURL string) (string, error) {
		page, perr := phishedVictim(loginURL)
		victimSaw = page
		if perr != nil {
			return "", perr
		}
		// Saldırganın elinde kod yok; uydurmaktan başka şansı yok.
		return "AAAA-AAAA", nil
	})

	if err == nil {
		t.Fatal("SALDIRI BAŞARILI: saldırgan kurbanın kimliğiyle kimlik doğruladı")
	}
	t.Logf("saldırı reddedildi: %v", err)

	// Hiçbir oturum açılmamış olmalı.
	sessions, serr := db.Sessions(t.Context(), "", 0)
	if serr != nil {
		t.Fatal(serr)
	}
	if len(sessions) != 0 {
		t.Errorf("%d oturum kaydı var, 0 bekleniyordu: %+v", len(sessions), sessions)
	}

	// Kurbanın gördüğü sayfa neyi onayladığını SÖYLEMELİ.
	t.Logf("kurbanın gördüğü sayfa:\n%s", victimSaw)

	if !regexp.MustCompile(`\d+\.\d+\.\d+\.\d+`).MatchString(victimSaw) {
		t.Error("onay sayfası SSH bağlantısının kaynak adresini göstermiyor — " +
			"kurbanın 'bunu ben başlatmadım' diyebilmesinin dayanağı yok")
	}
	for _, want := range []string{"Did you start this", "close this page"} {
		if !strings.Contains(victimSaw, want) {
			t.Errorf("onay sayfasında %q uyarısı yok", want)
		}
	}
	// Sayfa, kodun asla kimseye GÖNDERİLMEYECEĞİNİ söylemeli: saldırının
	// kalan tek yolu kurbandan kodu istemek.
	if !strings.Contains(victimSaw, "never ask you to send this code") {
		t.Error("sayfa kodun kimseye gönderilmemesi gerektiğini söylemiyor")
	}
}

// Yanlış kod denemeyi YAKMALI: kaba kuvvet tek atışlık olmalı.
func TestAttackOOBWrongCodeBurnsTheAttempt(t *testing.T) {
	sshAddr, _, hostPub, _ := oobBastion(t, 30*time.Second)

	tries := 0
	_, err := kiClient(sshAddr, hostPub, func(loginURL string) (string, error) {
		tries++
		if _, perr := phishedVictim(loginURL); perr != nil {
			return "", perr
		}
		return "ZZZZ-ZZZZ", nil
	})

	if err == nil {
		t.Fatal("yanlış kod kabul edildi")
	}
	if tries > 1 {
		t.Errorf("yanlış koddan sonra %d kez daha soruldu — deneme yanmamış", tries-1)
	}
}
