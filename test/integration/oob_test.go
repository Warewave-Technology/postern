//go:build integration

package integration

// S3.3'ün "Bitti" kanıtı: ANAHTARSIZ bir SSH istemcisi yalnızca tarayıcı
// onayıyla hedefe düşüyor. Zincirin tamamı gerçek: keyboard-interactive
// (OpenSSH protokolü), Keycloak login formu, postern'in callback'i, kod
// onayı, policy, sertifika, hedef konteyner, denetim kaydı.
//
//	go test -tags integration -run TestOOB -v ./test/integration/
//
// (Birim merdiveni internal/auth/pending_test.go'da — oradan başla.)

import (
	"context"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/httpapi"
	"github.com/warewave/postern/internal/store"
)

// oobBastion, OOB'si açık TAM bir düzenek kurar: CA → hedef konteyner →
// callback dinleyicisi → Keycloak → bastion. Sıralamanın iki kısıtı var:
// hedef, bastion'la AYNI CA'ya güvenmeli (CA önce), ve Keycloak callback
// portunu redirect olarak tanımalı (dinleyici Keycloak'tan önce).
func oobBastion(t *testing.T, oobTimeout time.Duration) (sshAddr, apiURL string, hostPub ssh.PublicKey, db *store.Store) {
	t.Helper()
	a, b, c, d, _ := oobBastionOpts(t, oobTimeout, false)
	return a, b, c, d
}

/*
 * oobBastionWithHolder, sağlayıcı TUTUCUSUNU da döner.
 *
 * ⚠️ Var olma sebebi: OIDC ayarları artık çalışırken değişebiliyor ve
 * "akış ortasında sağlayıcı değişirse ne olur" sorusunun cevabı ancak
 * tutucuya erişen bir testle ölçülebilir.
 */
func oobBastionWithHolder(t *testing.T) (sshAddr, apiURL string, hostPub ssh.PublicKey, db *store.Store, holder *auth.OIDCHolder) {
	t.Helper()
	return oobBastionOpts(t, 0, false)
}

// oobBastionWithTerminal, web terminali AÇIK düzenek (S4.3 testleri).
func oobBastionWithTerminal(t *testing.T) (sshAddr, apiURL string, hostPub ssh.PublicKey, db *store.Store) {
	t.Helper()
	a, b, c, d, _ := oobBastionOpts(t, 0, true)
	return a, b, c, d
}

// oobBastionFresh, kullanıcı/rol TOHUMLANMAMIŞ düzenek: JIT sağlama
// testleri kullanıcının yokluğundan başlamak zorunda.
func oobBastionFresh(t *testing.T) (sshAddr, apiURL string, hostPub ssh.PublicKey, db *store.Store) {
	t.Helper()
	a, b, c, d, _ := oobBastionOpts(t, 0, false, true)
	return a, b, c, d
}

func oobBastionOpts(t *testing.T, oobTimeout time.Duration, terminal bool, fresh ...bool) (sshAddr, apiURL string, hostPub ssh.PublicKey, db *store.Store, holder *auth.OIDCHolder) {
	t.Helper()

	caKeyPath, caPub := newTestCA(t)
	tgt := startCertTarget(t, caPub)
	tc := tgt.target()
	tc.Name = "web01"

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	external := "http://" + l.Addr().String()

	issuer := startKeycloak(t, external+"/auth/callback")

	oidcClient, err := auth.NewOIDC(context.Background(), auth.OIDCConfig{
		IssuerURL:   issuer,
		ClientID:    "postern",
		RedirectURL: external + "/auth/callback",
	})
	if err != nil {
		t.Fatalf("NewOIDC: %v", err)
	}
	holder = auth.NewOIDCHolder()
	holder.Install(oidcClient)
	logins := auth.NewLogins(holder)

	// Bastion önce kurulur: httpapi ile AYNI store'u paylaşmalılar
	// (web /api uçları da aynı veritabanını okuyacak).
	skipSeed := len(fresh) > 0 && fresh[0]
	srv, pub, _, db := newBastionOpts(t, caKeyPath, skipSeed, tc)
	// Dinlemeye başlamadan ÖNCE: EnableOOB kilitsiz alanlara yazıyor.
	srv.EnableOOB(logins, oobTimeout)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	webAPI := httpapi.New(holder, logins, db, logger)
	// Kayıt izleme uçları: sshd ile AYNI depo (serve.go'daki bağlamanın
	// aynısı) — kayıtların yazıldığı yer ile okunduğu yer ayrışamaz.
	webAPI.UseRecordings(srv.Records())
	if terminal {
		// Terminal, sshd ile AYNI bağımlılıkları paylaşır — iki kapı,
		// tek oturum akışı.
		webAPI.EnableTerminal(srv.ProxyDeps(), external)
	}
	api := &http.Server{Handler: webAPI.Handler()}
	go api.Serve(l)
	t.Cleanup(func() { api.Shutdown(context.Background()) })

	return startBastion(t, srv), external, pub, db, holder
}

// browserSignInForCode, bir insanın yapacağını yapar: linki açar, Keycloak'a
// girer, yönlendirmeyi postern'in callback'ine kadar TAKİP eder (driveLogin
// redirect'te duruyordu — orada sunucu yoktu, burada var), gelen onay
// formundaki state ile güvenlik kodunu /auth/confirm'e gönderir.
// browserSignInForCode, KURBANIN/kullanıcının tarayıcıda yaptığı şeyi
// yapar ve onay sayfasında GÖSTERİLEN doğrulama kodunu döner.
//
// ⚠️ YÖN: kod artık terminalde değil TARAYICIDA beliriyor ve terminale
// yazılıyor. Sebebi internal/auth/pending.go'daki UserCode yorumunda:
// eski yönde saldırgan kodu kendi terminalinde görüp linkle birlikte
// kurbana yolluyordu.
func browserSignInForCode(loginURL string) (string, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Jar: jar}

	resp, err := client.Get(loginURL)
	if err != nil {
		return "", fmt.Errorf("login sayfası: %w", err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	m := regexp.MustCompile(`<form[^>]+action="([^"]+)"`).FindSubmatch(page)
	if m == nil {
		return "", fmt.Errorf("login formu bulunamadı; sayfa: %.500s", page)
	}

	resp, err = client.PostForm(html.UnescapeString(string(m[1])), url.Values{
		"username": {kcUser},
		"password": {kcPassword},
	})
	if err != nil {
		return "", fmt.Errorf("login POST: %w", err)
	}
	confirmPage, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("callback %d döndü; sayfa: %.500s", resp.StatusCode, confirmPage)
	}

	// Kod, sayfada class="code" ile işaretli.
	//
	// ⚠️ ÖNCEDEN `letter-spacing:.25em` ARANIYORDU — yani bir INLINE
	// STİL değerine. Sayfa <style> bloğuna taşınıp sınıflara geçince o
	// dize kayboldu ve bu test, ürün doğru çalışırken kırıldı. Testin
	// tutunduğu şey sunumun bir ayrıntısı değil, anlamı olmalı: sınıf
	// adı sayfanın sözleşmesinin parçası, satır içi stil değil.
	cm := regexp.MustCompile(`(?s)class="code"[^>]*>\s*([A-Z0-9-]+)\s*<`).FindSubmatch(confirmPage)
	if cm == nil {
		return "", fmt.Errorf("onay sayfasında kod yok; sayfa: %.700s", confirmPage)
	}
	return string(cm[1]), nil
}

// kiClient, YALNIZCA keyboard-interactive sunan bir SSH istemcisi kurar;
// sunucunun instruction'ından link ile kodu söker, approve'a verir.
// Anahtar yok: bu istemcinin girebilmesinin tek yolu tarayıcı onayı.
func kiClient(sshAddr string, hostPub ssh.PublicKey, approve func(loginURL string) (string, error)) (*ssh.Client, error) {
	ki := func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		um := regexp.MustCompile(`https?://\S+`).FindString(instruction)
		if um == "" {
			if len(questions) > 0 {
				return make([]string, len(questions)), nil
			}
			return nil, nil // bazı sunucular önce boş tur atar
		}

		// Tarayıcı adımı: giriş yap ve sayfada GÖSTERİLEN kodu al.
		code, err := approve(um)
		if err != nil {
			return nil, err
		}
		if len(questions) == 0 {
			return nil, nil
		}
		answers := make([]string, len(questions))
		answers[0] = code
		return answers, nil
	}

	return ssh.Dial("tcp", sshAddr, &ssh.ClientConfig{
		User:            "yigit:web01",
		Auth:            []ssh.AuthMethod{ssh.KeyboardInteractive(ki)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         90 * time.Second,
	})
}

// --- adım 1: mutlu yol ---

func TestOOBLoginEndToEnd(t *testing.T) {
	sshAddr, _, hostPub, db := oobBastion(t, 0)

	client, err := kiClient(sshAddr, hostPub, browserSignInForCode)
	if err != nil {
		t.Fatalf("OOB girişi başarısız: %v", err)
	}
	defer client.Close()

	// Kimlik zinciri hedefe kadar: IdP'deki yigit → users.email → policy
	// → sertifika principal'ı "postern".
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	out, err := sess.Output("id -un")
	sess.Close()
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if got := string(out); got != "postern\n" {
		t.Errorf("hedefteki hesap = %q, beklenen %q", got, "postern\n")
	}

	// Denetim kaydı OOB oturumu için de tutulmalı — giriş yöntemi
	// değişti diye "kim girdi" sorusu cevapsız kalamaz.
	recorded, err := db.Sessions(context.Background(), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(recorded) != 1 || recorded[0].User != "yigit" {
		t.Errorf("denetim kaydı = %+v, beklenen yigit'in tek oturumu", recorded)
	}
}

// --- adım 2: yanlış kod ---
//
// Saldırı modeli DEĞİŞTİ ve daha güçlü: artık linki ele geçiren değil,
// linki ÜRETEN saldırgan modelleniyor. Kod tarayıcıda gösterildiği için
// saldırganın elinde yok; uydurması gerekiyor.
func TestOOBLoginRejectsWrongCode(t *testing.T) {
	sshAddr, _, hostPub, _ := oobBastion(t, 0)

	_, err := kiClient(sshAddr, hostPub, func(loginURL string) (string, error) {
		if _, berr := browserSignInForCode(loginURL); berr != nil {
			return "", berr
		}
		return "AAAA-AAAA", nil // tarayıcıdaki gerçek kod DEĞİL
	})
	if err == nil {
		t.Fatal("yanlış kodla giriş başarılı oldu")
	}
}

// --- adım 3: timeout temiz kapanıyor ---

func TestOOBLoginTimesOutCleanly(t *testing.T) {
	sshAddr, _, hostPub, _ := oobBastion(t, 3*time.Second)

	start := time.Now()
	_, err := kiClient(sshAddr, hostPub, func(loginURL string) (string, error) {
		// Linki aldık ama tarayıcıda HİÇBİR ŞEY yapmıyoruz; kod da
		// yok, dolayısıyla boş cevap veriyoruz ve süre dolmalı.
		return "", nil
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("onaysız giriş başarılı oldu")
	}
	if elapsed > 30*time.Second {
		t.Fatalf("timeout %v sürdü — 3sn'lik sınır işlemiyor", elapsed)
	}
}
