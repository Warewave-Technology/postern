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
	return oobBastionOpts(t, oobTimeout, false)
}

// oobBastionWithTerminal, web terminali AÇIK düzenek (S4.3 testleri).
func oobBastionWithTerminal(t *testing.T) (sshAddr, apiURL string, hostPub ssh.PublicKey, db *store.Store) {
	t.Helper()
	return oobBastionOpts(t, 0, true)
}

// oobBastionFresh, kullanıcı/rol TOHUMLANMAMIŞ düzenek: JIT sağlama
// testleri kullanıcının yokluğundan başlamak zorunda.
func oobBastionFresh(t *testing.T) (sshAddr, apiURL string, hostPub ssh.PublicKey, db *store.Store) {
	t.Helper()
	return oobBastionOpts(t, 0, false, true)
}

func oobBastionOpts(t *testing.T, oobTimeout time.Duration, terminal bool, fresh ...bool) (sshAddr, apiURL string, hostPub ssh.PublicKey, db *store.Store) {
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
	logins := auth.NewLogins(oidcClient)

	// Bastion önce kurulur: httpapi ile AYNI store'u paylaşmalılar
	// (web /api uçları da aynı veritabanını okuyacak).
	skipSeed := len(fresh) > 0 && fresh[0]
	srv, pub, _, db := newBastionOpts(t, caKeyPath, skipSeed, tc)
	// Dinlemeye başlamadan ÖNCE: EnableOOB kilitsiz alanlara yazıyor.
	srv.EnableOOB(logins, oobTimeout)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	webAPI := httpapi.New(oidcClient, logins, db, logger)
	if terminal {
		// Terminal, sshd ile AYNI bağımlılıkları paylaşır — iki kapı,
		// tek oturum akışı.
		webAPI.EnableTerminal(srv.ProxyDeps(), external)
	}
	api := &http.Server{Handler: webAPI.Handler()}
	go api.Serve(l)
	t.Cleanup(func() { api.Shutdown(context.Background()) })

	return startBastion(t, srv), external, pub, db
}

// approveInBrowser, bir insanın yapacağını yapar: linki açar, Keycloak'a
// girer, yönlendirmeyi postern'in callback'ine kadar TAKİP eder (driveLogin
// redirect'te duruyordu — orada sunucu yoktu, burada var), gelen onay
// formundaki state ile güvenlik kodunu /auth/confirm'e gönderir.
func approveInBrowser(loginURL, userCode string) error {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	client := &http.Client{Jar: jar}

	resp, err := client.Get(loginURL)
	if err != nil {
		return fmt.Errorf("login sayfası: %w", err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	m := regexp.MustCompile(`<form[^>]+action="([^"]+)"`).FindSubmatch(page)
	if m == nil {
		return fmt.Errorf("login formu bulunamadı; sayfa: %.500s", page)
	}

	resp, err = client.PostForm(html.UnescapeString(string(m[1])), url.Values{
		"username": {kcUser},
		"password": {kcPassword},
	})
	if err != nil {
		return fmt.Errorf("login POST: %w", err)
	}
	confirmPage, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("callback %d döndü; sayfa: %.500s", resp.StatusCode, confirmPage)
	}

	sm := regexp.MustCompile(`name="state"\s+value="([^"]+)"`).FindSubmatch(confirmPage)
	if sm == nil {
		return fmt.Errorf("onay formunda state yok; sayfa: %.500s", confirmPage)
	}

	// Onayın kökü, son isteğin VARDIĞI sunucu — yönlendirme zinciri
	// nereye getirdiyse form oraya gider.
	confirmURL := resp.Request.URL.ResolveReference(&url.URL{Path: "/auth/confirm"})
	resp, err = client.PostForm(confirmURL.String(), url.Values{
		"state": {string(sm[1])},
		"code":  {userCode},
	})
	if err != nil {
		return fmt.Errorf("confirm POST: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("confirm %d döndü; sayfa: %.300s", resp.StatusCode, body)
	}
	return nil
}

// kiClient, YALNIZCA keyboard-interactive sunan bir SSH istemcisi kurar;
// sunucunun instruction'ından link ile kodu söker, approve'a verir.
// Anahtar yok: bu istemcinin girebilmesinin tek yolu tarayıcı onayı.
func kiClient(sshAddr string, hostPub ssh.PublicKey, approve func(loginURL, userCode string) error) (*ssh.Client, error) {
	ki := func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		if len(questions) > 0 {
			// Soru beklemiyoruz; gelirse boş cevaplar yeterli.
			return make([]string, len(questions)), nil
		}
		if instruction == "" {
			return nil, nil // bazı sunucular önce boş tur atar
		}
		um := regexp.MustCompile(`https?://\S+`).FindString(instruction)
		cm := regexp.MustCompile(`(?i)security code:\s*(\S+)`).FindStringSubmatch(instruction)
		if um == "" || cm == nil {
			return nil, fmt.Errorf("instruction'da link/kod yok:\n%s", instruction)
		}
		if err := approve(um, cm[1]); err != nil {
			return nil, err
		}
		return nil, nil
	}

	return ssh.Dial("tcp", sshAddr, &ssh.ClientConfig{
		User:            "yigit:web01",
		Auth:            []ssh.AuthMethod{ssh.KeyboardInteractive(ki)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         60 * time.Second,
	})
}

// --- adım 1: mutlu yol ---

func TestOOBLoginEndToEnd(t *testing.T) {
	sshAddr, _, hostPub, db := oobBastion(t, 0)

	client, err := kiClient(sshAddr, hostPub, approveInBrowser)
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

func TestOOBLoginRejectsWrongCode(t *testing.T) {
	sshAddr, _, hostPub, _ := oobBastion(t, 0)

	_, err := kiClient(sshAddr, hostPub, func(loginURL, userCode string) error {
		// Saldırı modeli: linki ele geçiren, TERMİNALİ göremeyen biri.
		wrong := approveInBrowser(loginURL, "AAAA-AAAA")
		if wrong == nil {
			return fmt.Errorf("yanlış kod HTTP katmanında kabul edildi")
		}
		return nil // onay verilmedi; SSH tarafı reddetmeli
	})
	if err == nil {
		t.Fatal("yanlış kodla giriş başarılı oldu")
	}
}

// --- adım 3: timeout temiz kapanıyor ---

func TestOOBLoginTimesOutCleanly(t *testing.T) {
	sshAddr, _, hostPub, _ := oobBastion(t, 3*time.Second)

	start := time.Now()
	_, err := kiClient(sshAddr, hostPub, func(loginURL, userCode string) error {
		return nil // linki aldık ama tarayıcıda HİÇBİR ŞEY yapmıyoruz
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("onaysız giriş başarılı oldu")
	}
	if elapsed > 30*time.Second {
		t.Fatalf("timeout %v sürdü — 3sn'lik sınır işlemiyor", elapsed)
	}
}
