//go:build integration

package integration

// S3.2 entegrasyon merdiveni — gerçek bir Keycloak'a karşı:
//
//	go test -tags integration -run TestKeycloakRealmServesDiscovery ./test/integration/  // adım 0: düzenek
//	go test -tags integration -run TestOIDCFullFlow ./test/integration/                  // adım 1
//	go test -tags integration -run TestOIDCRejects ./test/integration/                   // adım 2-4
//
// Adım 0 senin kodundan bağımsızdır: konteyner ve realm çalışıyor mu?
// Kırmızıysa sorun düzenekte, oidc.go'da değil.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/warewave/postern/internal/auth"
)

const (
	kcUser     = "yigit"
	kcPassword = "parola-test-123"
	kcRedirect = "http://127.0.0.1/callback"
)

// startKeycloak, realm'i içe aktarılmış bir Keycloak kaldırır ve issuer
// URL'sini döner. Konteyner testler arasında paylaşılmaz — her test kendi
// temiz IdP'siyle çalışır (yavaş ama deterministik; Keycloak ~20sn açılır).
func startKeycloak(t *testing.T) (issuer string) {
	t.Helper()
	ctx := context.Background()

	realmPath, err := filepath.Abs(filepath.Join("testdata", "keycloak", "postern-realm.json"))
	if err != nil {
		t.Fatal(err)
	}

	cont, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "quay.io/keycloak/keycloak:26.0",
			Cmd:          []string{"start-dev", "--import-realm"},
			ExposedPorts: []string{"8080/tcp"},
			Env: map[string]string{
				"KC_BOOTSTRAP_ADMIN_USERNAME": "admin",
				"KC_BOOTSTRAP_ADMIN_PASSWORD": "admin-test-123",
			},
			Files: []testcontainers.ContainerFile{{
				HostFilePath:      realmPath,
				ContainerFilePath: "/opt/keycloak/data/import/postern-realm.json",
				FileMode:          0o644,
			}},
			WaitingFor: wait.ForHTTP("/realms/postern/.well-known/openid-configuration").
				WithPort("8080/tcp").
				WithStartupTimeout(3 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("keycloak başlatılamadı (Docker ayakta mı?): %v", err)
	}
	t.Cleanup(func() { _ = cont.Terminate(context.Background()) })

	host, err := cont.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := cont.MappedPort(ctx, "8080")
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("http://%s:%d/realms/postern", host, port.Num())
}

// --- adım 0: düzenek sağlığı (senin kodun daha yokken yeşil olmalı) ---

func TestKeycloakRealmServesDiscovery(t *testing.T) {
	issuer := startKeycloak(t)

	resp, err := http.Get(issuer + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var doc struct {
		Issuer   string `json:"issuer"`
		AuthURL  string `json:"authorization_endpoint"`
		TokenURL string `json:"token_endpoint"`
		JWKSURL  string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	// Discovery'nin issuer'ı config'tekiyle birebir aynı olmalı — go-oidc
	// da aynı karşılaştırmayı yapacak; uyuşmazsa NewOIDC daha ilk adımda
	// anlaşılır bir hatayla düşer.
	if doc.Issuer != issuer {
		t.Errorf("discovery issuer = %q, beklenen %q", doc.Issuer, issuer)
	}
	for name, v := range map[string]string{"authorization": doc.AuthURL, "token": doc.TokenURL, "jwks": doc.JWKSURL} {
		if v == "" {
			t.Errorf("discovery %s endpoint boş", name)
		}
	}
}

// driveLogin, bir insanın tarayıcıda yapacağını yapar: yetkilendirme
// URL'sini açar, Keycloak'ın login formunu doldurur ve sağlayıcının
// redirect_uri'ye döndürdüğü code+state'i yakalar.
//
// redirect_uri'de gerçek bir sunucu YOK: istemci son yönlendirmeyi takip
// etmeyip Location başlığını söker. Böylece test, dinleyici port
// derdine girmiyor.
func driveLogin(t *testing.T, authURL string) (code, state string) {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Jar: jar,
		// redirect_uri'ye giden yönlendirmede DUR: orada sunucu yok,
		// istediğimiz şey Location başlığının kendisi.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if strings.HasPrefix(req.URL.String(), kcRedirect) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// 1. Yetkilendirme sayfası: Keycloak login formunu döner.
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}

	// 2. Formun action'ını sök. Keycloak HTML'i sürümden sürüme oynar ama
	//    login formu tek ve action'ı mutlaktır.
	m := regexp.MustCompile(`<form[^>]+action="([^"]+)"`).FindSubmatch(body)
	if m == nil {
		t.Fatalf("login formu bulunamadı; sayfa:\n%.2000s", body)
	}
	action := html.UnescapeString(string(m[1]))

	// 3. Kimlik bilgilerini gönder → sağlayıcı redirect_uri'ye yönlendirir.
	resp, err = client.PostForm(action, url.Values{
		"username": {kcUser},
		"password": {kcPassword},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, kcRedirect) {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("login redirect_uri'ye varmadı; status=%d location=%q sayfa:\n%.1000s", resp.StatusCode, loc, b)
	}
	cb, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	if e := cb.Query().Get("error"); e != "" {
		t.Fatalf("sağlayıcı hata döndürdü: %s (%s)", e, cb.Query().Get("error_description"))
	}
	return cb.Query().Get("code"), cb.Query().Get("state")
}

func newOIDCClient(t *testing.T, issuer, clientID string) *auth.OIDC {
	t.Helper()

	o, err := auth.NewOIDC(context.Background(), auth.OIDCConfig{
		IssuerURL:   issuer,
		ClientID:    clientID,
		RedirectURL: kcRedirect,
	})
	if err != nil {
		t.Fatalf("NewOIDC: %v", err)
	}
	return o
}

// --- adım 1: tam akış ---

// S3.2'nin "Bitti" kanıtı: Begin → (kullanıcı girişi) → Exchange, ve dönen
// kimlik doğrulanmış e-postayı taşıyor.
func TestOIDCFullFlow(t *testing.T) {
	issuer := startKeycloak(t)
	o := newOIDCClient(t, issuer, "postern")

	req, err := o.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	code, state := driveLogin(t, req.URL)
	if code == "" {
		t.Fatal("callback'te code yok")
	}

	id, err := o.Exchange(context.Background(), req, state, code)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if id.Email != "yigit@warewave.io" {
		t.Errorf("Email = %q, beklenen %q", id.Email, "yigit@warewave.io")
	}
	if id.Subject == "" {
		t.Error("Subject boş — sağlayıcının değişmez kimliği kaybolmuş")
	}
}

// --- adım 2: state uyuşmazlığı GERÇEK bir code ile ---

// Birim test sahte code'la sırayı sınıyordu; burada elde sağlayıcının
// kestiği GEÇERLİ bir code var ve yine de reddedilmeli. Saldırı modeli:
// kurbanın tarayıcısına saldırganın callback'i enjekte edildi.
func TestOIDCRejectsForgedState(t *testing.T) {
	issuer := startKeycloak(t)
	o := newOIDCClient(t, issuer, "postern")

	req, err := o.Begin()
	if err != nil {
		t.Fatal(err)
	}
	code, _ := driveLogin(t, req.URL)

	_, err = o.Exchange(context.Background(), req, "saldirganin-state-degeri", code)
	if !errors.Is(err, auth.ErrStateMismatch) {
		t.Fatalf("hata = %v, beklenen ErrStateMismatch — geçerli code state'i telafi edemez", err)
	}
}

// --- adım 3: süresi dolmuş token ---

// Token'ı password grant ile alıyoruz (test düzeneğine özel arka kapı;
// realm'de directAccessGrantsEnabled bunun için açık) çünkü süre aşımını
// sınamak için HAM token'ı bekletip yeniden doğrulamak gerekiyor —
// Exchange ham token'ı dışarı vermez, VerifyIDToken tam bu yüzden ayrı.
//
// postern-short istemcisinin token ömrü 3 saniye (realm JSON'unda).
func TestOIDCRejectsExpiredToken(t *testing.T) {
	issuer := startKeycloak(t)
	o := newOIDCClient(t, issuer, "postern-short")

	resp, err := http.PostForm(issuer+"/protocol/openid-connect/token", url.Values{
		"grant_type": {"password"},
		"client_id":  {"postern-short"},
		"username":   {kcUser},
		"password":   {kcPassword},
		"scope":      {"openid"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		t.Fatal(err)
	}
	if tok.IDToken == "" {
		t.Fatal("password grant id_token döndürmedi — realm'de scope/grant ayarı bozuk")
	}

	// Taze hâli geçerli olmalı (yoksa süre aşımını değil başka bir şeyi
	// sınıyoruz demektir)...
	if _, err := o.VerifyIDToken(context.Background(), tok.IDToken, ""); err != nil {
		t.Fatalf("taze token reddedildi: %v", err)
	}

	// ...3 saniyelik ömrün dolmasını bekle, aynı token artık geçersiz.
	time.Sleep(5 * time.Second)

	if _, err := o.VerifyIDToken(context.Background(), tok.IDToken, ""); err == nil {
		t.Fatal("süresi dolmuş token kabul edildi")
	}
}

// --- adım 4: doğrulanmamış e-posta taşınmaz ---

// suheda kullanıcısının realm'de emailVerified=false. Kimlik eşleştirmesi
// e-posta üzerinden yapılacağı için (S3.3), doğrulanmamış adres Identity'ye
// HİÇ girmemeli — boş dönmeli ki yanlışlıkla bile eşleştirilemesin.
func TestOIDCDropsUnverifiedEmail(t *testing.T) {
	issuer := startKeycloak(t)
	o := newOIDCClient(t, issuer, "postern")

	resp, err := http.PostForm(issuer+"/protocol/openid-connect/token", url.Values{
		"grant_type": {"password"},
		"client_id":  {"postern"},
		"username":   {"suheda"},
		"password":   {kcPassword},
		"scope":      {"openid"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		t.Fatal(err)
	}

	id, err := o.VerifyIDToken(context.Background(), tok.IDToken, "")
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if id.Email != "" {
		t.Fatalf("Email = %q — doğrulanmamış e-posta Identity'ye taşınmış", id.Email)
	}
	if id.Subject == "" {
		t.Error("Subject boş olmamalı — kimliğin kendisi geçerli, yalnızca e-postası güvenilmez")
	}
}
