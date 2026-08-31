package auth

// S3.2 birim test merdiveni — Keycloak GEREKTİRMEZ, hızlı döngü için:
//
//	go test ./internal/auth/ -run TestBegin -v      // adım 1
//	go test ./internal/auth/ -run TestExchange -v   // adım 2 (sıra sözleşmesi)
//
// Uçtan uca kanıt test/integration/oidc_test.go'da (Keycloak konteyneri).

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// testOIDC, discovery YAPMADAN kurulmuş bir OIDC döner: Begin yalnızca
// oauth alanına ihtiyaç duyar, sahte uçlar yeterli. NewOIDC'nin kendisi
// entegrasyonda sınanıyor.
func testOIDC() *OIDC {
	cfg := OIDCConfig{
		IssuerURL:   "https://idp.example",
		ClientID:    "postern",
		RedirectURL: "http://127.0.0.1/callback",
	}
	return &OIDC{
		cfg: cfg,
		oauth: oauth2.Config{
			ClientID:    cfg.ClientID,
			RedirectURL: cfg.RedirectURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://idp.example/auth",
				TokenURL: "https://idp.example/token",
			},
			Scopes: []string{"openid", "email"},
		},
	}
}

func TestBeginProducesFreshIndependentSecrets(t *testing.T) {
	o := testOIDC()

	a, err := o.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	b, err := o.Begin()
	if err != nil {
		t.Fatalf("ikinci Begin: %v", err)
	}

	// RFC 7636: verifier en az 43 karakter. 32 baytın base64url'u 43 eder;
	// daha kısası entropi kısıntısı demektir. State ve nonce için de aynı
	// alt sınırı istiyoruz — URL'de yaşayacak değerler kısa olmaya meyilli.
	for name, v := range map[string]string{
		"State": a.State, "Nonce": a.Nonce, "Verifier": a.Verifier,
	} {
		if len(v) < 43 {
			t.Errorf("%s = %d karakter, en az 43 bekleniyor (32 bayt entropi)", name, len(v))
		}
	}

	// Bir deneme İÇİNDE üç değer birbirinden bağımsız olmalı...
	if a.State == a.Nonce || a.State == a.Verifier || a.Nonce == a.Verifier {
		t.Error("state/nonce/verifier birbirinden türetilmiş görünüyor — biri sızarsa üçü sızar")
	}
	// ...ve denemeler ARASINDA tekrar etmemeli.
	if a.State == b.State || a.Nonce == b.Nonce || a.Verifier == b.Verifier {
		t.Error("iki Begin aynı değeri üretti — rastgelelik yok ya da tohum sabit")
	}
}

func TestBeginURLCarriesTheProtocol(t *testing.T) {
	o := testOIDC()

	req, err := o.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	u, err := url.Parse(req.URL)
	if err != nil {
		t.Fatalf("URL parse: %v", err)
	}
	q := u.Query()

	if got := q.Get("response_type"); got != "code" {
		t.Errorf("response_type = %q, beklenen %q", got, "code")
	}
	if got := q.Get("client_id"); got != "postern" {
		t.Errorf("client_id = %q, beklenen %q", got, "postern")
	}
	if got := q.Get("state"); got != req.State {
		t.Errorf("URL'deki state (%q) AuthRequest'tekiyle (%q) aynı değil — Exchange karşılaştırması hiç tutmaz", got, req.State)
	}
	if got := q.Get("nonce"); got != req.Nonce {
		t.Errorf("URL'deki nonce (%q) AuthRequest'tekiyle (%q) aynı değil", got, req.Nonce)
	}
	// "openid" scope'u olmadan sağlayıcı ID token döndürmez; akış sessizce
	// yalnızca-OAuth2'ye düşer ve bunu ancak claims boş gelince fark edersin.
	if !strings.Contains(" "+q.Get("scope")+" ", " openid ") {
		t.Errorf("scope %q, \"openid\" içermiyor", q.Get("scope"))
	}

	// PKCE: yöntem S256 ve challenge GERÇEKTEN verifier'ın özeti olmalı.
	// "plain" ya da yanlış hesap, code'u çalanın işine yarar.
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, beklenen %q", got, "S256")
	}
	sum := sha256.Sum256([]byte(req.Verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if got := q.Get("code_challenge"); got != want {
		t.Errorf("code_challenge verifier'ın S256 özeti değil:\n  got  %q\n  want %q", got, want)
	}
}

// SIRA SÖZLEŞMESİNİN BEKÇİSİ: state kontrolü her şeyden — her ağ
// isteğinden, her alan erişiminden — önce gelir.
//
// OIDC burada BİLEREK sıfır değerli: oauth endpoint'leri boş, verifier
// nil. State kontrolünden önce token endpoint'ine gitmeye ya da
// verifier'a dokunmaya çalışan bir implementasyon burada hata/panik
// üretir. CVE-2026-44347'nin birim testi bu.
func TestExchangeRejectsStateMismatchBeforeAnythingElse(t *testing.T) {
	o := &OIDC{}

	req := AuthRequest{State: "dogru-state", Nonce: "n", Verifier: "v"}
	_, err := o.Exchange(context.Background(), req, "sahte-state", "calinti-code")

	if !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("hata = %v, beklenen ErrStateMismatch", err)
	}
}

/*
 * ⚠️ KEŞİF SINIRLI SÜREDE PES ETMELİ.
 *
 * ÖLÇÜLEN ARIZA: go-oidc, context'e istemci konmadıysa
 * http.DefaultClient'a düşüyor ve onun zaman aşımı yok. Bu çağrı
 * postern'in açılışında, SSH dinleyicisi kurulmadan ÖNCE yapılıyor —
 * yani TCP'yi kabul edip cevap vermeyen bir IdP, OIDC ile hiç ilgisi
 * olmayan SERTİFİKALI SSH'ın hiç açılmamasına yol açıyordu.
 *
 * Test, bağlantıyı kabul edip HİÇ cevap vermeyen bir dinleyiciye karşı
 * koşuyor: sınır yoksa süresiz asılır.
 */
func TestNewOIDCGivesUpOnAHangingProvider(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Kabul et, sonra hiçbir şey yapma.
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			// Bağlantıyı AÇIK tut: istemci cevap bekleyerek asılsın.
			defer c.Close()
		}
	}()

	start := time.Now()
	_, err = NewOIDC(context.Background(), OIDCConfig{
		IssuerURL: "http://" + ln.Addr().String(),
		ClientID:  "postern",
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("cevap vermeyen sağlayıcı başarılı sayıldı")
	}
	// Sınırın kendisi 8s; testin ölçtüğü şey "süresiz asılmıyor".
	if elapsed > 20*time.Second {
		t.Fatalf("keşif %v sürdü — sınır uygulanmıyor ve açılış askıda kalır", elapsed)
	}
	t.Logf("ölçüldü: cevap vermeyen sağlayıcıda %v sonra pes etti", elapsed)
}

/*
 * ⚠️ SAĞLAYICIYA ÖZEL KAPSAMLAR — VE "openid" HER ZAMAN.
 *
 * Kapsamlar sabit "openid email" idi. Eksik olan `profile`,
 * preferred_username'in yaşadığı yer: postern kullanıcı adını
 * istemeden bekliyor, gelmeyince e-posta eşleştirmesine düşüyordu.
 * Okta ve Auth0 ise grupları ancak açıkça istenirse gönderiyor.
 *
 * "openid"in her koşulda eklenmesi ayrı bir karar: onsuz akış OIDC
 * olmaktan çıkıp düz OAuth2'ye dönüyor ve sağlayıcı ID token
 * göndermiyor — yani doğrulanacak kimlik kalmıyor. Bunu operatörün
 * unutabileceği bir alana bırakmak, unutulduğu gün kimlik doğrulamayı
 * sessizce kapatmak olurdu.
 */
func TestRequestedScopes(t *testing.T) {
	has := func(list []string, want string) bool {
		for _, s := range list {
			if s == want {
				return true
			}
		}
		return false
	}

	// Varsayılan: profile DAHİL.
	def := requestedScopes("")
	for _, want := range []string{"openid", "email", "profile"} {
		if !has(def, want) {
			t.Errorf("varsayılan kapsamlarda %q yok: %v", want, def)
		}
	}

	// Operatörün listesi kullanılıyor.
	custom := requestedScopes("email groups")
	if !has(custom, "groups") {
		t.Errorf("özel kapsam düşmüş: %v", custom)
	}
	// ⚠️ openid yazılmasa da var.
	if !has(custom, "openid") {
		t.Fatalf("openid eklenmemiş (%v) — akış OIDC olmaktan çıkar, "+
			"sağlayıcı ID token göndermez ve doğrulanacak kimlik kalmaz", custom)
	}
	// Tekrar yok: "openid" iki kez yazılırsa listede bir kez.
	twice := requestedScopes("openid openid email")
	n := 0
	for _, s := range twice {
		if s == "openid" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("openid %d kez: %v", n, twice)
	}
}
