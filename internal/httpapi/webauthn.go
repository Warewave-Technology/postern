package httpapi

/*
 * Donanım güvenlik anahtarları (WebAuthn) — göç 039.
 *
 * ⚠️ NEDEN TOTP YETMİYOR. Kod PAYLAŞILAN bir sırdan üretiliyor ve
 * kullanıcı onu bir kutuya YAZIYOR. Sahte bir sayfa o kutuyu çizip
 * kodu otuz saniye içinde gerçek sunucuya aktarabilir; kullanıcı
 * tarafında bunu fark ettirecek hiçbir şey yok. WebAuthn imzası
 * KAYNAĞA bağlı: sahte alan adı için üretilen imzayı bu sunucu kabul
 * etmiyor, çünkü imzalanan veri hangi kaynağa gidildiğini taşıyor.
 * Panel postern'in kontrol düzlemi olduğu için farkın ısırdığı yer
 * tam olarak burası.
 */

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/Warewave-Technology/postern/internal/store"
)

/*
 * challengeTTL, bir törenin açık kalabileceği süre.
 *
 * ⚠️ BU BİR OTURUM DEĞİL. Meydan okuma tek kullanımlık bir nonce:
 * elinde tutan biri hiçbir şey yapamıyor, çünkü imzayı ancak
 * doğrulayıcı atabiliyor ve ikinci istek parolayı YİNE taşıyor.
 * Süre, terk edilmiş törenlerin bellekte birikmemesi için var —
 * güvenlik sınırı diye anlatılmamalı.
 */
const challengeTTL = 2 * time.Minute

// pendingCeremony, başlatılmış ama bitmemiş bir tören.
type pendingCeremony struct {
	data    webauthn.SessionData
	started time.Time
}

/*
 * webauthnFor, bu kurulumun WebAuthn yapılandırmasını üretir.
 *
 * ⚠️ RP ID, TARAYICIDAN GÖRÜLEN ADRESTEN TÜRETİLİYOR ve başka bir yerden
 * türetilemez: imzanın bağlandığı şey o. external_url yanlışsa kayıt
 * çalışır ama giriş çalışmaz — bu yüzden hata, düzeltilecek ayarın adını
 * veriyor.
 *
 * ⚠️ IP ADRESİ RP ID OLAMAZ. Şartname RP ID'nin kayıtlanabilir bir alan
 * adı olmasını istiyor; "localhost" özel bir istisna, "127.0.0.1" DEĞİL.
 * Ölçüldü: tarayıcı sessizce reddetmiyor, ama kaydı da kabul etmiyor.
 */
func webauthnFor(externalURL string) (*webauthn.WebAuthn, error) {
	if externalURL == "" {
		return nil, errors.New("webauthn: http.external_url is not set")
	}

	u, err := url.Parse(externalURL)
	if err != nil {
		return nil, errors.New("webauthn: http.external_url is not a URL")
	}

	host := u.Hostname()
	if host == "" {
		return nil, errors.New("webauthn: http.external_url has no host")
	}
	if ip := net.ParseIP(host); ip != nil {
		return nil, errors.New(
			"webauthn: http.external_url must name a host, not an IP address " +
				"(browsers accept \"localhost\" but not \"127.0.0.1\")")
	}

	origin := u.Scheme + "://" + u.Host

	return webauthn.New(&webauthn.Config{
		RPDisplayName: "postern",
		RPID:          host,
		RPOrigins:     []string{origin},
		/*
		 * ⚠️ KULLANICI DOĞRULAMASI İSTENİYOR (PIN ya da biyometri).
		 * "Sadece dokun" yeterli sayılsaydı, çalınan bir anahtar tek
		 * başına ikinci faktör olurdu — oysa ikinci faktörün amacı
		 * parolayı bilen birinin elinde ayrıca bir şey olmasını
		 * istemek, ve o şeyin de sahibine bağlı olması.
		 */
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
		},
	})
}

/*
 * webauthnUser, go-webauthn'ın beklediği kullanıcı görünümü.
 *
 * ⚠️ WebAuthnID KULLANICI ADI DEĞİL, KİMLİK. Kullanıcı adı
 * değiştirilebiliyor (postern'de hesap adı yeniden kullanılabiliyor:
 * user purge); anahtarın bağlandığı şey değişirse doğrulayıcıdaki kayıt
 * sessizce başka bir kişiye işaret ederdi.
 */
type webauthnUser struct {
	id    []byte
	name  string
	creds []webauthn.Credential
}

func (u webauthnUser) WebAuthnID() []byte                         { return u.id }
func (u webauthnUser) WebAuthnName() string                       { return u.name }
func (u webauthnUser) WebAuthnDisplayName() string                { return u.name }
func (u webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// webauthnUserFor, hesabın kayıtlı anahtarlarını kütüphanenin biçimine çevirir.
func (s *Server) webauthnUserFor(r *http.Request, username string) (webauthnUser, error) {
	stored, err := s.store.WebAuthnCredentials(r.Context(), username)
	if err != nil {
		return webauthnUser{}, err
	}

	id, err := s.store.UserIdentity(r.Context(), username)
	if err != nil {
		return webauthnUser{}, err
	}

	u := webauthnUser{id: []byte(id), name: username}
	for _, c := range stored {
		raw, derr := base64.RawURLEncoding.DecodeString(c.ID)
		if derr != nil {
			// ⚠️ BOZUK SATIR ATLANIYOR, TÖREN DÜŞMÜYOR. Tek bir
			// okunamayan kayıt, kişinin öbür anahtarıyla girmesini
			// engellememeli.
			s.logger.Error("webauthn credential id is not base64url",
				"user", username, "id", c.ID)
			continue
		}
		u.creds = append(u.creds, webauthn.Credential{
			ID:        raw,
			PublicKey: c.PublicKey,
			Authenticator: webauthn.Authenticator{
				AAGUID:    c.AAGUID,
				SignCount: c.SignCount,
			},
		})
	}

	return u, nil
}

/*
 * ceremonies, süren törenleri tutar.
 *
 * ⚠️ BELLEKTE VE TEK SÜREÇTE. postern zaten tek düğüm (belgelenmiş
 * sınır); veritabanına yazmak, hiçbir şey kazandırmadan meydan
 * okumaları kalıcı hâle getirirdi. Yeniden başlatma töreni düşürüyor
 * ve kullanıcı yeniden deniyor — kaybedilen şey bir tıklama.
 */
type ceremonies struct {
	mu sync.Mutex
	m  map[string]pendingCeremony
}

func (c *ceremonies) put(key string, data webauthn.SessionData) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.m == nil {
		c.m = map[string]pendingCeremony{}
	}
	c.prune()
	c.m[key] = pendingCeremony{data: data, started: time.Now()}
}

/*
 * take, töreni ALIP SİLER.
 *
 * ⚠️ TEK KULLANIMLIK. Bırakılsaydı aynı meydan okuma için birden çok
 * imza denenebilirdi; WebAuthn'ın tekrar saldırılarına karşı koyduğu
 * şey tam olarak meydan okumanın bir kez geçerli olması.
 */
func (c *ceremonies) take(key string) (webauthn.SessionData, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.prune()
	p, ok := c.m[key]
	if !ok {
		return webauthn.SessionData{}, false
	}
	delete(c.m, key)

	return p.data, true
}

// prune, süresi geçmiş törenleri atar. Kilit TUTULUYOR olmalı.
func (c *ceremonies) prune() {
	for k, p := range c.m {
		if time.Since(p.started) > challengeTTL {
			delete(c.m, k)
		}
	}
}

// randomName, ad verilmemiş bir anahtara okunur bir etiket üretir.
func randomName() string {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return "security key"
	}

	return "security key " + strings.ToUpper(base64.RawURLEncoding.EncodeToString(b))
}

// credentialName, kişinin verdiği adı temizler.
func credentialName(raw string) string {
	name := strings.TrimSpace(raw)
	// Kontrol karakterleri panelde satır kırar; ad bir etiket, metin değil.
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, name)

	if name == "" {
		return randomName()
	}
	if len(name) > 60 {
		name = name[:60]
	}

	return name
}

// storedFrom, doğrulanmış bir kimlik bilgisini saklanacak biçime çevirir.
func storedFrom(c *webauthn.Credential, name string) store.WebAuthnCredential {
	return store.WebAuthnCredential{
		ID:        base64.RawURLEncoding.EncodeToString(c.ID),
		PublicKey: c.PublicKey,
		AAGUID:    c.Authenticator.AAGUID,
		SignCount: c.Authenticator.SignCount,
		Name:      name,
	}
}

// base64url, ham kimlik bilgisi kimliğini saklanan biçime çevirir.
func base64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
