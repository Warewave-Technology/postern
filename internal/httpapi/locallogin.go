package httpapi

import (
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/store"
)

/*
 * Yerel giriş: postern'in KENDİ kapısı.
 *
 * ⚠️ BU, ÜRÜNE EKLENEN İLK AĞDAN ERİŞİLEBİLİR KİMLİK BİLGİSİ. Bugüne
 * kadar postern'in doğruladığı hiçbir sır yoktu; kimlik ya bir açık
 * anahtarla ya da IdP'nin verdiği bir belirteçle geliyordu. Kalıcı ve
 * gerçek bir yüzey artışı, ve aşağıdaki her kural onu olabildiğince
 * küçük tutmak için.
 *
 * Sırrın 128 bit ve MAKİNE ÜRETİMİ olması bu dosyadaki üç kararın
 * dayanağı:
 *   - Kilitleme YOK. Kilitleme, 2^128'i denemeyen bir saldırgana
 *     hiçbir şey kazandırmaz ama kimliği doğrulanmamış birine
 *     kurulumun tek yöneticisini dışarıda tutan bir düğme verirdi.
 *   - Hız sınırı GÜVENLİK için değil, YÜK için: her deneme argon2id
 *     ile 19MB ayırtıyor.
 *   - Biçimi tutmayan değer KDF'e hiç ulaşmıyor (auth.NormalizeSecret).
 */

// localLoginSlots, aynı anda yürütülebilecek doğrulama sayısı.
//
// argon2 parametreleri deneme başına 19MB ayırtıyor; sınırsız bırakmak,
// kimliği doğrulanmamış bir isteğin belleği tüketmesine izin vermek
// olurdu. Sıra beklemek yerine REDDEDİYORUZ: kuyruk, saldırganın
// bedavaya tutabileceği bir kaynak olurdu.
const localLoginSlots = 4

// localLoginPerIP, tek bir kaynaktan dakikada kabul edilen deneme.
//
// ⚠️ İSTEMCİ ADRESİ GÜVENİLİR OLMAYABİLİR: ters vekil arkasında her
// istek vekilin adresinden gelir ve bu sınır tek bir küresel kovaya
// çöker. O yüzden TEK savunma değil — localLoginSlots her hâlükârda
// üstte duruyor.
const localLoginPerIP = 10

// localLimiter, kaynak başına basit bir sayaç penceresi.
type localLimiter struct {
	mu     sync.Mutex
	counts map[string]int
	window time.Time
	now    func() time.Time
}

func newLocalLimiter() *localLimiter {
	return &localLimiter{counts: map[string]int{}, now: time.Now}
}

// allow, bu kaynağın penceredeki kotasını tüketir.
func (l *localLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	// Pencere kaydırma yerine sıfırlama: bellekte kaynak başına satır
	// biriktirmemek için. Saldırgan pencere sınırında iki kat deneme
	// yapabilir; 128 bitlik bir sır karşısında bunun bir anlamı yok.
	if now.Sub(l.window) >= time.Minute {
		l.counts = map[string]int{}
		l.window = now
	}
	if l.counts[key] >= localLoginPerIP {
		return false
	}
	l.counts[key]++
	return true
}

/*
 * handleLocalLogin: POST /auth/local
 *
 * Gövde: {"username": "...", "secret": "..."}
 */
func (s *Server) handleLocalLogin(w http.ResponseWriter, r *http.Request) {
	log := s.logger.With("remote", r.RemoteAddr)

	var in struct {
		Username string `json:"username"`
		Secret   string `json:"secret"`
	}
	if !readJSON(w, r, &in) {
		return
	}

	if !s.localLimit.allow(clientKey(r)) {
		// 429: "yanlış sır" ile karıştırılmamalı, yoksa operatör
		// elindeki sırrın bozuk olduğunu sanır.
		w.Header().Set("Retry-After", "60")
		writeErr(w, http.StatusTooManyRequests, "too many sign-in attempts; try again in a minute")
		return
	}

	select {
	case s.localSlots <- struct{}{}:
		defer func() { <-s.localSlots }()
	default:
		w.Header().Set("Retry-After", "5")
		writeErr(w, http.StatusServiceUnavailable, "sign-in is busy; try again shortly")
		return
	}

	/*
	 * ⚠️ HANGİ KAYNAĞA SORULACAĞI AÇIKÇA KARARLAŞTIRILIYOR.
	 *
	 * Hesabın YEREL bir kimlik bilgisi varsa yerel doğrulayıcı, yoksa
	 * ve dizin parolası açıksa bind. Sıra bu yönde olmak zorunda:
	 * tersi olsaydı, yerel yöneticinin sırrı dizine gönderilmeye
	 * çalışılırdı — kurumsal olmayan bir sırrı kurumsal bir sisteme
	 * yollamak.
	 *
	 * ⚠️ Bu yönlendirme GEÇİCİ. Ürün kararı "aynı anda tek aktif
	 * kaynak, biri açıksa yerel kapanır" yönünde; o anahtar geldiğinde
	 * burası bir if değil, aktif kaynağın kendisi olacak.
	 */
	verifier, err := s.store.LocalCredential(r.Context(), in.Username)
	switch {
	case err == nil:
		// Yerel yol: aşağıda.
	case errors.Is(err, store.ErrNotFound):
		if s.directoryAuthEnabled(r.Context()) {
			s.directoryLogin(w, r, log, in.Username, in.Secret)
			return
		}
		/*
		 * ⚠️ KULLANICI VARLIĞI SIZDIRILMIYOR.
		 *
		 * Hesap yoksa da doğrulama YAPILIYOR (üretilmiş bir sahte
		 * doğrulayıcıya karşı) ve dönen hata birebir aynı. Aksi hâlde
		 * yanıt süresi ve metni, "bu kullanıcı adı var" bilgisini
		 * kimliği doğrulanmamış herkese verirdi.
		 */
		verifier = decoyVerifier()
	default:
		log.Error("local login lookup failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "sign-in failed")
		return
	}

	if !auth.VerifyLocalSecret(verifier, in.Secret) {
		/*
		 * ⚠️ DENENEN KULLANICI ADI HAM OLARAK KAYDEDİLMİYOR.
		 *
		 * Operatör er ya da geç sırrı kullanıcı adı kutusuna yapıştırır.
		 * O değeri denetim kaydına yazmak, tam da hiçbir yerde
		 * saklamamaya çalıştığımız şeyi kalıcı bir tabloya düz metin
		 * olarak koymak olurdu. Bilinen bir hesabın adı yazılıyor,
		 * bilinmeyen bir şey yazılmıyor.
		 */
		entity := "unknown account"
		if err == nil {
			entity = in.Username
		}
		log.Warn("local login refused", "account_known", err == nil)
		if aerr := s.store.LogAdmin(r.Context(), store.AdminLogEntry{
			Actor: "anonymous", Via: "local", Action: "auth.local_denied", Entity: entity,
			Details: "wrong or malformed secret",
		}); aerr != nil {
			log.Error("audit write failed", "error", aerr)
		}
		writeErr(w, http.StatusUnauthorized, "wrong username or secret")
		return
	}

	u, err := s.store.User(r.Context(), in.Username)
	if err != nil {
		log.Error("local login user load failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "sign-in failed")
		return
	}

	token, err := s.webSessions.Create(u.Name)
	if err != nil {
		log.Error("web session create failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "sign-in failed")
		return
	}

	// #nosec G124 -- Secure koşullu: bkz. Server.SetExternalURL
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.secureCookies || r.TLS != nil,
	})

	if terr := s.store.TouchLocalCredential(r.Context(), u.Name, time.Now()); terr != nil {
		// Kullanım damgası bir teşhis bilgisi; yazılamaması kimliği
		// doğrulanmış bir kullanıcıyı dışarıda bırakmak için sebep değil.
		log.Error("local credential touch failed", "error", terr)
	}
	if aerr := s.store.LogAdmin(r.Context(), store.AdminLogEntry{
		Actor: u.Name, Via: "local", Action: "auth.local_login", Entity: u.Name,
		Details: "signed in with the local secret",
	}); aerr != nil {
		log.Error("audit write failed", "error", aerr)
	}

	log.Info("local login", "user", u.Name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

/*
 * decoyVerifier, olmayan hesaplar için kullanılan doğrulayıcı.
 *
 * ⚠️ ELLE YAZILMIYOR, ÜRETİLİYOR. Elle yazılmış bir sabitin bir
 * karakteri bozuk olsaydı VerifyLocalSecret onu ayrıştıramayıp ERKEN
 * dönerdi — argon2 hiç çalışmaz, yanıt gözle görülür biçimde hızlanır
 * ve "bu kullanıcı yok" bilgisi tam da gizlemeye çalıştığımız yerden
 * sızardı. Üretilmiş bir doğrulayıcı biçim olarak her zaman geçerli.
 *
 * Ürettiği sır atılıyor: hiçbir giriş buna uyamaz. Tek işi aynı
 * maliyeti ödetmek.
 *
 * rand okunamazsa panik: o durumda oturum belirteci de üretilemiyor,
 * yani süreç zaten hiçbir işe yaramaz.
 */
var decoyVerifier = sync.OnceValue(func() string {
	_, v, err := auth.NewLocalSecret()
	if err != nil {
		panic("httpapi: cannot generate decoy verifier: " + err.Error())
	}
	return v
})

/*
 * clientKey, hız sınırının anahtarı.
 *
 * ⚠️ YALNIZCA r.RemoteAddr. X-Forwarded-For OKUNMUYOR: onu okumak,
 * istemcinin kendi hız sınırı anahtarını seçmesine izin vermek olurdu
 * — her istekte farklı bir başlık yollayan saldırgan sınırı tamamen
 * atlar. Ters vekil arkasında bu değer vekilin adresine çöküyor ve
 * sınır küreselleşiyor; kabul edilen bir bedel, çünkü asıl koruma
 * localLoginSlots ve sırrın 128 bit olması.
 */
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
