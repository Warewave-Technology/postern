package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Warewave-Technology/postern/internal/auth"
	"github.com/Warewave-Technology/postern/internal/store"
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
		// Code, hesabın DOĞRULANMIŞ bir ikinci faktörü varsa istenen
		// TOTP kodu. Aynı istekte gönderiliyor: iki adımlı bir akış,
		// aradaki durumu taşıyacak bir ara belirteç gerektirirdi ve o
		// belirteç, henüz ikinci faktörünü kanıtlamamış birinin elinde
		// duran bir şey olurdu.
		Code string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}

	/*
	 * ⚠️ KAYNAK, KAYNAĞA ÖZEL KAYNAKLARDAN ÖNCE.
	 *
	 * Hız sınırı ve yuvalar kaynağa göre AYRI: yerel yolda korunan şey
	 * postern'in belleği (argon2), dizin yolunda KURUMUN DİZİNİ. İkisini
	 * de burada almak, dizin girişinin hem kotayı iki kez tüketmesine
	 * (çağrılan taraf kendi kontrolünü yapıyor) hem de bir ağ bind'i
	 * boyunca argon2 yuvası tutmasına yol açıyordu — dört eşzamanlı
	 * dizin girişi, hiç argon2 çalışmadan yerel kapıyı meşgul ediyordu.
	 */
	src, ok := s.sourceOrRefuse(w, r)
	if !ok {
		return
	}

	/*
	 * ⚠️ KAYNAK SEÇİMİ ARTIK BİR TAHMİN DEĞİL, BİR AYAR.
	 *
	 * Eskiden burada bir if vardı: hesabın yerel kimlik bilgisi varsa
	 * yerel, yoksa dizin. Yani kaynağı, yazılan KULLANICI ADI
	 * belirliyordu — ve bu, kurumsal parolanın nereye gideceğini
	 * saldırganın seçebileceği anlamına geliyordu: postern'de yerel
	 * kaydı olmayan bir ad yazan herkes, bind yolunu açabiliyordu.
	 *
	 * Şimdi kaynak tek ve önceden belli. Yerel kapı açıkken hiçbir
	 * parola dizine gitmiyor; dizin kapısı açıkken hiçbir yerel
	 * doğrulayıcı denenmiyor.
	 */
	switch src {
	case auth.SourceLDAP:
		s.directoryLogin(w, r, log, in.Username, in.Secret)
		return
	case auth.SourceOIDC:
		/*
		 * ⚠️ BU FORM HİÇ ÇİZİLMEMELİYDİ (bkz. handleAuthMethods) ama
		 * uç yine de kapalı: arayüzün doğru çizilmesine güvenerek
		 * açık bırakılan bir kapı, kapalı değildir.
		 *
		 * Denemeler yine de sayılıyor: kapalı bir kapıya yapılan
		 * ısrarlı denemeler görülmeye değer.
		 */
		log.Warn("local sign-in attempted while the identity provider is the active source")
		writeErr(w, http.StatusForbidden,
			"password sign-in is closed; this postern signs in through its identity provider")
		return
	}

	if !s.localLimit.allow(s.clientKey(r)) {
		// 429: "yanlış sır" ile karıştırılmamalı, yoksa operatör
		// elindeki sırrın bozuk olduğunu sanır.
		w.Header().Set("Retry-After", "60")
		writeErr(w, http.StatusTooManyRequests, "too many sign-in attempts; try again in a minute")
		return
	}

	/*
	 * ⚠️ ARTAN GECİKME, ARGON2 YUVASINDAN ÖNCE.
	 *
	 * Sıra kritik: gecikme yuvayı aldıktan sonra uygulansaydı, dört
	 * bekleyen istek bütün kapıyı kapatırdı — savunma, saldırının aracı
	 * olurdu. Burada hiçbir yuva alınmadan, anında reddediyoruz.
	 *
	 * Anahtar (hesap, adres) çifti; NEDEN yalnızca hesap olmadığı
	 * backoff.go'da yazılı ve bu dosyanın "kilitleme YOK" kuralının
	 * ayakta kalmasının tek sebebi.
	 */
	bkey := backoffKey(in.Username, s.clientKey(r))
	if wait := s.guessBackoff.retryAfter(bkey); wait > 0 {
		secs := int(wait.Seconds()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		log.Warn("local login throttled", "seconds", secs)
		writeErr(w, http.StatusTooManyRequests, fmt.Sprintf(
			"too many failed attempts from here; try again in %d seconds", secs))
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

	cred, err := s.store.LocalCredential(r.Context(), in.Username)
	switch {
	case err == nil:
		// Yerel yol: aşağıda.
	case errors.Is(err, store.ErrNotFound):
		/*
		 * ⚠️ KULLANICI VARLIĞI SIZDIRILMIYOR.
		 *
		 * Hesap yoksa da doğrulama YAPILIYOR (üretilmiş bir sahte
		 * doğrulayıcıya karşı) ve dönen hata birebir aynı. Aksi hâlde
		 * yanıt süresi ve metni, "bu kullanıcı adı var" bilgisini
		 * kimliği doğrulanmamış herkese verirdi.
		 */
		/*
		 * ⚠️ SAHTE SATIR "PAROLA" OLARAK İŞARETLENİYOR.
		 *
		 * Aşağıdaki gecikme yalnızca parola tutan hesaplara uygulanıyor
		 * (gerekçe orada). Olmayan hesap "sır tutuyor" sayılsaydı,
		 * gecikmenin gelip gelmemesi doğrudan "bu kullanıcı adı var mı"
		 * sorusunu cevaplardı — decoy'un kapatmak için var olduğu
		 * kanalın ta kendisi, başka bir kapıdan.
		 */
		cred = store.Credential{Verifier: decoyVerifier(), Chosen: true}
	default:
		log.Error("local login lookup failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "sign-in failed")
		return
	}

	if !verifyCredential(cred, in.Secret) {
		/*
		 * ⚠️ GECİKME YALNIZCA PAROLA TUTAN HESAPLARA.
		 *
		 * Makine üretimi sır 128 bit; onu tahmin etmeye çalışan biri
		 * gecikmeden etkilenmez, ama gecikme ONA UYGULANIRSA bir şey
		 * kazanır: (hesap, adres) anahtarı ters vekil arkasında tek bir
		 * adrese çöküyor (clientKey'in kendi notu) ve o kurulumda
		 * anahtar fiilen yalnızca HESAP oluyor. Yani vekil arkasındaki
		 * bir yabancı, üst üste yanlış deneyerek acil durum
		 * yöneticisini panelden dışarıda tutabilirdi — localcred.go:30
		 * "kilitleme YOK" derken tam olarak bunu yasaklıyor.
		 *
		 * Sır tutan hesapları muaf tutmak o düğmeyi kırıyor ve hiçbir
		 * şey kaybettirmiyor: gecikmenin koruduğu şey tahmin edilebilir
		 * değerler, ve orada tahmin edilebilir bir değer yok.
		 *
		 * Sızan bilgi: "gecikme geldi" = parola ya da olmayan hesap,
		 * "gelmedi" = henüz değiştirilmemiş makine üretimi değer. İki
		 * sınıf da kalabalık; yönetici listesi vermiyor.
		 */
		if cred.Chosen {
			s.guessBackoff.fail(bkey)
		}
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

	/*
	 * ⚠️ SAYAÇ BURADA SIFIRLANMIYOR — İKİNCİ FAKTÖRDEN SONRA.
	 *
	 * Burada sıfırlıyordu ve ölçüldü: TOTP kontrolü aşağıda, ve spendTOTP
	 * AYNI anahtarı kullanıyor (backoffKey = ad + adres). Yani parolayı
	 * bilen biri için sıra şuydu — doğru parola sayacı SİLİYOR, yanlış kod
	 * sayacı 1 yapıyor, bir sonraki denemede doğru parola tekrar SİLİYOR.
	 * Sayaç hiçbir zaman 1'i geçmiyordu ve backoffSteps'in ilk üç adımı
	 * zaten sıfır olduğu için artan gecikme HİÇ devreye girmiyordu; geriye
	 * yalnızca dakikalık kota kalıyordu.
	 *
	 * Yani parolayı ele geçiren biri, altı haneyi gecikmesiz deniyordu —
	 * ikinci faktörün var olma sebebinin tam karşısı.
	 *
	 * Sıfırlama artık TAM başarıdan sonra: parola VE kod. Doğru parolayı
	 * bilen kişinin gecikmeyle karşılaşmaması kuralı korunuyor, çünkü kodu
	 * da doğru giren kişi sayacı yine siliyor.
	 */

	// ⚠️ Silinmiş hesap girişle geri gelmez (bkz. göç 023).
	if derr := s.store.RefuseIfDeleted(r.Context(), in.Username); derr != nil {
		log.Warn("local login denied: account is deleted", "user", in.Username)
		writeErr(w, http.StatusUnauthorized, "wrong username or secret")
		return
	}

	u, err := s.store.User(r.Context(), in.Username)
	if err != nil {
		log.Error("local login user load failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "sign-in failed")
		return
	}

	/*
	 * ⚠️ İKİNCİ FAKTÖR, OTURUM YARATILMADAN ÖNCE.
	 *
	 * Sıra bu işin tamamı. Önce oturumu açıp sonra kod sormak, kodu
	 * bilmeyen birinin elinde GEÇERLİ BİR OTURUM bırakırdı; o oturumun
	 * neye eriştiği artık başka kapıların dikkatine kalırdı ve tek bir
	 * unutulmuş uç yeter.
	 *
	 * ⚠️ YALNIZCA DOĞRULANMIŞ KAYIT KOD İSTİYOR. Kaydı olmayan ya da
	 * yarım bırakmış hesap girebiliyor — ve hemen ardından panel kapısına
	 * (weblogin.go, totpEnrolmentDone) çarpıp kaydını tamamlamak zorunda
	 * kalıyor. İkisi birlikte boşluk bırakmıyor: ya kayıtlısın ve kod
	 * veriyorsun, ya değilsin ve hiçbir şey yapamadan kaydoluyorsun.
	 * Burada kod ISRAR ETMEK, kaydolmamış kimsenin giremediği ve
	 * dolayısıyla kaydolamadığı bir kilit olurdu.
	 */
	switch c, terr := s.store.TOTP(r.Context(), u.Name); {
	case terr != nil && !errors.Is(terr, store.ErrNotFound):
		log.Error("totp lookup failed", "user", u.Name, "error", terr)
		writeErr(w, http.StatusInternalServerError, "sign-in failed")
		return
	case terr == nil && c.Confirmed:
		if in.Code == "" {
			/*
			 * ⚠️ 401 VE MAKİNE OKUNUR BİR İŞARET.
			 *
			 * Panelin kod kutusunu çizebilmesi için "parola yanlış" ile
			 * "kod eksik"i ayırt etmesi gerekiyor. Bilgi sızdırmıyor:
			 * buraya gelen taraf parolayı ZATEN kanıtladı.
			 *
			 * Deneme sayacına yazılmıyor — eksik kod bir tahmin değil.
			 * Yanlış kod ise spendTOTP'nin kovasına düşüyor.
			 */
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error":         "enter the code from your authenticator",
				"totp_required": true,
			})
			return
		}
		if !s.spendTOTP(w, r, u.Name, in.Code) {
			return
		}
	}

	// Parola VE (varsa) kod doğrulandı: sayaç ancak şimdi sıfırlanıyor.
	s.guessBackoff.succeed(bkey)

	// ⚠️ CreateLocal: oturumun kökeni yerel parola kapısı. Zorunlu
	// parola değişikliği kısıtı buna bakıyor (weblogin.go'daki gate).
	token, err := s.createLocalWebSession(r.Context(), u.Name)
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

	/*
	 * ⚠️ YEREL KAPI DA ONAY DAMGASI VURUYOR.
	 *
	 * Diğer iki kapı (dizin ve kimlik sağlayıcı) bunu zaten yapıyordu;
	 * burası unutulmuştu ve o gün zararsızdı: StaleAccounts yalnızca
	 * sso_only ya da dizine bağlı hesapları tarıyor, saf yerel hesaba
	 * hiç dokunmuyordu.
	 *
	 * Panelden parola verilen kurulumlarda bu artık doğru değil: yerel
	 * kapı ASIL kapı oluyor. Damga vurulmazsa, hesap yaşam döngüsü işi
	 * her gün giriş yapan insanları önce pasife, sonra silinmişe
	 * çeviriyor — ve sshd'nin "paneline bir kez gir, hesabın yeniden
	 * aktifleşir" mesajı yalan oluyor, çünkü giriş işe yarıyor ama
	 * hiçbir şeyi tazelemiyor.
	 */
	if cerr := s.store.ConfirmAccount(r.Context(), u.Name, time.Now()); cerr != nil {
		log.Error("account confirm failed", "user", u.Name, "error", cerr)
	}

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
 * verifyCredential, kimlik bilgisini TÜRÜNE GÖRE doğrular.
 *
 * ⚠️ TÜR SATIRDAN GELİYOR, GİRDİDEN DEĞİL. Girdinin biçimine bakıp
 * "base32 gibi duruyor, sır yolunu deneyeyim" demek, hangi kapının
 * açılacağını SALDIRGANIN seçmesine izin vermek olurdu: kurumsal
 * parolasını yazan kişiye parola yolunu, sırrı deneyene sır yolunu
 * açardı. Hangi yol açık olduğu veritabanındaki satırın işi.
 *
 * İKİ YOLU DA DENEMEK de yasak ve sebebi aynı: bir hesap için tek bir
 * doğru yol var, ikincisini denemek biçim kontrolünü baypas ederdi.
 *
 * Maliyet iki yolda da bir argon2 — gerekçesi her iki fonksiyonun
 * içinde yazılı.
 */
func verifyCredential(c store.Credential, input string) bool {
	if c.Chosen {
		return auth.VerifyPassword(c.Verifier, input)
	}
	return auth.VerifyLocalSecret(c.Verifier, input)
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
