package httpapi

// S4.1 — tarayıcı oturumu: OIDC ile web login, cookie, middleware.
//
// OOB (S3.3) ile AYNI IdP kaydını ve AYNI /auth/callback ucunu paylaşır;
// callback state'e bakarak hangi akışın döndüğünü ayırt eder.

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/model"
	"github.com/warewave/postern/internal/store"
)

// sessionCookie, oturum token'ını taşıyan cookie'nin adı.
//
// Öznitelikler güvenliğin parçası (completeWebLogin kuruyor):
//   - HttpOnly: JS okuyamaz — XSS oturumu ÇALAMAZ (sekmeye hapsolur).
//   - SameSite=Lax: site-dışı POST'lar cookie taşımaz (CSRF birinci kat);
//     Strict değil, çünkü IdP'den dönen redirect de "başka site"den gelir
//     ve cookie o istekte de çalışmalı.
//   - Secure: istek TLS üzerinden geldiyse.
const sessionCookie = "postern_session"

// webPendingTTL: /auth/login'den callback'e dönüş için tanınan süre.
// IdP'de parola + MFA girecek bir insana bol; sonsuz büyüyen bir
// bekleyenler haritası bırakmayacak kadar kısa.
const webPendingTTL = 5 * time.Minute

// webPending, başlatılmış ama henüz dönmemiş web login denemeleri.
//
// Logins'in (OOB) küçük kardeşi: park yok, kod yok, Wait yok — bekleyen
// bir SSH tarafı olmadığı için yalnızca state→AuthRequest eşlemesi.
type webPending struct {
	mu      sync.Mutex
	byState map[string]pendingWebLogin
}

// maxWebPending, aynı anda bekleyebilecek web giriş denemesi.
//
// ⚠️ NEDEN VAR: GET /auth/login KİMLİK DOĞRULAMASIZ ve her çağrı
// haritaya bir kayıt ekliyordu. Sınırsız bir harita, bir isteğin bellek
// ayırmasına yol açan bir uç demek; üstelik her çağrı haritanın
// TAMAMINI kilit altında tarıyordu, yani maliyet kayıt sayısıyla
// karesel büyüyordu.
//
// Sınıra ulaşıldığında EN ESKİSİ düşürülüyor, yeni deneme reddedilmiyor:
// tersi, saldırganın haritayı doldurup meşru girişleri kapatması
// demek olurdu — kotayı bir DoS aracına çevirirdi.
const maxWebPending = 512

type pendingWebLogin struct {
	req       auth.AuthRequest
	expiresAt time.Time
}

func (p *webPending) begin(req auth.AuthRequest) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.byState == nil {
		p.byState = make(map[string]pendingWebLogin)
	}
	// Tembel temizlik (websession'daki desen): süresi geçmişleri yeni
	// kayıt açılırken süpür — login sıklığı süpürge sıklığı olarak yeter.
	now := time.Now()
	for state, pend := range p.byState {
		if now.After(pend.expiresAt) {
			delete(p.byState, state)
		}
	}

	// Süpürme yetmediyse (hepsi taze) EN ESKİSİNİ düşür.
	//
	// Reddetmek yerine düşürmek bilinçli: kimlik doğrulamasız bir uçta
	// kotayı reddetmeye bağlamak, saldırganın haritayı doldurup meşru
	// girişleri kapatmasına izin vermek olurdu. Düşürülen deneme
	// yalnızca yarım kalmış bir giriş; sahibi yeniden başlatabilir.
	for len(p.byState) >= maxWebPending {
		var oldestState string
		var oldest time.Time
		for state, pend := range p.byState {
			if oldestState == "" || pend.expiresAt.Before(oldest) {
				oldestState, oldest = state, pend.expiresAt
			}
		}
		delete(p.byState, oldestState)
	}

	p.byState[req.State] = pendingWebLogin{req: req, expiresAt: now.Add(webPendingTTL)}
}

// take, state'e ait AuthRequest'i döner ve kaydı DÜŞÜRÜR — tek kullanım:
// aynı callback'in ikinci oynatılışı ikinci bir oturum üretemez.
func (p *webPending) take(state string) (auth.AuthRequest, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	pend, ok := p.byState[state]
	if !ok {
		return auth.AuthRequest{}, false
	}
	delete(p.byState, state)
	if time.Now().After(pend.expiresAt) {
		return auth.AuthRequest{}, false
	}
	return pend.req, true
}

// handleWebLogin, tarayıcıyı IdP'ye yollar: GET /auth/login.
// Login sayfası diye bir şey yok — giriş IdP'nin işi, bizimki yönlendirmek.
func (s *Server) handleWebLogin(w http.ResponseWriter, r *http.Request) {
	/*
	 * ⚠️ YAPILANDIRILMIŞ OLMAK, AÇIK OLMAK DEĞİL.
	 *
	 * Rota yalnızca OIDC yapılandırıldıysa kuruluyor; ama aktif kaynak
	 * başkasıysa bu kapı KAPALI olmalı. Aksi hâlde "yerel kapıya
	 * geçtim" diyen bir kurulumda IdP kapısı sessizce açık kalırdı —
	 * kapattığını sanan operatörün göremeyeceği bir yol.
	 */
	if src, ok := s.sourceOrRefuse(w, r); !ok {
		return
	} else if src != auth.SourceOIDC {
		s.logger.Warn("oidc login attempted while another source is active",
			"active", src)
		writeErr(w, http.StatusNotFound, "not found")
		return
	}

	client, gen := s.oidc.Current()
	if client == nil {
		// Yapılandırma var ama çalışan istemci yok (sağlayıcı
		// ulaşılamıyor ya da ayarlar bozuk). "Kapalı" ile
		// "şu an çalışmıyor" ayrı şeyler ve log ikisini ayırıyor.
		s.logger.Error("oidc login attempted with no live provider",
			"configured", s.oidc.Configured())
		writeErr(w, http.StatusServiceUnavailable,
			"the identity provider is not reachable right now")
		return
	}

	req, err := client.Begin()
	if err != nil {
		s.logger.Error("web login begin failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "login unavailable")
		return
	}
	/*
	 * ⚠️ AKIŞI ÜRETEN KUŞAKLA DAMGALA.
	 *
	 * Damgalanmazsa tamamlanma kontrolü sıfırla karşılaştırır ve HER
	 * giriş reddedilir. (OOB kolunda damga auth.Logins.Start'ta
	 * konuyordu; web kolunda unutulmuştu ve bütün panel girişlerini
	 * kırdı — entegrasyon testleri yakaladı.)
	 */
	req.Gen = gen
	s.webLogins.begin(req)

	// ⚠️ STATE'İ BAŞLATAN TARAYICIYA BAĞLA.
	//
	// Kapatılan açık (giriş CSRF / oturum sabitleme): saldırgan
	// /auth/login çağırıp kendi state'ini alıyor, sonra kurbanın
	// tarayıcısını o state ile callback'e sürüklüyordu. Kurban
	// SALDIRGANIN kimliğiyle oturum açmış oluyor ve bundan sonra
	// yaptığı her şey saldırganın hesabına yazılıyordu — bir bastion
	// panelinde bu, kurbanın işlemlerinin denetim kaydında yanlış
	// kişiye atfedilmesi demek.
	//
	// SameSite=Lax bilinçli: IdP'den geri dönüş üst düzey bir
	// gezinmedir ve Strict çerezi orada göndermez, yani giriş hiç
	// çalışmazdı.
	// #nosec G124 -- Secure koşullu: bkz. Server.SetExternalURL
	http.SetCookie(w, &http.Cookie{
		Name:     loginStateCookie,
		Value:    req.State,
		Path:     "/auth/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.secureCookies,
		MaxAge:   int(webPendingTTL / time.Second),
	})

	http.Redirect(w, r, req.URL, http.StatusFound)
}

// loginStateCookie, web giriş akışının state'ini tarayıcıya bağlayan
// çerez.
const loginStateCookie = "postern_login"

// clearLoginStateCookie, tek kullanımlık state çerezini düşürür.
func (s *Server) clearLoginStateCookie(w http.ResponseWriter) {
	// #nosec G124 -- Secure koşullu: bkz. Server.SetExternalURL
	http.SetCookie(w, &http.Cookie{
		Name: loginStateCookie, Value: "", Path: "/auth/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.secureCookies,
	})
}

// completeWebLogin, callback'in WEB koluna düşen yarısı: handleCallback
// state'i OOB kaydında bulamayınca buraya gelir.
func (s *Server) completeWebLogin(w http.ResponseWriter, r *http.Request, state, code string) {
	log := s.logger.With("remote", r.RemoteAddr)

	/*
	 * ⚠️ AÇILIŞTA DEĞİL, TESLİMDE DE KONTROL.
	 *
	 * handleWebLogin kapıyı zaten kapatıyor; ama akış başladıktan sonra
	 * kaynak değişmiş olabilir ve o an havada olan bir akış, kapanmış
	 * bir kapıdan oturum teslim ederdi. Kapatma ile yürürlüğe girmesi
	 * arasında bir pencere bırakmıyoruz.
	 *
	 * ⚠️ Bu kontrol OOB (SSH) koluna GİRMİYOR ve girmemeli: orası
	 * panelin değil, SSH'ın kapısı. Panel kaynağını değiştirmenin
	 * kimsenin sunucu erişimini kesmemesi, ayarın açıkça sınırı.
	 */
	if src, ok := s.sourceOrRefuse(w, r); !ok {
		return
	} else if src != auth.SourceOIDC {
		log.Warn("web callback arrived after the source changed", "active", src)
		s.clearLoginStateCookie(w)
		http.Error(w, "the sign-in method changed while you were signing in; start again",
			http.StatusForbidden)
		return
	}

	// ⚠️ Bu akışı BAŞLATAN tarayıcı mı geri döndü?
	//
	// OOB akışında böyle bir kontrol YOK ve olmamalı: orada tarayıcının
	// akışı başlatmamış olması tasarımın kendisi. Web akışında ise
	// başlatan ile dönen aynı tarayıcı olmalı.
	c, cerr := r.Cookie(loginStateCookie)
	if cerr != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(state)) != 1 {
		log.Warn("web callback state does not match the browser that started it")
		s.clearLoginStateCookie(w)
		http.Error(w, "login session mismatch; start again", http.StatusForbidden)
		return
	}
	s.clearLoginStateCookie(w)

	req, ok := s.webLogins.take(state)
	if !ok {
		// OOB'dekiyle aynı ketumluk: hangi state'ler canlı, söyleme.
		log.Warn("web callback for unknown attempt")
		http.Error(w, "unknown or expired login attempt", http.StatusNotFound)
		return
	}

	// Query'den gelen state AYNEN geçiyor; Exchange kendi sabit-zamanlı
	// karşılaştırmasını yapar (OOB callback'teki CVE notu burada da geçerli).
	/*
	 * ⚠️ Bkz. OOB kolundaki aynı not: akış, kendisini başlatan kuşakla
	 * tamamlanmak zorunda — yoksa A'nın ürettiği code B'nin token
	 * ucuna gider.
	 */
	client, gen := s.oidc.Current()
	if client == nil || gen != req.Gen {
		log.Warn("web callback arrived after the provider changed",
			"started_gen", req.Gen, "current_gen", gen)
		s.clearLoginStateCookie(w)
		http.Error(w, "the identity provider configuration changed while you were "+
			"signing in; start again", http.StatusForbidden)
		return
	}

	id, err := client.Exchange(r.Context(), req, state, code)
	if err != nil {
		log.Warn("web oidc exchange failed", "error", err)
		http.Error(w, "login failed", http.StatusForbidden)
		return
	}

	u, err := s.resolveIdentity(r.Context(), log, id)
	if err != nil {
		if errors.Is(err, store.ErrAccessDenied) || errors.Is(err, store.ErrNotFound) {
			http.Error(w, "access denied", http.StatusForbidden)
			return
		}
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}

	token, err := s.webSessions.Create(u.Name)
	if err != nil {
		log.Error("web session create failed", "error", err)
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}

	// #nosec G124 -- Secure koşullu: bkz. Server.SetExternalURL
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		// Secure, dış adresin şemasından geliyor; r.TLS ters vekil
		// arkasında yalan söyler (bkz. Server.SetExternalURL).
		Secure: s.secureCookies || r.TLS != nil,
	})

	log.Info("web login", "user", u.Name)
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleLogout: POST /auth/logout — oturumu düşürür, cookie'yi geçersiz
// kılar. Cookie yoksa da başarılıdır: çifte logout hata değil.
/*
 * handleAuthMethods, yapılandırılmış giriş yollarını söyler.
 *
 * Oturumsuz erişilir ve öyle olmak ZORUNDA: giriş ekranı henüz bir
 * oturum yokken çizilecek. Sızdırdığı tek bilgi hangi kapıların açık
 * olduğu — kullanıcı adı, hesap varlığı ya da yapılandırma değeri
 * yok. Bu bilgi zaten giriş ekranının kendisinden görülüyor.
 */
func (s *Server) handleAuthMethods(w http.ResponseWriter, r *http.Request) {
	src, ok := s.sourceOrRefuse(w, r)
	if !ok {
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		/*
		 * ⚠️ ARTIK "YAPILANDIRILDI MI" DEĞİL, "AÇIK MI".
		 *
		 * Eskiden bu alanlar yapılandırmayı söylüyordu ve aynı anda
		 * ikisi birden true olabiliyordu. Aktif kaynak tek olduğuna
		 * göre giriş ekranı da tek kapı göstermeli: kapalı bir kapının
		 * düğmesini çizmek, kullanıcıyı çalışmayacak bir yola sokar.
		 */
		"source": string(src),
		"oidc":   src == auth.SourceOIDC && s.oidc.Live(),
		/*
		 * ⚠️ BU ALAN YAPILANDIRMAYI SÖYLER, VERİTABANINI DEĞİL.
		 *
		 * "Yerel bir yönetici VAR mı" sorusunun cevabı buradan
		 * verilemez: kimliği doğrulanmamış herkese kurulumda bir acil
		 * durum hesabı bulunduğunu söylemek olurdu. Kapının açık olup
		 * olmadığı ise dağıtımın kendi kararı ve zaten giriş
		 * ekranından görülüyor.
		 *
		 * Yanlış sır, hesap olsa da olmasa da AYNI cevabı alıyor
		 * (bkz. locallogin.go), dolayısıyla formu her zaman göstermek
		 * hiçbir şey sızdırmıyor.
		 */
		"local": src == auth.SourceLocal,

		// Dizin kapısı da kullanıcı adı + parola kutusu gösteriyor ama
		// istenen parola KURUMSAL parola. Ekranın bunu ayırt edebilmesi
		// gerekiyor: aynı forma bambaşka bir sır yazdırmak, sırların
		// yanlış yere girilmesinin en kısa yolu.
		"ldap": src == auth.SourceLDAP,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.webSessions.Destroy(c.Value)
	}
	s.clearSessionCookie(w)
	// Form gönderimi tarayıcı navigasyonu: kullanıcıyı login ekranına döndür.
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	// Silme çerezi de kurulum çerezinin özniteliklerini taşımalı:
	// tarayıcılar Secure'lu bir çerezi Secure'suz bir Set-Cookie ile
	// güvenilir biçimde silmez.
	// #nosec G124 -- Secure koşullu: dış adres http:// ise (localhost kurulumu) çerez Secure olamaz, yoksa hiç gönderilmez
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: s.secureCookies,
	})
}

// handleMe: GET /api/me — oturum sahibinin kimliği ve erişebildiği
// hedefler. Frontend'in ilk sorusu; şekil web/src/api.ts ile sözleşme.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u, err := s.store.User(r.Context(), sessionUser(r))
	if err != nil {
		// Oturum var ama kullanıcı yok: oturum açıkken silinmiş. Oturumu
		// da düşür — sahipsiz token'ın yaşamaya devam etmesi için sebep yok.
		if errors.Is(err, store.ErrNotFound) {
			s.clearSessionCookie(w)
			writeErr(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		s.logger.Error("me lookup failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Rollerdeki hedefler tekilleştirilip sıralanır: iki rol aynı hedefi
	// verebilir, kullanıcıya "hangi kapılar açık" listesi lazım.
	set := map[string]struct{}{}
	for _, role := range u.Roles {
		for _, t := range role.Targets {
			set[t] = struct{}{}
		}
	}
	targets := make([]string, 0, len(set))
	for t := range set {
		targets = append(targets, t)
	}
	sort.Strings(targets)

	/*
	 * ⚠️ KISIT VE POLİTİKA BURADAN GİDİYOR.
	 *
	 * Zorunlu değişiklik ekranını çizen oturum KISITLI: yalnızca bu uca
	 * ve parola ucuna ulaşabiliyor. Politikayı ayarlar ucundan okumak
	 * (yönetici gerektiriyor) onun için imkânsız. Kuralı ekrana ikinci
	 * kez YAZMAK ise bir güvenlik kontrolünün ikinci kopyası olurdu ve
	 * iki kopyadan biri er ya da geç geride kalır. Tek kaynak sunucu,
	 * ve bu uç zaten açık.
	 */
	mustChange := false
	hasLocal := false
	if cred, cerr := s.store.LocalCredential(r.Context(), u.Name); cerr == nil {
		mustChange = cred.MustChange
		hasLocal = true
	}
	policy := auth.LoadPasswordPolicy(r.Context(), s.store)

	/*
	 * canChangePassword, profil sayfasının parola kartını çizip
	 * çizmeyeceği.
	 *
	 * ⚠️ İKİ AYRI SEBEPLE HAYIR OLABİLİR ve ikisi de sunucuda ZATEN
	 * uygulanıyor — bu bayrak yeni bir kural değil, var olan iki
	 * kuralın ekrana söylenmesi:
	 *
	 *   - postern'de değeri olmayan hesap (dizin/kimlik sağlayıcı):
	 *     parolası ORADA yaşıyor, uç 409 dönüyor (password.go).
	 *   - yönetici: kimlik bilgisi bir acil çıkış sırrı ve yalnızca
	 *     host'ta üretiliyor; seçilmiş parolaya çevrilmesini göç
	 *     026'daki kısıt reddediyor (store.SetChosenPassword).
	 *
	 * Bayrak olmasaydı panel iki durumda da bir form çizer, kullanıcı
	 * doldurur ve hata alırdı — özelliğin BOZUK mu yoksa KENDİSİNE
	 * KAPALI mı olduğunu ayırt edemeden.
	 */
	canChangePassword := hasLocal && !u.Admin

	// Kısıtlıyken hedef listesi GÖNDERİLMİYOR: kişi henüz hiçbir şey
	// yapamıyor ve envanter, ekranın işine yaramayan bir bilgi.
	if mustChange {
		targets = []string{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"name":    u.Name,
		"os_user": u.OSUser,
		"admin":   u.Admin,
		"targets": targets,

		// Panel bunu görürse yalnızca parola ekranını çiziyor. Asıl
		// koruma uçta (requireSession): ekranın doğru çizilmesine
		// güvenerek açık bırakılan bir kapı, kapalı değildir.
		"must_change_password": mustChange,
		"password_policy":      policy,

		// Profil sayfası parola kartını buna göre çiziyor (gerekçe
		// yukarıda). Asıl koruma uçta ve veritabanı kısıtında.
		"can_change_password": canChangePassword,

		// Terminal rotası yalnızca EnableTerminal çağrıldıysa var.
		// Panel bunu bilmezse kapanmamış bir kapı sunar: düğmeye basan
		// kullanıcı 404 alır ve ekranda "[disconnected]" görür — yani
		// olmayan bir özelliğin bozuk olduğunu sanır.
		"terminal_enabled": s.proxyDeps != nil,
		// Panel anahtar yönetimini buna göre çiziyor. Asıl koruma uçta.
		"public_key_login": s.publicKeyLogin,

		/*
		 * ssh_host/ssh_port: panelin kopyalattığı komutun adresi.
		 *
		 * ⚠️ Yetki DEĞİL, gösterim. Boş host, "adresi bilmiyoruz"
		 * demek ve panel o zaman kopyalama seçeneğini hiç çizmiyor:
		 * yapıştırıldığında çalışmayacak bir komut, hiç komut
		 * olmamasından kötü.
		 */
		"ssh_host": s.sshHost,
		"ssh_port": s.sshPort,

		/*
		 * Hesap bir DİZİN kimliğine bağlı mı.
		 *
		 * Kurulum sihirbazı buna bakıyor: kaynağı dizine çevirmeden önce
		 * kendi kimliğini bağlamış olmak gerekiyor, ama ZATEN bağlı olan
		 * yöneticiye "önce bağla" demek onu ilerleyemeyeceği bir duvara
		 * dayardı — bağlama ucu haklı olarak çatışma döner.
		 */
		"dir_bound": u.DirBound,

		/*
		 * ⚠️ KURULUM YAPILMADIYSA PANEL SADECE SİHİRBAZDAN İBARET.
		 *
		 * İsteğe bağlı bir ekran olarak bırakıldığında atlanıyordu ve
		 * geriye kaynağı seçilmemiş — kapısı config dosyasından
		 * TÜRETİLEN — bir kurulum kalıyordu. Ürünün en kritik kararı,
		 * keşfedilmeyi bekleyen bir menü maddesi olamaz.
		 */
		"setup_required": !auth.SetupCompleted(r.Context(), s.store),
	})
}

// ctxKey, context değerleri için paket-özel anahtar tipi.
type ctxKey int

const ctxUser ctxKey = 0

// requireSession, oturum isteyen uçları saran middleware: cookie →
// kullanıcı adı → context. 401 gövdesi JSON — SPA yakalayıp login'e
// yönlendirecek, HTML hata sayfası API'de gürültü.
func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthenticated")
			return
		}

		username, viaLocal, err := s.webSessions.ResolveSession(c.Value)
		if err != nil {
			// Bayat cookie her istekte 401 üretmesin: temizle.
			s.clearSessionCookie(w)
			writeErr(w, http.StatusUnauthorized, "unauthenticated")
			return
		}

		if viaLocal && !s.passwordChangeDone(w, r, username, c.Value) {
			return
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxUser, username)))
	})
}

/*
 * changePasswordAllowed, ZORUNLU PAROLA DEĞİŞİKLİĞİ sırasında açık
 * kalan uçlar.
 *
 * ⚠️ TAM DESEN EŞLEŞMESİ, ÖNEK DEĞİL — ve bu, bu dosyadaki en kolay
 * gözden kaçacak güvenlik kararı.
 *
 * "/api/me ile başlayan her şey serbest" demek şunu açardı:
 * POST /api/me/keys de o önekin altında ve o uç, hesabın İLK anahtarını
 * hiçbir kimlik doğrulaması istemeden ekliyor (kural ve gerekçesi
 * mykeys.go'da: ilk anahtar bedava). Yani "parolanı değiştirene kadar
 * hiçbir şey yapamazsın" kısıtı, tam olarak kalıcı SSH erişimi
 * kurmanın önündeki tek engeli kaldırırdı. Bir öneki gevşetmek, bir
 * kapıyı gevşetmez — o önekin altına ileride eklenecek HER kapıyı
 * gevşetir.
 *
 * r.Pattern kullanılıyor, r.URL.Path değil: yönlendiricinin gerçekten
 * seçtiği rota bu ve yol normalizasyonuyla oynanamaz.
 *
 * ⚠️ KAPSAM PANELDİR, SSH DEĞİL — ve bu bir eksik değil, bir karar.
 * SSH bu oturumlardan hiç geçmiyor: kimlik orada bir AÇIK ANAHTARLA
 * kanıtlanıyor ve yerel parolanın o kapıda hiçbir rolü yok. Zaten
 * varolan anahtarını, panel parolası yüzünden çalışmaz hâle getirmek,
 * kimsenin istemediği bir kesinti olurdu. Kapatılan şey YENİ anahtar
 * EKLEMEK — yani kalıcılık kurmak — ve o kontrol hem burada hem
 * mykeys.go'da duruyor.
 */
var changePasswordAllowed = map[string]bool{
	// Panelin kim olduğunu ve kuralın ne olduğunu öğrenmesi için.
	"GET /api/me": true,
	// Kısıttan çıkışın TEK yolu.
	"POST /api/me/password": true,
}

/*
 * passwordChangeDone, oturumun kısıtlı olup olmadığını karara bağlar.
 * false dönerse cevap YAZILMIŞTIR ve çağıran hemen dönmelidir.
 *
 * ⚠️ KARAR HER İSTEKTE VERİTABANINDAN OKUNUYOR, oturuma damgalanmıyor.
 * websession.go'nun başındaki kuralın aynısı: oturuma damgalanan yetki,
 * değiştiği an görünmez olur. İki yönde de somut:
 *   - Kişi parolasını değiştirir ve kısıt HEMEN kalkmalı; damgalanmış
 *     olsaydı 12 saat daha ekranda kalırdı.
 *   - Yönetici bir hesaba "değiştirmek zorunda" der ve o kişinin AÇIK
 *     oturumu da hemen kısıtlanmalı; damga yalnızca yeni oturumları
 *     etkilerdi.
 *
 * ⚠️ VARSAYILAN RET. Kimlik bilgisi satırı okunamıyorsa ya da hiç yoksa
 * oturum düşüyor. Sebebi ölçülmüş bir açık: sırrı İPTAL EDİLEN kişinin
 * (`postern admin revoke`) satırı kalkıyor; "satır yok → kısıt yok"
 * deseydik, iptal etmek kısıtı KALDIRIRDI ve oturum tam yetkiyle
 * devam ederdi. İptal, oturumu bitirmeli.
 */
func (s *Server) passwordChangeDone(w http.ResponseWriter, r *http.Request,
	username, token string) bool {

	cred, err := s.store.LocalCredential(r.Context(), username)
	if err != nil {
		// Satır yok (iptal edildi) ya da okunamadı: oturum biter.
		// Yönü güvenli olan taraf bu.
		if !errors.Is(err, store.ErrNotFound) {
			s.logger.Error("credential check failed", "user", username, "error", err)
		}
		s.webSessions.Destroy(token)
		s.clearSessionCookie(w)
		writeErr(w, http.StatusUnauthorized, "unauthenticated")
		return false
	}
	if !cred.MustChange {
		return true
	}
	if changePasswordAllowed[r.Pattern] {
		return true
	}

	// 403, 401 değil: kim olduğunu biliyoruz ve oturum geçerli. 401
	// olsaydı panel kişiyi giriş ekranına atardı ve kişi sonsuz bir
	// döngüye girerdi — gireceği yer zaten bu ekran.
	writeErr(w, http.StatusForbidden,
		"set a new password before using the panel")
	return false
}

// sessionUser, requireSession'ın context'e koyduğu adı geri okur.
// Middleware'siz çağrılırsa boş döner — bu bir programlama hatasıdır ve
// handler'ın hatayla düşmesi doğrudur, sessizce anonim davranması değil.
func sessionUser(r *http.Request) string {
	name, _ := r.Context().Value(ctxUser).(string)
	return name
}

// resolveIdentity, doğrulanmış OIDC kimliğini postern kullanıcısına
// çevirir — gerekirse JIT olarak oluşturarak.
//
// SIRA ÖNEMLİ:
//
//  1. Kullanıcı adı varsa JIT sağlama denenir (ProvisionUser): grupları
//     rollere eşlenir, kullanıcı yoksa oluşturulur, SSO rolleri her
//     girişte yenilenir.
//  2. Kullanıcı adı yoksa (IdP preferred_username vermiyorsa) eski yola
//     düşülür: doğrulanmış e-postayla eşleştirme. Bu, JIT'ten önce elle
//     oluşturulmuş kullanıcıların çalışmaya devam etmesini sağlar.
//
// İkisi de başarısızsa erişim yok — ve sebep log'da ayrışır.
func (s *Server) resolveIdentity(ctx context.Context, log *slog.Logger, id auth.Identity) (model.User, error) {
	if id.Username != "" {
		// Gruplar kaynaktan: OIDC claim'i ya da LDAP. Kaynak arayüzün
		// arkasında olduğu için buradaki kod hangisini kullandığını
		// bilmiyor — LDAP eklendiğinde bu satır değişmedi.
		res, err := s.groups.Groups(ctx, id)
		if err != nil {
			// Dizin arızası yetki YOKLUĞU değildir: kullanıcıyı sessizce
			// yetkisiz bırakmak yerine girişi reddediyoruz. Aksi halde
			// LDAP çöktüğünde herkes "hiçbir hedefe erişimin yok"
			// mesajıyla karşılaşır ve sorun günlerce fark edilmez.
			log.Error("group lookup failed", "idp_user", id.Username, "error", err)
			return model.User{}, err
		}

		// ⚠️ Bkz. sshd tarafındaki aynı not: "bulamadım" yetki kararı
		// değildir ve roller o hâlde tazelenmez.
		if res.Presence != auth.GroupsPresent {
			log.Warn("directory did not resolve this user; roles left untouched",
				"idp_user", id.Username, "presence", res.Presence.String())
		}

		/*
		 * Gelen kimliğin KENDİSİ yönetici grubunda mı?
		 *
		 * ⚠️ YALNIZCA gruplar gerçekten çözüldüyse: "cevap veremedim"
		 * hâlinde false kalıyor, yani kapı KAPALI tarafta. Bir dizin
		 * arızasının yönetici hesabı devralmayı açması olmaz.
		 */
		adminMember := false
		if res.Presence == auth.GroupsPresent {
			var aerr error
			adminMember, aerr = auth.InAdminGroup(ctx, s.store, res.Groups)
			if aerr != nil {
				log.Error("admin group lookup failed", "error", aerr)
				return model.User{}, aerr
			}
		}

		u, err := s.store.ProvisionUser(ctx, store.ProvisionRequest{
			Username:       id.Username,
			Email:          id.Email,
			Groups:         res.Groups,
			GroupsResolved: res.Presence == auth.GroupsPresent,
			Issuer:         id.Issuer,
			Subject:        id.Subject,
			// Gelen kimliğin KENDİSİ yönetici grubunda mı (bkz.
			// ProvisionRequest.AdminGroupMember). Yalnızca gruplar
			// gerçekten çözüldüyse sorulabilir.
			AdminGroupMember: adminMember,
			// ⚠️ Kapalıysa hesap açılmıyor; kişi kuyruğa yazılıyor
			// (aşağıdaki ErrAccountNotProvisioned dalı).
			AutoCreate: auth.AutoCreateEnabled(ctx, s.store),
		})
		switch {
		case err == nil:
			/*
			 * ⚠️ Yönetici yetkisi de aynı kaynaktan. İKİ KAPI TEK
			 * KURAL: dizinle giren ile IdP ile giren aynı yoldan
			 * yönetici olmalı, yoksa "hangi kapıdan girdiğine göre
			 * yetkin değişir" gibi açıklanamaz bir davranış çıkar.
			 *
			 * YALNIZCA sağlama BAŞARILI olduğunda ve gruplar gerçekten
			 * çözüldüğünde: reddedilmiş bir kullanıcıya yetki
			 * uygulamak ya da bir dizin arızasında herkesin
			 * yöneticiliğini kaldırmak, ikisi de kabul edilemez.
			 */
			if res.Presence == auth.GroupsPresent {
				s.applyGroupAdmin(ctx, u.Name, res.Groups)
				if fresh, ferr := s.store.User(ctx, u.Name); ferr == nil {
					u = fresh
				}
			}
			// ⚠️ Silinmiş hesap girişle geri gelmez; pasif hesap gelir
			// — başarılı girişin kendisi kaynağın doğrulaması.
			if derr := s.store.RefuseIfDeleted(ctx, u.Name); derr != nil {
				log.Warn("login denied: account is deleted", "user", u.Name)
				return model.User{}, store.ErrAccessDenied
			}
			// ⚠️ Kaynak bu kişiyi ŞU AN doğruladı (bkz. göç 023).
			if cerr := s.store.ConfirmAccount(ctx, u.Name, time.Now()); cerr != nil {
				log.Error("confirm stamp failed", "user", u.Name, "error", cerr)
			}
			return u, nil
		case errors.Is(err, store.ErrAccountNotProvisioned):
			/*
			 * ⚠️ KAPI KAPANMIYOR, KUYRUĞA YAZILIYOR.
			 *
			 * Kimlik doğrulandı ama postern bu kişiyi tanımıyor ve
			 * hesapların kendiliğinden açılması kapalı. Kuyruk satırı
			 * KARARLI KİMLİKLE anahtarlı (göç 022): reddedilen kişi
			 * IdP'de adını değiştirip yeniden başvuramaz.
			 */
			st, perr := s.store.RecordPending(ctx, store.PendingUser{
				Subject: id.Subject, Source: "oidc", Username: id.Username,
				Email: id.Email, SeenGroups: res.Groups,
			})
			if perr != nil {
				log.Error("pending record failed", "error", perr)
				return model.User{}, perr
			}
			if st == store.PendingRejected {
				log.Warn("rejected identity tried again", "idp_user", id.Username)
			} else {
				log.Info("pending account recorded", "idp_user", id.Username)
			}
			return model.User{}, store.ErrAccessDenied
		case errors.Is(err, store.ErrAdminBindRefused):
			/*
			 * Adı bir YÖNETİCİ hesabıyla eşleşen, ilk kez görülen bir
			 * kimlik. Ayrı loglanıyor: meşru bir yöneticinin ilk girişi
			 * de buraya düşebilir ve onu "devralma denemesi" diye
			 * kaydetmek, gerçek denemeleri gürültüye gömerdi.
			 *
			 * ⚠️ Dönen hata yine ErrAccessDenied: yanıt kodunun
			 * farklılaşması, "bu kullanıcı adı postern'de bir yönetici"
			 * bilgisini kimliği doğrulanmamış birine sızdırırdı.
			 */
			log.Warn("login denied: this username belongs to an administrator account "+
				"and cannot be claimed by a first sign-in",
				"idp_user", id.Username, "idp_issuer", id.Issuer)
			return model.User{}, store.ErrAccessDenied
		case errors.Is(err, store.ErrIdentityConflict):
			// Kullanıcı adı var olan bir hesapla eşleşiyor ama o hesap
			// BAŞKA bir IdP kimliğine bağlı — yapılandırma eksiği değil,
			// incelenmesi gereken bir olay (kullanıcı adı geri dönüşümü
			// ya da devralma denemesi). Ayrı loglanıyor.
			//
			// ⚠️ DÖNEN HATA ErrAccessDenied OLMAK ZORUNDA: default dalına
			// düşseydi yanıt 403 yerine 500 olurdu ve bu fark tek başına
			// "bu kullanıcı adı postern'de var" bilgisini sızdırırdı.
			log.Warn("login denied: username belongs to an account bound to a different identity",
				"idp_user", id.Username, "idp_issuer", id.Issuer)
			return model.User{}, store.ErrAccessDenied
		case errors.Is(err, store.ErrAccessDenied):
			// Kimlik geçerli ama hiçbir grubu role eşleşmiyor. Bu bir
			// yapılandırma boşluğu olabilir: eşlenmemiş gruplar teşhis
			// tablosunda, yönetici panelden görecek.
			log.Warn("login denied",
				"idp_user", id.Username, "presence", res.Presence.String(),
				"reason", map[bool]string{
					true:  "no mapped directory groups",
					false: "directory could not resolve this user",
				}[res.Presence == auth.GroupsPresent])
			return model.User{}, err
		default:
			log.Error("provisioning failed", "idp_user", id.Username, "error", err)
			return model.User{}, err
		}
	}

	// preferred_username yoksa e-posta eşleştirmesine düş.
	if id.Email == "" {
		log.Warn("login denied: identity has neither username nor verified email")
		return model.User{}, store.ErrAccessDenied
	}

	/*
	 * ⚠️ E-POSTA YOLU DA KİMLİK BAĞINDAN GEÇMEK ZORUNDA.
	 *
	 * Buradaki hesap DOĞRUDAN döndürülüyordu: ne (issuer, subject)
	 * bağına bakılıyordu, ne yönetici korumasına. Yani kullanıcı adı
	 * yollamayan bir IdP'de, doğrulanmış e-postası bir hesabınkiyle
	 * eşleşen herhangi bir kimlik o hesaba giriyordu — 011'in ve
	 * 020'nin kapattığı iki kapının ikisi de aynı anda atlanıyordu.
	 * Bir yönetici hesabı da bu yolla devralınabiliyordu.
	 *
	 * Düzeltme ayrı bir kural yazmıyor: hesabı BULDUKTAN sonra aynı
	 * ProvisionUser'dan geçiriyor. Böylece bağ kontrolü, yönetici
	 * koruması ve TOFU denetim satırı tek yerde kalıyor — ikinci bir
	 * kopya, ikinci kez unutulacak bir kural demekti.
	 *
	 * ⚠️ Groups BİLEREK BOŞ ve GroupsResolved false: bu yola yalnızca
	 * kullanıcı adı yokken düşülüyor, yani kaynağa o kişi hakkında
	 * soru sorulamamış. Rollere dokunulmuyor.
	 */
	/*
	 * ⚠️ ProvisionUser DEĞİL: o, gruplar çözülemediğinde reddediyor —
	 * ve haklı, yeni bir hesap açıp açmamaya karar verecek bilgi yok.
	 * Ama burada hesap ZATEN VAR ve verilecek karar "bu kimlik bu
	 * hesabı alabilir mi". (İlk taslakta ProvisionUser çağrılmıştı ve
	 * e-posta yolunu HERKES için kapatıyordu; bir test yakaladı.)
	 */
	bound, berr := s.store.ClaimByVerifiedEmail(ctx, id.Email, id.Issuer, id.Subject, false)
	switch {
	case berr == nil:
		return bound, nil
	case errors.Is(berr, store.ErrNotFound):
		log.Warn("login denied: no postern user for verified email")
		return model.User{}, berr
	case errors.Is(berr, store.ErrAdminBindRefused):
		log.Warn("login denied: this email belongs to an administrator account " +
			"and cannot be claimed by a first sign-in")
		return model.User{}, store.ErrAccessDenied
	case errors.Is(berr, store.ErrIdentityConflict):
		log.Warn("login denied: that email belongs to an account bound to a " +
			"different identity")
		return model.User{}, store.ErrAccessDenied
	default:
		log.Error("email-matched claim failed", "error", berr)
		return model.User{}, berr
	}
}
