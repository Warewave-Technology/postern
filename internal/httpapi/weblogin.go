package httpapi

// S4.1 — tarayıcı oturumu: OIDC ile web login, cookie, middleware.
//
// OOB (S3.3) ile AYNI IdP kaydını ve AYNI /auth/callback ucunu paylaşır;
// callback state'e bakarak hangi akışın döndüğünü ayırt eder.

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/warewave/postern/internal/auth"
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
	req, err := s.oidc.Begin()
	if err != nil {
		s.logger.Error("web login begin failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "login unavailable")
		return
	}
	s.webLogins.begin(req)
	http.Redirect(w, r, req.URL, http.StatusFound)
}

// completeWebLogin, callback'in WEB koluna düşen yarısı: handleCallback
// state'i OOB kaydında bulamayınca buraya gelir.
func (s *Server) completeWebLogin(w http.ResponseWriter, r *http.Request, state, code string) {
	log := s.logger.With("remote", r.RemoteAddr)

	req, ok := s.webLogins.take(state)
	if !ok {
		// OOB'dekiyle aynı ketumluk: hangi state'ler canlı, söyleme.
		log.Warn("web callback for unknown attempt")
		http.Error(w, "unknown or expired login attempt", http.StatusNotFound)
		return
	}

	// Query'den gelen state AYNEN geçiyor; Exchange kendi sabit-zamanlı
	// karşılaştırmasını yapar (OOB callback'teki CVE notu burada da geçerli).
	id, err := s.oidc.Exchange(r.Context(), req, state, code)
	if err != nil {
		log.Warn("web oidc exchange failed", "error", err)
		http.Error(w, "login failed", http.StatusForbidden)
		return
	}

	if id.Email == "" {
		log.Warn("web login without verified email")
		http.Error(w, "identity has no verified email", http.StatusForbidden)
		return
	}

	u, err := s.store.UserByEmail(r.Context(), id.Email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// "IdP'de hesap var" ≠ "postern'de hesap var" (OOB'deki kural).
			log.Warn("web login for unknown postern user")
			http.Error(w, "access denied", http.StatusForbidden)
			return
		}
		log.Error("web login user lookup failed", "error", err)
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}

	token, err := s.webSessions.Create(u.Name)
	if err != nil {
		log.Error("web session create failed", "error", err)
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})

	log.Info("web login", "user", u.Name)
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleLogout: POST /auth/logout — oturumu düşürür, cookie'yi geçersiz
// kılar. Cookie yoksa da başarılıdır: çifte logout hata değil.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.webSessions.Destroy(c.Value)
	}
	clearSessionCookie(w)
	// Form gönderimi tarayıcı navigasyonu: kullanıcıyı login ekranına döndür.
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
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
			clearSessionCookie(w)
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

	writeJSON(w, http.StatusOK, map[string]any{
		"name":    u.Name,
		"os_user": u.OSUser,
		"admin":   u.Admin,
		"targets": targets,
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

		username, err := s.webSessions.Resolve(c.Value)
		if err != nil {
			// Bayat cookie her istekte 401 üretmesin: temizle.
			clearSessionCookie(w)
			writeErr(w, http.StatusUnauthorized, "unauthenticated")
			return
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxUser, username)))
	})
}

// sessionUser, requireSession'ın context'e koyduğu adı geri okur.
// Middleware'siz çağrılırsa boş döner — bu bir programlama hatasıdır ve
// handler'ın hatayla düşmesi doğrudur, sessizce anonim davranması değil.
func sessionUser(r *http.Request) string {
	name, _ := r.Context().Value(ctxUser).(string)
	return name
}
