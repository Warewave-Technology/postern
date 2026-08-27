// Package httpapi serves postern's web endpoints: the OIDC callback and
// login confirmation now (S3.3), the web terminal later (S4).
package httpapi

import (
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net/http"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/proxy"
	"github.com/warewave/postern/internal/store"
)

// Server, HTTP uçlarını taşır. TLS/dinleme çağıranın işi (serve kuruyor);
// burada yalnızca yönlendirme ve handler'lar var.
type Server struct {
	oidc   *auth.OIDC
	logins *auth.Logins
	logger *slog.Logger

	// S4.1: tarayıcı oturumları. store, /api uçlarının kimlik ve yetki
	// kaynağı — sshd ile AYNI veritabanı, aynı tek-kaynak sözleşmesi.
	store       *store.Store
	webSessions *auth.WebSessions
	webLogins   *webPending

	// S4.3: web terminali. proxyDeps nil ise terminal yapılandırılmamış
	// demektir ve rota HİÇ bağlanmaz — kapalı özellik, kapalı yüzey.
	proxyDeps   *proxy.Deps
	externalURL string
}

// EnableTerminal, web terminalini açar. serve yalnızca
// http.terminal_enabled true iken çağırır; çağrılmazsa /api/terminal
// rotası var olmaz (404), yalnızca yetkisiz olmaz.
func (s *Server) EnableTerminal(deps proxy.Deps, externalURL string) {
	s.proxyDeps = &deps
	s.externalURL = externalURL
}

func New(o *auth.OIDC, logins *auth.Logins, db *store.Store, logger *slog.Logger) *Server {
	return &Server{
		oidc:        o,
		logins:      logins,
		logger:      logger,
		store:       db,
		webSessions: auth.NewWebSessions(),
		webLogins:   &webPending{},
	}
}

// Handler, yönlendirme tablosu. Metod kısıtları desenin içinde ("GET /x"):
// yanlış metod otomatik 405 alır.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Kimlik akışları (oturumsuz erişilir).
	mux.HandleFunc("GET /auth/login", s.handleWebLogin)
	mux.HandleFunc("GET /auth/callback", s.handleCallback)
	mux.HandleFunc("POST /auth/confirm", s.handleConfirm)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)

	// API: oturum ister.
	mux.Handle("GET /api/me", s.requireSession(http.HandlerFunc(s.handleMe)))

	// Yönetim: oturum + admin + same-origin (admin.go).
	s.registerAdminRoutes(mux)

	// Terminal: yalnızca yapılandırıldıysa. Kapalıyken rota yok — açık
	// ama yetkisiz bir uç, kapalı bir uçtan daha büyük bir yüzeydir.
	if s.proxyDeps != nil {
		mux.Handle("GET /api/terminal/{target}", s.requireSession(http.HandlerFunc(s.handleTerminal)))
	}

	// Kalan her şey SPA: web/dist'ten statik dosyalar (S4.1 frontend).
	mux.Handle("/", spaHandler())

	return securityHeaders(mux)
}

// securityHeaders, her cevaba tarayıcı savunmalarını ekler.
//
// CSP buradaki en önemli satır ve web terminali tartışmasının doğrudan
// sonucu: script YALNIZCA kendi origin'imizden. Vite build'i harici
// script/inline script üretmiyor; bu başlık, SPA'ya sızacak bir XSS'in
// dışarıdan kod yükleyip oturumu silaha çevirmesini zorlaştıran kat.
// style-src'taki 'unsafe-inline' React'in style={{}} nitelikleri için.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// handleCallback, IdP'nin tarayıcıyı geri gönderdiği uç:
// /auth/callback?state=...&code=...
//
// Başarı, kimliği yalnızca PARK eder — teslim değil. Teslim, kullanıcının
// terminaldeki güvenlik kodunu yazmasına (handleConfirm) bağlı; bu ayrım
// "linki gören onaylayamaz, terminali gören onaylar" güvencesinin kendisi.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	log := s.logger.With("remote", r.RemoteAddr)

	q := r.URL.Query()

	// IdP redirect'i hata da taşıyabilir (kullanıcı girişten vazgeçti,
	// istemci kaydı bozuk...). code yokmuş gibi davranmak yerine açıkça
	// ele alıyoruz ki log gerçek sebebi görsün.
	if e := q.Get("error"); e != "" {
		log.Warn("oidc callback returned error", "idp_error", e)
		http.Error(w, "login failed", http.StatusForbidden)
		return
	}

	state, code := q.Get("state"), q.Get("code")
	if state == "" || code == "" {
		http.Error(w, "missing state or code", http.StatusBadRequest)
		return
	}

	req, ok := s.logins.Lookup(state)
	if !ok {
		// OOB kaydında yok: bu bir WEB login dönüşü olabilir — iki akış
		// aynı redirect URL'ini paylaşıyor, state hangi kayıttaysa akış
		// odur. Web kaydında da yoksa 404'ü o taraf verir.
		s.completeWebLogin(w, r, state, code)
		return
	}

	// Query'den gelen state'i AYNEN geçiyoruz; Exchange kendi sabit-zamanlı
	// karşılaştırmasını yapar. req.State'i iki kez geçmek kontrolü boşa
	// düşürürdü — CVE-2026-44347'nin kapısı tam orası.
	id, err := s.oidc.Exchange(r.Context(), req, state, code)
	if err != nil {
		log.Warn("oidc exchange failed", "error", err)
		http.Error(w, "login failed", http.StatusForbidden)
		return
	}

	if err := s.logins.Park(state, id); err != nil {
		// Deneme bu arada yandı ya da düştü (timeout, ikinci callback).
		log.Warn("oidc callback for finished attempt", "error", err)
		http.Error(w, "unknown or expired login attempt", http.StatusNotFound)
		return
	}

	// state kayıtlı bir denemenin base64url değeri — yine de kaçırıyoruz:
	// "bu değer güvenli" bilgisi bu satırın üç dosya ötesinde ve yarın
	// değişebilir; kaçırma ise bedava.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, confirmPageHTML, html.EscapeString(state))
}

// handleConfirm, kullanıcının güvenlik kodunu doğrulayan uç:
// form alanları state + code (terminaldeki UserCode).
func (s *Server) handleConfirm(w http.ResponseWriter, r *http.Request) {
	log := s.logger.With("remote", r.RemoteAddr)

	state, code := r.FormValue("state"), r.FormValue("code")
	if state == "" || code == "" {
		http.Error(w, "missing state or code", http.StatusBadRequest)
		return
	}

	if err := s.logins.Confirm(state, code); err != nil {
		// Yanlış kod ile bilinmeyen deneme aynı sayfayı görür (dışarıya
		// ayrım yok) ama log'da ayrışırlar: biri güvenlik olayı, diğeri
		// bayat bir sekme.
		if errors.Is(err, auth.ErrLoginDenied) {
			log.Warn("oob login rejected", "error", err)
		} else {
			log.Warn("oob confirm for unknown attempt", "error", err)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, deniedPageHTML)
		return
	}

	log.Info("oob login approved")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, okPageHTML)
}

// Sayfalar bilerek gösterişsiz: sunum öğrenme konusu değil. İçlerindeki
// %s yerleri fmt.Fprintf ile doldurulur.

const confirmPageHTML = `<!doctype html>
<meta charset="utf-8"><title>postern — confirm login</title>
<body style="font-family:system-ui;max-width:28rem;margin:4rem auto">
<h2>Almost there</h2>
<p>Type the security code shown in your terminal to approve this SSH login.</p>
<form method="post" action="/auth/confirm">
  <input type="hidden" name="state" value="%s">
  <input name="code" autofocus autocomplete="off" placeholder="ABCD-EFGH"
         style="font-size:1.4rem;letter-spacing:.2em;width:100%%">
  <button style="margin-top:1rem;font-size:1rem">Approve login</button>
</form>
`

const okPageHTML = `<!doctype html>
<meta charset="utf-8"><title>postern — approved</title>
<body style="font-family:system-ui;max-width:28rem;margin:4rem auto">
<h2>Login approved ✓</h2>
<p>You can return to your terminal.</p>
`

const deniedPageHTML = `<!doctype html>
<meta charset="utf-8"><title>postern — denied</title>
<body style="font-family:system-ui;max-width:28rem;margin:4rem auto">
<h2>Login denied</h2>
<p>The code did not match. This attempt is now void — start a new SSH
connection and try again.</p>
`
