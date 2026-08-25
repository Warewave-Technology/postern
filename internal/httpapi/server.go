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
)

// Server, HTTP uçlarını taşır. TLS/dinleme çağıranın işi (serve kuruyor);
// burada yalnızca yönlendirme ve handler'lar var.
type Server struct {
	oidc   *auth.OIDC
	logins *auth.Logins
	logger *slog.Logger
}

func New(o *auth.OIDC, logins *auth.Logins, logger *slog.Logger) *Server {
	return &Server{oidc: o, logins: logins, logger: logger}
}

// Handler, yönlendirme tablosu. Metod kısıtları desenin içinde ("GET /x"):
// yanlış metod otomatik 405 alır.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/callback", s.handleCallback)
	mux.HandleFunc("POST /auth/confirm", s.handleConfirm)
	return mux
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
		// Ayrıntı yok: hangi state'lerin canlı olduğu saldırgana bilgi.
		// Meşru yol buraya düşmez — link tek kullanımlık ve taze.
		log.Warn("oidc callback for unknown attempt")
		http.Error(w, "unknown or expired login attempt", http.StatusNotFound)
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
