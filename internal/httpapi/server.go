// Package httpapi serves postern's web endpoints: the OIDC callback and
// login confirmation now (S3.3), the web terminal later (S4).
package httpapi

import (
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"strings"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/events"
	"github.com/warewave/postern/internal/proxy"
	"github.com/warewave/postern/internal/record"
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

	// groups, kullanıcının grup üyeliklerini veren kaynak: OIDC claim'i
	// ya da LDAP dizini. New varsayılan olarak claim'i kurar; serve
	// LDAP yapılandırılmışsa UseGroupSource ile değiştirir.
	groups auth.GroupSource

	// groupSwitch, groups ile AYNI nesne (değiştirilebilir sarmalayıcı
	// verildiyse). Panelden ayar değişince kaynağı buradan çeviriyoruz —
	// sshd de aynı sarmalayıcıyı tuttuğu için iki kapı ayrışmıyor.
	groupSwitch *auth.SwitchableGroupSource

	// S4.3: web terminali. proxyDeps nil ise terminal yapılandırılmamış
	// demektir ve rota HİÇ bağlanmaz — kapalı özellik, kapalı yüzey.
	proxyDeps   *proxy.Deps
	externalURL string

	// records nil ise kayıt izleme yapılandırılmamış demektir ve
	// rotalar HİÇ kurulmaz — kapalı özellik, kapalı yüzey.
	records *record.Store

	// secureCookies, oturum çerezine Secure bayrağının konup
	// konmayacağı. SetExternalURL kuruyor.
	secureCookies bool

	// bus nil ise canlı olay akışı yapılandırılmamış demektir ve rota
	// HİÇ kurulmaz — kapalı özellik, kapalı yüzey. Panel bunu görüp
	// yoklamaya düşüyor.
	bus *events.Bus
}

// SetExternalURL, kullanıcının tarayıcısından görülen kök adresi verir.
//
// Çerezin Secure bayrağı BURADAN türetiliyor, r.TLS'ten değil: postern
// TLS'i sonlandıran bir ters vekilin arkasındaysa r.TLS nil olur ama
// bağlantı HTTPS'tir. r.TLS'e bakan kod o kurulumda oturum çerezini
// Secure'suz yazar — yani düz metin bir isteğe iliştirilebilir hâle
// getirir. Dış adresin şeması dağıtımın gerçeğini söyleyen tek kaynak.
func (s *Server) SetExternalURL(raw string) {
	s.externalURL = raw
	s.secureCookies = strings.HasPrefix(strings.ToLower(raw), "https://")
}

// UseGroupSource, grup kaynağını değiştirir (LDAP için).
//
// Dinlemeye başlamadan ÖNCE çağrılmalı: alan kilitsiz.
func (s *Server) UseGroupSource(src auth.GroupSource) {
	s.groups = src
	// Değiştirilebilir sarmalayıcıysa ayrıca sakla: ayar değişiminde
	// kaynağı çevirebilmek için.
	if sw, ok := src.(*auth.SwitchableGroupSource); ok {
		s.groupSwitch = sw
	}
}

// EnableTerminal, web terminalini açar. serve yalnızca
// http.terminal_enabled true iken çağırır; çağrılmazsa /api/terminal
// rotası var olmaz (404), yalnızca yetkisiz olmaz.
func (s *Server) EnableTerminal(deps proxy.Deps, externalURL string) {
	s.proxyDeps = &deps
	s.SetExternalURL(externalURL)
}

func New(o *auth.OIDC, logins *auth.Logins, db *store.Store, logger *slog.Logger) *Server {
	return &Server{
		oidc:        o,
		logins:      logins,
		logger:      logger,
		store:       db,
		webSessions: auth.NewWebSessions(),
		webLogins:   &webPending{},
		groups:      auth.ClaimGroups{},
	}
}

// Handler, yönlendirme tablosu. Metod kısıtları desenin içinde ("GET /x"):
// yanlış metod otomatik 405 alır.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Kimlik akışları (oturumsuz erişilir).
	mux.HandleFunc("GET /auth/login", s.handleWebLogin)
	mux.HandleFunc("GET /auth/callback", s.handleCallback)
	// Çıkış da same-origin: siteler arası bir POST kurbanı sessizce
	// oturumdan atıyordu. Etkisi düşük ama bedeli sıfır.
	mux.Handle("POST /auth/logout", s.sameOrigin(http.HandlerFunc(s.handleLogout)))

	// API: oturum ister.
	mux.Handle("GET /api/me", noStore(s.requireSession(http.HandlerFunc(s.handleMe))))

	// Yönetim: oturum + admin + same-origin (admin.go, federation.go).
	s.registerAdminRoutes(mux)
	s.registerFederationRoutes(mux)
	s.registerEventRoutes(mux)

	// Terminal: yalnızca yapılandırıldıysa. Kapalıyken rota yok — açık
	// ama yetkisiz bir uç, kapalı bir uçtan daha büyük bir yüzeydir.
	if s.proxyDeps != nil {
		mux.Handle("GET /api/terminal/{target}", s.requireSession(http.HandlerFunc(s.handleTerminal)))
	}

	// /api altındaki eşleşmeyen yollar SPA'ya DÜŞMEZ: bir API isteğine
	// index.html dönmek, istemciyi "200 ama beklediğim şey değil" ile baş
	// başa bırakır. Kapalı bir özelliğin rotası burada dürüstçe 404 olur.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusNotFound, "not found")
	})

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
// style-src'taki 'unsafe-inline' HÂLÂ AÇIK ve sebebi artık React değil.
//
// Panelde satır içi stil KALMADI — ölçüldü, çalışan sayfada style
// niteliği taşıyan sıfır öğe var ve index.html'deki <style> bloğu da
// styles.css'e taşındı. Yani izni düşürmenin önündeki tek engel
// xterm.js: DOM renderer'ı çalışma zamanında belgeye <style> enjekte
// ediyor.
//
// Düşürmeden ÖNCE ölçülmesi gereken: üretim derlemesi, bu başlıkla
// servis edilen gerçek bir sunucu, ve AÇILMIŞ bir terminal. Bunu
// ölçmeden kaldırmak, yerelde (CSP'siz Vite dev sunucusu) her şey
// çalışırken üretimde terminali sessizce bozmak olurdu — tam olarak
// kaçınılması gereken arıza biçimi.
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

	// ⚠️ KODU BURADA GÖSTERİYORUZ, BURADA SORMUYORUZ.
	//
	// Kurbanın gördüğü sayfa artık üç şeyi birden söylüyor: SSH
	// bağlantısının NEREDEN geldiği, kimin adına açılacağı, ve kodun
	// TERMİNALE yazılacağı. Eskiden sayfa yalnızca "terminaldeki kodu
	// yaz" diyordu; kurbanın kendi başlatmadığı bir girişi ayırt
	// etmesinin hiçbir yolu yoktu.
	code, source, ok := s.logins.Challenge(state)
	if !ok {
		log.Warn("oidc callback for finished attempt")
		http.Error(w, "unknown or expired login attempt", http.StatusNotFound)
		return
	}

	log.Info("oob login parked; verification code shown to browser",
		"user", id.Username, "ssh_source", source)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, confirmPageHTML,
		html.EscapeString(source),
		html.EscapeString(id.Username),
		html.EscapeString(code))
}

// Sayfalar bilerek gösterişsiz: sunum öğrenme konusu değil. İçlerindeki
// %s yerleri fmt.Fprintf ile doldurulur.

// Sıra: SSH kaynağı, kimlik, sonra kod.
const confirmPageHTML = `<!doctype html>
<meta charset="utf-8"><title>postern — verify this SSH login</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
/* Renkler İKİ TEMA İÇİN DE AÇIKÇA yazılıyor.
   Sayfa yalnızca ön plan renklerini verip zemini tarayıcıya bırakırsa,
   koyu temada uyarı koyu zemine koyu yazılıp OKUNMAZ hale geliyordu.
   Bu sayfanın tek işi o uyarıyı okutmak: okunmayan uyarı, oltalama
   savunmasının kendisini işlevsiz bırakır. */
:root {
  color-scheme: light dark;
  --bg: #ffffff; --fg: #1a1d23; --soft: #5a5f6a;
  --warn-bg: #fdf3e2; --warn-fg: #6d4600; --warn-line: #b07d1a;
  --code-bg: #f1f2f4; --code-fg: #16181d;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14161a; --fg: #e7e9ee; --soft: #a2a9b6;
    --warn-bg: #33260f; --warn-fg: #f3cf8b; --warn-line: #8a6a22;
    --code-bg: #232830; --code-fg: #f2f4f8;
  }
}
body {
  font-family: system-ui, sans-serif; max-width: 34rem;
  margin: 3rem auto; padding: 0 1rem; line-height: 1.5;
  background: var(--bg); color: var(--fg);
}
.warn {
  background: var(--warn-bg); border: 1px solid var(--warn-line);
  color: var(--warn-fg); padding: .75rem 1rem; border-radius: 6px;
}
.code {
  font-size: 2rem; letter-spacing: .25em;
  font-family: ui-monospace, monospace; text-align: center;
  padding: 1rem; border-radius: 6px;
  background: var(--code-bg); color: var(--code-fg);
  overflow-wrap: anywhere;
}
.note { color: var(--soft); font-size: .9rem; }
</style>
<body>
<h2>An SSH login is waiting for you</h2>

<p class="warn">
<strong>Did you start this?</strong> A connection from
<code style="font-size:1.05em">%s</code> is asking to sign in as
<strong>%s</strong>. If that was not you, close this page and tell your
administrator — someone may be trying to use your account.
</p>

<p>If it was you, type this verification code into the terminal that is
waiting:</p>

<p class="code">%s</p>

<p class="note">
postern will never ask you to send this code to anyone. It is only ever
typed into a terminal you are sitting at.
</p>
`
