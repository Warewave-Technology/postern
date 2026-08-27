package httpapi

// S4.3 — web terminali: WS /api/terminal/{target}
//
// Yetki modeli SSH ile AYNI: kimlik doğrulanmış oturumdan gelir, hedef
// erişimi policy'den. Fark yalnızca kapı — proxy.Open her ikisini de
// aynı akıştan geçirir.

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/coder/websocket"

	"github.com/warewave/postern/internal/proxy"
)

// handleTerminal, tarayıcıya hedefte bir kabuk açar.
//
// TODO(yigit): implement.
//
// Sıra ve gerekçeleri:
//
//  1. ORIGIN KONTROLÜ — ilk satır. Tarayıcı WebSocket'e SameSite cookie
//     kuralını uygulamaz ve CORS da WS'i kapsamaz: kötü niyetli bir
//     sayfa, kurbanın cookie'siyle bu uca bağlanabilir ("cross-site
//     WebSocket hijacking"). Kütüphanenin varsayılan kontrolü Host ile
//     Origin'i karşılaştırır ama biz external_url'e göre AÇIKÇA
//     doğruluyoruz — ters proxy arkasında Host aldatıcı olabilir.
//     websocket.AcceptOptions.OriginPatterns ya da InsecureSkipVerify +
//     kendi kontrolün; ikincisini seçersen kontrolü ATLAMA, yalnızca
//     kütüphaneninkini kendi kontrolünle DEĞİŞTİR.
//
//  2. proxy.Open(r.Context(), s.proxyDeps, proxy.Request{
//     Username: sessionUser(r), TargetName: r.PathValue("target"),
//     SrcIP: <r.RemoteAddr'ın host kısmı>})
//     ⚠️ Upgrade'DEN ÖNCE: yetki reddini düzgün bir HTTP durum koduyla
//     söylemek, WS kurup sonra kapatmaktan iyidir — istemci sebebi görür.
//     ErrAccessDenied → 403, ErrUnavailable → 503.
//
//  3. websocket.Accept → hata durumunda proxy oturumunu KAPAT (Close);
//     yoksa denetim satırı "running" kalır ve hedef bağlantısı sızar.
//
//  4. down, downR := newWSChannel(ctx, conn); defer sess.Close(ctx)
//     sess.Run(ctx, down, downR)
//
// ⚠️ ctx seçimi: r.Context() istek bitince iptal olur. WebSocket
// yükseltmesinden sonra "istek" kavramı biter ama bağlantı yaşar —
// oturumu r.Context()'e bağlarsan terminal ilk saniyede kapanabilir.
// Bağlantının ömrüne bağlı bir ctx kur (context.WithoutCancel + kendi
// iptalin ya da conn.CloseRead'in verdiği ctx).
func (s *Server) handleTerminal(w http.ResponseWriter, r *http.Request) {
	writeErr(w, http.StatusNotImplemented, "not implemented")
}

// checkTerminalOrigin, WS isteğinin bizim sayfamızdan geldiğini doğrular.
//
// TODO(yigit): implement.
//
// r.Header.Get("Origin") boşsa (tarayıcı olmayan istemci) ne yapacağına
// karar ver ve gerekçeni yaz: tarayıcı SALDIRISINA karşı korunuyoruz,
// curl ile bağlanan birinin zaten geçerli bir oturum cookie'si olması
// gerekir — yani boş Origin'i reddetmek güvenlik eklemez ama hata
// ayıklamayı zorlaştırır.
func (s *Server) checkTerminalOrigin(r *http.Request) bool {
	return false
}

// sameOriginURL, iki adresin şema+host+port olarak aynı olup olmadığını
// söyler (hazır verildi: url karşılaştırmasının tuzakları öğrenme konusu
// değil).
func sameOriginURL(a, b string) bool {
	ua, err := url.Parse(a)
	if err != nil {
		return false
	}
	ub, err := url.Parse(b)
	if err != nil {
		return false
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host)
}

var _ = []any{websocket.Accept, proxy.Open, errors.Is}
