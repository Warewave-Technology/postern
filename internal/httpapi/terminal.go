package httpapi

// S4.3 — web terminali: WS /api/terminal/{target}
//
// Yetki modeli SSH ile AYNI: kimlik doğrulanmış oturumdan gelir, hedef
// erişimi policy'den. Fark yalnızca kapı — proxy.Open her ikisini de
// aynı akıştan geçirir.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/coder/websocket"

	"github.com/warewave/postern/internal/proxy"
)

// handleTerminal, tarayıcıya hedefte bir kabuk açar.
func (s *Server) handleTerminal(w http.ResponseWriter, r *http.Request) {
	log := s.logger.With("remote", r.RemoteAddr, "user", sessionUser(r))

	// 1. ORIGIN — her şeyden önce.
	//
	// Tarayıcı WebSocket'e SameSite cookie kuralını UYGULAMAZ ve CORS da
	// WS'i kapsamaz: kötü niyetli bir sayfa, kurbanın cookie'siyle bu uca
	// bağlanabilir ("cross-site WebSocket hijacking"). Bu kontrol o
	// saldırının tek savunması — admin API'sindeki sameOrigin'in WS
	// karşılığı.
	if !s.checkTerminalOrigin(r) {
		origin := r.Header.Get("Origin")
		log.Warn("terminal websocket rejected on origin", "origin", origin)

		// Mesaj sebebi AYIRIYOR: eksik başlık neredeyse her zaman
		// araya giren bir vekilin onu düşürmesi demek ve o arıza
		// aksi hâlde "terminal çalışmıyor" diye teşhis edilemez
		// görünür.
		if origin == "" {
			writeErr(w, http.StatusForbidden,
				"missing Origin header — a proxy in front of postern may be stripping it")
			return
		}
		writeErr(w, http.StatusForbidden, "cross-site request rejected")
		return
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	// 2. YETKİ — upgrade'DEN ÖNCE.
	//
	// Reddi düzgün bir HTTP durum koduyla söylemek, WS kurup sonra
	// kapatmaktan iyidir: istemci sebebi görür, tarayıcı konsolunda
	// anlamsız bir "connection closed" kalmaz.
	sess, err := proxy.Open(r.Context(), *s.proxyDeps, proxy.Request{
		Username:   sessionUser(r),
		TargetName: r.PathValue("target"),
		SrcIP:      host,
	})
	if err != nil {
		if errors.Is(err, proxy.ErrAccessDenied) {
			writeErr(w, http.StatusForbidden, "access denied")
			return
		}
		writeErr(w, http.StatusServiceUnavailable, "session unavailable")
		return
	}

	// 3. Upgrade. Origin kontrolünü kendimiz yaptığımız için
	//    kütüphaneninkini kapatıyoruz — ATLAMIYORUZ, DEĞİŞTİRİYORUZ:
	//    ters proxy arkasında Host aldatıcı olabilir, biz external_url'e
	//    göre karşılaştırıyoruz.
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		// Upgrade başarısız: oturumu KAPAT, yoksa denetim satırı
		// "running" kalır ve hedef bağlantısı sızar.
		sess.Log.Error("websocket upgrade failed", "error", err)
		sess.Close(r.Context())
		return
	}

	// 4. Oturumu sür.
	//
	// ⚠️ ctx seçimi: r.Context() istek bitince iptal olur. WebSocket
	// yükseltmesinden sonra "istek" kavramı biter ama bağlantı yaşar —
	// oturumu ona bağlarsak terminal ilk saniyede kapanabilir. Bu yüzden
	// iptali bağlantının ömrüne bağlıyoruz.
	ctx, cancel := context.WithCancel(context.WithoutCancel(r.Context()))
	defer cancel()

	// Bağlantı kapanınca ctx'i iptal et: broker'ın hedef tarafındaki
	// akışları pty yüzünden kendiliğinden bitmez (wschannel.go'daki not).
	down, downR := newWSChannel(ctx, conn, cancel)
	defer sess.Close(ctx)

	if err := sess.Run(ctx, down, downR); err != nil {
		sess.Log.Error("session broker failed", "error", err)
	}

	// Broker döndü: kullanıcı çıktı ya da hedef kapattı. Bağlantıyı
	// düzgün kapat ki tarayıcı "disconnected" yazabilsin.
	_ = down.Close()
}

// checkTerminalOrigin, WS isteğinin bizim sayfamızdan geldiğini doğrular.
//
// Origin başlığı YOKSA geçiriyoruz: tarayıcılar onu her WS isteğinde
// gönderir, yani boş Origin tarayıcı dışı bir istemci demektir (curl,
// test aracı). Onu reddetmek güvenlik EKLEMEZ — böyle bir istemcinin
// zaten geçerli bir oturum cookie'si olması gerekir ve saldırı senaryosu
// "kurbanın tarayıcısını kullandırmak" üzerine kurulu.
func (s *Server) checkTerminalOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")

	// ⚠️ EKSİK ORIGIN ARTIK GEÇMİYOR.
	//
	// Eskiden yokluğunda true dönüyordu — güvenlik başlığının
	// YOKLUĞUNDA açık kalmak, sonradan ısıran desenin ta kendisi.
	//
	// Tarayıcılar WebSocket el sıkışmasında Origin'i HER ZAMAN gönderir
	// (siteler arası bir sayfa da onu bastıramaz; kontrolün dayandığı
	// şey bu). Başlığın olmaması "istekte bulunan taraf tarayıcı değil"
	// demek — ve bu uç yalnızca panelin kendi JS'i için var.
	//
	// Bu kontrolün savunduğu şey siteler arası WebSocket ele
	// geçirmesidir; tarayıcı olmayan bir istemcinin buraya gelebilmesi
	// için zaten oturum çerezini çalmış olması gerekir, o noktada
	// Origin'in bir önemi kalmaz. Yani sıkı olmanın maliyeti yok.
	if origin == "" {
		return false
	}
	return sameOriginURL(origin, s.externalURL)
}

// sameOriginURL, iki adresin şema+host olarak aynı olup olmadığını söyler.
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
