package httpapi

// S4.3 — web terminali: WS /api/terminal/{target}
//
// Yetki modeli SSH ile AYNI: kimlik doğrulanmış oturumdan gelir, hedef
// erişimi policy'den. Fark yalnızca kapı — proxy.Open her ikisini de
// aynı akıştan geçirir.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/coder/websocket"

	"github.com/Warewave-Technology/postern/internal/proxy"
	"github.com/Warewave-Technology/postern/internal/upstream"
)

// handleTerminal, tarayıcıya hedefte bir kabuk açar.
func (s *Server) handleTerminal(w http.ResponseWriter, r *http.Request) {
	log := s.logger.With("remote", s.clientKey(r), "user", sessionUser(r))

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

	/*
	 * ⚠️ DENETİME YAZILAN ADRES clientKey'DEN GELİYOR, r.RemoteAddr'DAN
	 * DEĞİL.
	 *
	 * ÖLÇÜLDÜ: TLS'i sonlandıran bir ters vekilin arkasında bu satır
	 * sessions.src_ip'ye VEKİLİN adresini yazıyordu (src_ip =
	 * "127.0.0.1"), kullanıcınınkini değil — üstelik trusted_proxies
	 * doğru yapılandırılmışken, yani postern gerçek adresi biliyor ve
	 * atıyordu.
	 *
	 * Aynı sütuna SSH kapısı (sshd/channel.go) doğrudan bağlantının
	 * adresini yazıyor. Yani tek sütun iki ayrı anlam taşıyordu ve
	 * "bu kabuk nereden açıldı" sorusu, panelden açılan her oturum için
	 * aynı cevabı veriyordu: vekilin adresi. İki kullanıcı ayırt
	 * edilemiyordu.
	 *
	 * clientKey aynı sorunun hız sınırı tarafındaki cevabı ve kuralı
	 * burada da doğru: X-Forwarded-For YALNIZCA istek
	 * http.trusted_proxies'teki bir adresten geliyorsa okunuyor.
	 * Liste boşken — varsayılan — dönen değer bugünküyle bit bit aynı.
	 *
	 * ⚠️ BEDELİ: trusted_proxies artık bir DENETİM ayarı da. Geniş
	 * yazılan bir liste, o aralıktaki herkese kalıcı denetim satırına
	 * yazılacak adresi seçtirir.
	 */
	host := s.clientKey(r)

	/*
	 * 2. OTURUMU AÇ.
	 *
	 * ⚠️ BAŞARISIZLIK, UPGRADE'DEN SONRA SÖYLENİYOR — VE BU BİR
	 * DÜZELTME.
	 *
	 * Burada eskiden upgrade'den ÖNCE writeErr çağrılıyordu; yorumu da
	 * "istemci sebebi görür" diyordu. O gerekçe tarayıcı için YANLIŞ:
	 * WebSocket el sıkışması 101 dışında bir şeyle biterse, tarayıcı
	 * durum kodunu da gövdeyi de JavaScript'e VERMİYOR (WHATWG
	 * sözleşmesi bunu kasten yapıyor). Sayfaya ulaşan tek şey boş bir
	 * error/close olayı oluyordu.
	 *
	 * ÖLÇÜLDÜ: hedefi bu bastion'ın CA'sına güvenecek şekilde
	 * yapılandırmamış bir kurulumda, panelde kabuk düğmesine basan
	 * kullanıcının gördüğü tek şey "[disconnected]" idi. Sunucu sebebi
	 * biliyordu ve günlüğüne yazıyordu; kullanıcı ise özelliğin bozuk
	 * olduğunu sanıyordu.
	 *
	 * Sebep artık KAPANIŞ ÇERÇEVESİYLE gidiyor: tarayıcı CloseEvent'in
	 * code ve reason alanlarını JavaScript'e veriyor.
	 *
	 * Kimlik doğrulama ve site-dışı istek kontrolleri YUKARIDA, hâlâ
	 * upgrade'den önce: onlar bir kullanıcıya açıklanacak durumlar
	 * değil, sokete hiç hakkı olmayan çağrılar.
	 */
	sess, err := proxy.Open(r.Context(), *s.proxyDeps, proxy.Request{
		Username:   sessionUser(r),
		AccountID:  sessionAccountID(r),
		TargetName: r.PathValue("target"),
		SrcIP:      host,
	})
	if err != nil {
		s.refuseTerminal(w, r, err)
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

	/*
	 * ⚠️ KAPANIŞ DA OTURUMU BİTİRİR.
	 *
	 * Yukarıdaki WithoutCancel oturumu isteğin ömründen KASTEN
	 * koparıyor; bedeli, hiçbir şeyin onu durdurmaması. Ölçüldü: açık
	 * bir web terminali varken SIGTERM alan postern hiç ölmüyordu.
	 *
	 * Oturumu kesmek burada doğru olan: süreç gidiyor, hedefe giden
	 * bağlantıyı taşıyan da o. Kaydın kapanması bundan etkilenmiyor —
	 * aşağıdaki sess.Close, denetim satırını WithoutCancel ile
	 * yazıyor, yani iptal edilmiş bir bağlamla bile oturum "running"
	 * kalmıyor ve kayıt düzgün kapanıyor.
	 */
	if s.closing != nil {
		go func() {
			select {
			case <-s.closing:
				cancel()
			case <-ctx.Done():
				// Oturum kendiliğinden bitti: goroutine'i burada
				// bırakmak, uzun ömürlü bir süreçte oturum başına
				// bir sızıntı demekti.
			}
		}()
	}

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

/*
 * Kapanış kodları.
 *
 * ⚠️ 4000-4999 uygulamaya ayrılmış aralık (RFC 6455 §7.4.2). Standart
 * kodları (1008, 1011) kullanmak, tarayıcının ya da bir ara vekilin
 * ürettiği kapanışlarla bizimkini ayırt edilemez kılardı.
 */
const (
	closeDenied      = 4403 // kullanıcının bu hedefe yetkisi yok
	closeUnavailable = 4503 // oturum açılamadı
)

/*
 * refuseTerminal, oturumun NEDEN açılamadığını tarayıcıya söyler.
 *
 * ⚠️ SOKET AÇILIP HEMEN KAPANIYOR ve sebebi bu tek yol taşıyor. Kapanış
 * çerçevesinin reason alanı 123 BAYT ile sınırlı (RFC 6455 §5.5) —
 * metinler bu yüzden kısa; ayrıntı sunucu günlüğünde ve hedefin
 * sayfasında ("en son neden çalışmadı") duruyor.
 *
 * Upgrade'in kendisi başarısız olursa geriye HTTP hatası yazmak
 * kalıyor: soket yok, söyleyecek kanal da yok.
 */
func (s *Server) refuseTerminal(w http.ResponseWriter, r *http.Request, err error) {
	code, reason := terminalRefusal(err)

	s.logger.Warn("terminal session refused",
		"user", sessionUser(r), "target", r.PathValue("target"),
		"code", code, "error", err)

	conn, upErr := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if upErr != nil {
		// Soket kurulamadı: elimizde yalnızca HTTP var.
		writeErr(w, http.StatusServiceUnavailable, reason)
		return
	}
	_ = conn.Close(websocket.StatusCode(code), reason)
}

/*
 * terminalRefusal, hatayı kullanıcıya söylenecek bir cümleye çevirir.
 *
 * ⚠️ CÜMLELER NE YAPILACAĞINI SÖYLÜYOR. "session unavailable" teknik
 * olarak doğru ama okuyan kişiye hiçbir şey vermiyordu; bu ekranı gören
 * kişi çoğu zaman hedefi henüz yapılandırmamış olan operatörün ta
 * kendisi.
 */
func terminalRefusal(err error) (int, string) {
	switch {
	case errors.Is(err, proxy.ErrAccessDenied):
		return closeDenied, "You do not have access to this target."

	case errors.Is(err, upstream.ErrRefused):
		// Uzaktaki sshd bizi reddetti. Neredeyse her zaman tek bir
		// sebep: hedef bu bastion'ın CA'sına güvenmiyor.
		return closeUnavailable,
			"The target refused this bastion's certificate — it needs to trust the CA."

	case errors.Is(err, upstream.ErrHandshake):
		/*
		 * ⚠️ RET DEĞİL — VE AYRI CÜMLE OLMASI BUNUN İÇİN.
		 *
		 * Buraya düşen her şey ("no common algorithm", susan hedef,
		 * SSH konuşmayan port) eskiden ret sayılıyordu ve operatör
		 * hedefteki TrustedUserCAKeys'e bakmaya gönderiliyordu. Ölçüldü:
		 * sekiz arıza biçiminden altısı bu yanlış cümleyi alıyordu.
		 *
		 * Cümle bir tahmin YAPMIYOR: postern hangisi olduğunu bilmiyor
		 * ve uydurmak, yanlış cümlenin daha kibar hâli olurdu.
		 */
		return closeUnavailable,
			"The bastion reached this target but could not complete the SSH handshake."

	case errors.Is(err, upstream.ErrUnreachable):
		return closeUnavailable, "The bastion could not reach this target."

	case errors.Is(err, upstream.ErrHostKeyMismatch):
		// ⚠️ "Yapılandırma değişmiş olabilir" demiyoruz: postern bunu
		// bilemez, ve sabitlenmiş anahtarın tutmaması araya girme de
		// olabilir. Kararı operatöre bırakan bir cümle.
		return closeUnavailable,
			"The target presented a different host key than the one postern has pinned."

	case errors.Is(err, proxy.ErrRecordingFailed):
		return closeUnavailable, "The session was refused because it could not be recorded."
	}
	return closeUnavailable, "The session could not be opened."
}
