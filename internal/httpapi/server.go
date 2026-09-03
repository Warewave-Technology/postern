// Package httpapi serves postern's web endpoints: the OIDC callback and
// login confirmation now (S3.3), the web terminal later (S4).
package httpapi

import (
	"context"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/Warewave-Technology/postern/internal/auth"
	"github.com/Warewave-Technology/postern/internal/config"
	"github.com/Warewave-Technology/postern/internal/events"
	"github.com/Warewave-Technology/postern/internal/groupsync"
	"github.com/Warewave-Technology/postern/internal/proxy"
	"github.com/Warewave-Technology/postern/internal/record"
	"github.com/Warewave-Technology/postern/internal/store"
)

// Server, HTTP uçlarını taşır. TLS/dinleme çağıranın işi (serve kuruyor);
// burada yalnızca yönlendirme ve handler'lar var.
type Server struct {
	/*
	 * oidc, ÇALIŞIRKEN değiştirilebilen sağlayıcı tutucusu.
	 *
	 * ⚠️ İşaretçi DEĞİL tutucu: ayarlar panelden değişebiliyor ve sabit
	 * bir işaretçi, değiştirilmiş bir sağlayıcıdan sonra ESKİSİYLE
	 * giriş yapılmasına yol açardı.
	 */
	oidc   *auth.OIDCHolder
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
	proxyDeps *proxy.Deps

	// publicKeyLogin, anahtarla girişin açık olup olmadığı. Varsayılan
	// AÇIK: sıfır değeri bir güvenlik ayarını sessizce KAPATMAMALI —
	// tersi, SetPublicKeyLogin çağırmayı unutan bir yolun kullanıcıları
	// kapı dışında bırakması demekti.
	publicKeyLogin bool

	/*
	 * sshHost/sshPort, KULLANICIYA GÖSTERİLEN ssh adresi.
	 *
	 * ⚠️ Hiçbir erişim kararına girmiyor: panel yalnızca kopyalanacak
	 * komutu bununla kuruyor. sshHost boşsa panel kopyalama seçeneğini
	 * hiç göstermiyor — yapıştırıldığında çalışmayacak bir komut
	 * vermektense hiç vermemek (config.SSHEndpoint).
	 */
	sshHost string
	sshPort int

	// syncDefaults, YAML'daki sync bloğu — saklanan ayar yokken geçerli
	// olan değerler. Panel ETKİN değeri göstermek zorunda: "ayarlanmamış"
	// demek, döngünün 15 dakikada bir koştuğu bir kurulumda yanlış bilgi.
	syncDefaults groupsync.Settings
	externalURL  string

	// records nil ise kayıt izleme yapılandırılmamış demektir ve
	// rotalar HİÇ kurulmaz — kapalı özellik, kapalı yüzey.
	records *record.Store

	/*
	 * archiveDest, kayıt arşivinin HEDEFİ — config'ten geliyor ve
	 * panelden değiştirilemiyor. Panelin salt okunur alanları doğru
	 * çizebilmesi ve "buradan yönetilmiyor" diyebilmesi için burada.
	 */
	archiveDest config.ArchiveConfig

	// archiveHostSecret, host'tan gelen yükleme sırrı (dosya ya da
	// ortam). Doluysa panel kimliği DEĞİŞTİREMİYOR ve bunu söylüyor.
	archiveHostSecret string

	// ready, hazırlık yoklamasının kısa ömürlü önbelleği. Kimliksiz
	// bir ucun veritabanına gidebileceği hızı bağlıyor (health.go).
	ready readyCache

	// ping, hazırlık yoklaması. Testlerin veritabanını taklit
	// edebilmesi için alan (record.Pruner.now ile aynı gerekçe):
	// ölçmek istediğimiz şey yoklamanın SONUCU değil, KAÇ KEZ
	// yapıldığı — ve bunu gerçek bir veritabanıyla ölçmek mümkün değil.
	ping func(context.Context) error

	// live, akan oturumların defteri (proxy.Live).
	//
	// ⚠️ proxyDeps'ten AYRI TUTULUYOR. proxyDeps yalnızca
	// http.terminal_enabled açıkken doluyor; kesme yeteneğini oraya
	// bağlamak, varsayılan kurulumda — terminal kapalı, yalnızca SSH —
	// düğmeyi sessizce yok ederdi.
	live *proxy.Live

	// trustedProxies, X-Forwarded-For'una güvenilen kaynaklar.
	// Boşken başlık HİÇ okunmuyor (bkz. trustedproxy.go).
	trustedProxies *trustedProxies

	// secureCookies, oturum çerezine Secure bayrağının konup
	// konmayacağı. SetExternalURL kuruyor.
	secureCookies bool

	// bus nil ise canlı olay akışı yapılandırılmamış demektir ve rota
	// HİÇ kurulmaz — kapalı özellik, kapalı yüzey. Panel bunu görüp
	// yoklamaya düşüyor.
	bus *events.Bus

	/*
	 * closing, kapanışın BAŞLADIĞINI duyuran kanal.
	 *
	 * ⚠️ VAR OLMA SEBEBİ ÖLÇÜLDÜ: SIGTERM alan postern ölmüyordu.
	 * http.Server.Shutdown etkin bağlantıların bitmesini bekler ve
	 * istek bağlamlarını İPTAL ETMEZ; bizim iki uzun ömürlü
	 * işleyicimiz (SSE akışı ve terminal WebSocket'i) kendiliğinden
	 * bitmediği için bekleme sonsuza kadar sürüyordu. Süreç ayakta
	 * kalıp eski bağlantıları taşımaya devam ediyordu: paneli açık
	 * olan operatör, ölmüş sandığı sürecin akışına bakıp "Live"
	 * rozetiyle ESKİ sayıları okuyordu.
	 *
	 * Yalnızca Shutdown'a süre sınırı koymak yetmezdi: her yeniden
	 * başlatma o sınır kadar sürer ve süre dolunca oturumlar
	 * ortasından kesilirdi. Bu kanal işleyicilere "bitir" diyor,
	 * kapanış milisaniyelerde tamamlanıyor; süre sınırı da ayrıca
	 * duruyor ama artık bir SON ÇARE.
	 */
	closing   chan struct{}
	closeOnce sync.Once

	// Yerel giriş kapısının yük korumaları (bkz. locallogin.go).
	localSlots chan struct{}
	localLimit *localLimiter
	// guessBackoff, parola tahminine karşı (hesap, adres) başına artan
	// gecikme. Gerekçesi backoff.go'da.
	guessBackoff *guessBackoff

	// bindSlots, dizine karşı eşzamanlı bind sayısını sınırlar. Yerel
	// yuvalardan AYRI: orada postern'in belleği, burada KURUMUN dizini
	// korunuyor.
	bindSlots chan struct{}
}

/*
 * BeginShutdown, uzun ömürlü işleyicilere kapanışın başladığını söyler.
 *
 * http.Server.Shutdown'dan ÖNCE çağrılmalı: sıra tersine dönerse
 * Shutdown, henüz durması söylenmemiş akışları beklemeye başlar.
 *
 * Birden çok kez çağrılabilir (closeOnce): kapanış yolları iç içe
 * geçebiliyor ve kapalı bir kanalı ikinci kez kapatmak panik olurdu.
 */
func (s *Server) BeginShutdown() {
	// New dışında kurulmuş bir Server (testlerdeki değişmez alanlı
	// literaller) için kanal nil olur; nil kanal hiç sinyal vermez,
	// yani o kurulumlar eskisi gibi davranır.
	if s.closing == nil {
		return
	}
	s.closeOnce.Do(func() { close(s.closing) })
}

// SetExternalURL, kullanıcının tarayıcısından görülen kök adresi verir.
//
// Çerezin Secure bayrağı BURADAN türetiliyor, r.TLS'ten değil: postern
// TLS'i sonlandıran bir ters vekilin arkasındaysa r.TLS nil olur ama
// bağlantı HTTPS'tir. r.TLS'e bakan kod o kurulumda oturum çerezini
// Secure'suz yazar — yani düz metin bir isteğe iliştirilebilir hâle
// getirir. Dış adresin şeması dağıtımın gerçeğini söyleyen tek kaynak.
/*
 * SetPublicKeyLogin, anahtar girişinin açık olup olmadığını bildirir.
 *
 * Panelin anahtar yönetimi ekranı buna bakıyor — ama ASIL KORUMA UÇTA
 * (adminAddKey/adminRemoveKey). Arayüzde gizlemek bir yetki kontrolü
 * değil, yalnızca nezaket: uç açık kaldığı sürece curl ile anahtar
 * eklenebilirdi ve kapalı sanılan kapı açık kalırdı.
 */
func (s *Server) SetPublicKeyLogin(on bool) { s.publicKeyLogin = on }

// SetSSHEndpoint, panelin göstereceği ssh adresini bildirir.
// Dinlemeye başlamadan ÖNCE çağrılmalı: alan kilitsiz.
func (s *Server) SetSSHEndpoint(host string, port int) {
	s.sshHost, s.sshPort = host, port
}

// SetSyncDefaults, YAML'dan gelen senkronizasyon varsayılanlarını bildirir.
func (s *Server) SetSyncDefaults(d groupsync.Settings) { s.syncDefaults = d }

/*
 * UseArchive, arşiv hedefini ve host sırrının varlığını bildirir.
 *
 * ⚠️ SIRRIN KENDİSİ DEĞİL, VARLIĞI önemli: panel yalnızca "buradan
 * değiştirilebilir mi" sorusunu cevaplıyor. Değeri httpapi'ye taşımak,
 * onu bir daha gerekmeyecek bir yerde tutmak olurdu.
 */
func (s *Server) UseArchive(dest config.ArchiveConfig, hostSecret string) {
	s.archiveDest = dest
	s.archiveHostSecret = hostSecret
}

// UseLiveSessions, akan oturum defterini bildirir; kesme uçları buradan
// çalışıyor. Dinlemeye başlamadan ÖNCE çağrılmalı: alan kilitsiz.
func (s *Server) UseLiveSessions(l *proxy.Live) { s.live = l }

/*
 * SetTrustedProxies, X-Forwarded-For'una güvenilecek kaynakları bildirir.
 * Dinlemeye başlamadan ÖNCE çağrılmalı: alan kilitsiz.
 *
 * Hata döndürüyor ve çağıran BAŞLAMAYI KESMELİ: bozuk bir CIDR'ı
 * yok saymak, operatörün "vekilimi tanıttım" sandığı ama tanıtmadığı
 * bir kurulum üretirdi — kilidin geri geldiği hâl (bkz. trustedproxy.go).
 */
func (s *Server) SetTrustedProxies(cidrs []string) error {
	tp, err := parseTrustedProxies(cidrs)
	if err != nil {
		return err
	}
	s.trustedProxies = tp
	return nil
}

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

func New(o *auth.OIDCHolder, logins *auth.Logins, db *store.Store, logger *slog.Logger) *Server {
	return &Server{
		oidc:         o,
		closing:      make(chan struct{}),
		localSlots:   make(chan struct{}, localLoginSlots),
		localLimit:   newLocalLimiter(),
		guessBackoff: newGuessBackoff(),
		bindSlots:    make(chan struct{}, directoryBindSlots),
		logins:       logins,
		logger:       logger,
		store:        db,
		ping:         db.Ping,
		webSessions:  auth.NewWebSessions(),
		webLogins:    &webPending{},
		groups:       auth.ClaimGroups{},

		// ⚠️ VARSAYILAN AÇIK. Sıfır değeri false olsaydı,
		// SetPublicKeyLogin çağırmayı unutan her yol anahtar girişini
		// sessizce kapatırdı — güvenlik ayarları "unutulunca kapansın"
		// diye kurulur, "unutulunca kullanıcıyı kilitlesin" diye değil.
		publicKeyLogin: true,
	}
}

// Handler, yönlendirme tablosu. Metod kısıtları desenin içinde ("GET /x"):
// yanlış metod otomatik 405 alır.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	/*
	 * ⚠️ ROTALAR KOŞULSUZ KURULUYOR.
	 *
	 * Eskiden yalnızca açılışta OIDC yapılandırılmışsa kuruluyordu.
	 * Ayarlar artık çalışırken gelebiliyor ve o an mux yeniden
	 * kurulamaz — sihirbazdan OIDC seçen operatör, yeniden başlatana
	 * kadar 404 alırdı. Kontrol istek anına taşındı: canlı istemci
	 * yoksa handler'ın kendisi reddediyor.
	 */
	{
		mux.HandleFunc("GET /auth/login", s.handleWebLogin)
		mux.HandleFunc("GET /auth/callback", s.handleCallback)
	}

	/*
	 * Hangi giriş kapıları açık — oturumsuz okunur.
	 *
	 * ⚠️ GİRİŞ EKRANI BUNU UYDURAMAZ. Panel bugüne kadar tek bir
	 * "kimlik sağlayıcınla gir" düğmesi çiziyordu çünkü başka ihtimal
	 * yoktu. Artık var: kimlik sağlayıcısı olmayan bir kurulumda o
	 * düğme 404'e gider ve kullanıcı ürünün bozuk olduğunu düşünür.
	 * Ekran ne olduğunu SUNUCUYA sormalı.
	 */
	mux.Handle("GET /api/auth/methods", noStore(http.HandlerFunc(s.handleAuthMethods)))

	// Yerel kapı. sameOrigin ŞART: siteler arası bir POST, kurbanın
	// tarayıcısında oturum açtırmaya çalışabilirdi.
	mux.Handle("POST /auth/local", s.sameOrigin(http.HandlerFunc(s.handleLocalLogin)))
	// Çıkış da same-origin: siteler arası bir POST kurbanı sessizce
	// oturumdan atıyordu. Etkisi düşük ama bedeli sıfır.
	mux.Handle("POST /auth/logout", s.sameOrigin(http.HandlerFunc(s.handleLogout)))

	// API: oturum ister.
	mux.Handle("GET /api/me", noStore(s.requireSession(http.HandlerFunc(s.handleMe))))

	// Kendi anahtarlarım. Yazma uçları same-origin: siteler arası bir
	// POST, kurbanın hesabına anahtar ekletmeye çalışabilirdi.
	mux.Handle("GET /api/me/keys", noStore(s.requireSession(http.HandlerFunc(s.handleMyKeys))))
	mux.Handle("POST /api/me/keys",
		s.requireSession(s.sameOrigin(http.HandlerFunc(s.handleAddMyKey))))
	mux.Handle("POST /api/me/keys/remove",
		s.requireSession(s.sameOrigin(http.HandlerFunc(s.handleRemoveMyKey))))

	/*
	 * Kendi parolam. ZORUNLU DEĞİŞİKLİK KISITINDAN ÇIKIŞIN TEK YOLU —
	 * gerekçesi weblogin.go'daki changePasswordAllowed'da, ve o harita
	 * buradaki desenle BİREBİR aynı yazılmak zorunda (eşleşme tam desen
	 * üzerinden).
	 */
	mux.Handle("POST /api/me/password",
		s.requireSession(s.sameOrigin(http.HandlerFunc(s.handleChangePassword))))

	// Kendi ikinci faktörüm (totp.go).
	s.routeTOTP(mux)

	// Yönetim: oturum + admin + same-origin (admin.go, federation.go).
	s.registerAdminRoutes(mux)
	s.registerFederationRoutes(mux)
	s.registerAuthSourceRoutes(mux)
	s.registerPendingRoutes(mux)
	s.registerOIDCRoutes(mux)
	s.registerSetupRoutes(mux)
	s.registerEventRoutes(mux)
	s.registerTargetRoutes(mux)

	// Arşiv kimliği: kendi ucu, genel ayarlar yolu DEĞİL (gerekçe
	// archivesettings.go'da — oradaki sınıflandırma fail-open).
	s.registerArchiveRoutes(mux, func(h http.HandlerFunc) http.Handler {
		return noStore(s.requireSession(s.requireAdmin(s.sameOrigin(h))))
	})

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

	/*
	 * /auth altındaki eşleşmeyen yollar da SPA'ya DÜŞMEZ.
	 *
	 * Ölçülerek bulundu: kimlik sağlayıcı yapılandırılmamışken
	 * /auth/login rotası kurulmuyor, ama SPA yakalayıcısı onu alıp
	 * index.html döndürüyordu — yani KAPALI bir özellik 200 ile
	 * uygulamanın kabuğunu veriyordu. /api için aynı gerekçeyle zaten
	 * bir koruma vardı; bu yol unutulmuştu.
	 *
	 * Daha belirgin desenler (POST /auth/logout, OIDC açıkken
	 * GET /auth/login) bunu gölgelemiyor: ServeMux en özgül eşleşmeyi
	 * seçiyor.
	 */
	mux.HandleFunc("/auth/", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusNotFound, "not found")
	})

	/*
	 * Sağlık uçları: kimlik İSTEMİYORLAR ve bu bilinçli — bir sağlık
	 * kontrolünün amacı kimlik bilgisi olmadan sorulabilmesi.
	 * /healthz hiçbir şeye dokunmuyor; /readyz veritabanına bakıyor
	 * ama önbellekli (gerekçe health.go'da).
	 */
	s.registerHealthRoutes(mux)

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
	/*
	 * ⚠️ AKIŞI BAŞLATAN KUŞAKLA TAMAMLANMAK ZORUNDA.
	 *
	 * Ayarlar akışın ortasında değiştirilirse, A sağlayıcısının
	 * ürettiği code B'nin token ucuna gönderilirdi — code ve istemci
	 * sırrı, operatörün az önce yazdığı adrese giderdi. İstemci ve
	 * kuşak TEK okumada alınıyor ve Exchange O istemcide yapılıyor;
	 * ikinci bir okuma korumayı boşa çıkarırdı.
	 */
	client, gen := s.oidc.Current()
	if client == nil || gen != req.Gen {
		log.Warn("oidc callback arrived after the provider changed",
			"started_gen", req.Gen, "current_gen", gen)
		// Denemeyi HEMEN düşür: SSH tarafındaki kullanıcıyı zaman
		// aşımına kadar bekletmek, cevabı bildiğimiz hâlde susmak olurdu.
		s.logins.DropState(state)
		http.Error(w, "the identity provider configuration changed while you were "+
			"signing in; start again", http.StatusForbidden)
		return
	}

	id, err := client.Exchange(r.Context(), req, state, code)
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
