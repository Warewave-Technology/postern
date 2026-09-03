package httpapi

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/model"
	"github.com/warewave/postern/internal/sshalg"
	"github.com/warewave/postern/internal/store"
	"github.com/warewave/postern/internal/upstream"
)

// registerTargetRoutes, hedeflerle ilgili iki ucu bağlar.
func (s *Server) registerTargetRoutes(mux *http.ServeMux) {
	// ⚠️ ADMIN DEĞİL. Bu uç, oturum sahibinin KENDİ hedeflerini
	// döndürüyor ve ana ekranı besliyor. Yetki sınırı gövdede: liste
	// kullanıcının rollerinden türüyor, istemcinin sorduğundan değil.
	mux.Handle("GET /api/targets", noStore(s.requireSession(http.HandlerFunc(s.handleMyTargets))))

	// Tarama YAZMA gibi korunuyor (sameOrigin): hedefe ağdan bağlanan,
	// yan etkisi olan bir eylem. GET olsaydı bir <img> etiketiyle
	// tetiklenebilirdi.
	mux.Handle("POST /api/admin/targets/scan",
		noStore(s.requireSession(s.requireAdmin(s.sameOrigin(http.HandlerFunc(s.adminScanTarget))))))

	/*
	 * ⚠️ ADMIN DEĞİL: oturum sahibinin ERİŞEBİLDİĞİ tek hedefin
	 * detayı. Yetki gövdede; erişimi olmayan için 404 dönüyor, 403
	 * değil — "böyle bir hedef var ama sana kapalı" demek, envanteri
	 * tek tek deneyerek çıkarmaya izin vermek olurdu.
	 */
	mux.Handle("GET /api/targets/{name}",
		noStore(s.requireSession(http.HandlerFunc(s.handleMyTargetDetail))))

	mux.Handle("GET /api/admin/targets/{name}",
		noStore(s.requireSession(s.requireAdmin(s.sameOrigin(http.HandlerFunc(s.adminTargetDetail))))))
}

// targetCard, ana ekrandaki kutunun ihtiyacı.
//
// Host/port BURADA YOK ve bu kasıtlı: sıradan kullanıcı hedefe postern
// üzerinden bağlanıyor, adresini bilmesi gerekmiyor. Adresi vermek, bir
// bastion'ın varlık sebebi olan "ağ topolojisini kullanıcıya açmama"
// özelliğini panelden sızdırırdı.
type targetCard struct {
	Name          string            `json:"name"`
	Labels        map[string]string `json:"labels"`
	ServerVersion string            `json:"server_version,omitempty"`
	LastSeenAt    string            `json:"last_seen_at,omitempty"`
}

func (s *Server) handleMyTargets(w http.ResponseWriter, r *http.Request) {
	u, err := s.store.User(r.Context(), sessionUser(r))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.clearSessionCookie(w)
			writeErr(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		s.storeErr(w, "targets.mine", err)
		return
	}

	// Kullanıcının erişebildiği hedefler, rollerinden. İki rol aynı
	// hedefi verebilir; küme tekilleştiriyor.
	allowed := map[string]struct{}{}
	for _, role := range u.Roles {
		for _, t := range role.Targets {
			allowed[t] = struct{}{}
		}
	}

	targets, err := s.store.Targets(r.Context())
	if err != nil {
		s.storeErr(w, "targets.mine", err)
		return
	}

	// Gözlemler TEK sorguyla: hedef başına ayrı sorgu, ana ekranı
	// çizerken erişilen her hedef için bir gidiş dönüş olurdu (N+1).
	//
	// Hatası ölümcül DEĞİL: gözlem olmadan da kutular çizilir ve
	// kullanıcının bağlanmasını engellemek için sebep yok.
	facts, ferr := s.store.AllTargetFacts(r.Context())
	if ferr != nil {
		s.logger.Warn("target facts unavailable", "error", ferr)
		facts = map[string]model.TargetFacts{}
	}

	out := make([]targetCard, 0, len(allowed))
	for _, t := range targets {
		if _, ok := allowed[t.Name]; !ok {
			continue
		}
		card := targetCard{Name: t.Name, Labels: t.Labels}
		if card.Labels == nil {
			// nil map JSON'da null oluyor ve istemcide Object.entries
			// patlıyor.
			card.Labels = map[string]string{}
		}
		// Gözlemler kullanıcı için de yararlı: "bu makineye en son ne
		// zaman girilebilmiş" sorusu, bağlanmadan önce sorulmaya değer.
		if f, ok := facts[t.Name]; ok {
			card.ServerVersion = f.ServerVersion
			if !f.LastSeenAt.IsZero() {
				card.LastSeenAt = f.LastSeenAt.Format(time.RFC3339)
			}
		}
		out = append(out, card)
	}

	writeJSON(w, http.StatusOK, out)
}

// adminTargetDetail, tek bir hedefin TAM sayfası.
//
// NEDEN AYRI SAYFA: tablo satırı adres, parmak izi, etiketler, gözlemler
// ve hangi rollerin eriştiğini birden taşıyamıyor — denendi, satır
// okunamaz hâle geliyor ve birincil eylem yatay kaydırmanın ardına
// düşüyordu.
func (s *Server) adminTargetDetail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	t, err := s.store.Target(r.Context(), name)
	if err != nil {
		s.storeErr(w, "target.detail", err)
		return
	}

	labels, err := s.store.TargetLabels(r.Context(), name)
	if err != nil {
		s.storeErr(w, "target.detail", err)
		return
	}
	if labels == nil {
		labels = map[string]string{}
	}

	facts, err := s.store.TargetFacts(r.Context(), name)
	if err != nil {
		s.storeErr(w, "target.detail", err)
		return
	}

	// Bu hedefe erişim VEREN roller. Kullanıcı listesi değil rol listesi:
	// erişim yalnızca rol üzerinden veriliyor ve "kimler girebilir"
	// sorusunun doğru cevabı önce "hangi roller".
	roles, err := s.store.Roles(r.Context())
	if err != nil {
		s.storeErr(w, "target.detail", err)
		return
	}
	granting := []string{}
	for _, role := range roles {
		for _, rt := range role.Targets {
			if rt == t.Name {
				granting = append(granting, role.Name)
				break
			}
		}
	}

	type sessionRow struct {
		ID        string `json:"id"`
		User      string `json:"user"`
		OSUser    string `json:"os_user"`
		SrcIP     string `json:"src_ip"`
		StartedAt string `json:"started_at"`
		EndedAt   string `json:"ended_at,omitempty"`
	}
	recent := []sessionRow{}
	/*
	 * ⚠️ OKUNAMADIYSA SÖYLE — VE BU BİR DÜZELTME.
	 *
	 * Burada `else` yoktu: sorgu çöktüğünde `recent` boş kalıyor ve
	 * cevaba `recent_sessions: []` diye gidiyordu, hiçbir hata alanı
	 * olmadan. Panel de bunu görüp "No session has been opened to this
	 * host." yazıyordu — yani "bakamadık"ı "hiç olmamış" diye
	 * bildiriyordu, üstelik bir denetim ekranında.
	 *
	 * Oturum detayındaki `files_error` deseninin aynısı: liste düşse
	 * de sayfa düşmüyor, ama boşluğun ne anlama GELMEDİĞİ yazılıyor.
	 */
	recentErr := false
	recentPartial := false
	// Boş kullanıcı adı = "hepsi" (bkz. store.Sessions).
	sessions, serr := s.store.Sessions(r.Context(), "", sessionScanLimit)
	if serr != nil {
		s.logger.Error("target session history unavailable",
			"target", t.Name, "error", serr)
		recentErr = true
	} else {
		for _, sn := range sessions {
			if sn.Target != t.Name {
				continue
			}
			row := sessionRow{
				ID: sn.ID, User: sn.User, OSUser: sn.OSUser, SrcIP: sn.SrcIP,
				StartedAt: sn.StartedAt.Format(time.RFC3339),
			}
			if !sn.EndedAt.IsZero() {
				row.EndedAt = sn.EndedAt.Format(time.RFC3339)
			}
			recent = append(recent, row)
			if len(recent) >= targetSessionRows {
				break
			}
		}

		/*
		 * ⚠️ PENCERENİN DIBINE VURDUK MU?
		 *
		 * Tarama TÜM hedeflerin son N oturumuna bakıyor ve sonra bu
		 * hedefe göre süzüyor. Gürültülü bir kurulumda o pencere tek
		 * bir hedefin oturumlarını hiç içermeyebiliyor ve sonuç boş
		 * liste oluyor — panel de "No session has been opened to this
		 * host." yazıyordu.
		 *
		 * ÖLÇÜLDÜ, gerçek PostgreSQL ile: web01'de 1 gerçek oturum,
		 * başka bir hedefte 200 daha yeni oturum → cevap
		 * `recent_sessions: []`, hiçbir hata alanı yok. Yani "hiç
		 * bağlanılmamış" diye okunan bir cümle, bağlanılmış bir hedef
		 * için yazılıyordu.
		 *
		 * Sınırın "panelde yazılı" olduğunu söyleyen yorum da yanlıştı:
		 * ekranda buna dair tek kelime yoktu (grep'lendi).
		 *
		 * Bayrak yalnızca pencere DOLDUĞUNDA anlamlı: daha az satır
		 * döndüyse gerçekten hepsini gördük ve nitelemek, uyarıyı
		 * okunmaz yapardı.
		 */
		recentPartial = len(sessions) >= sessionScanLimit
	}

	writeJSON(w, http.StatusOK, struct {
		Name        string            `json:"name"`
		Host        string            `json:"host"`
		Port        int               `json:"port"`
		Fingerprint string            `json:"fingerprint"`
		Labels      map[string]string `json:"labels"`
		Facts       factsOut          `json:"facts"`
		GrantedBy   []string          `json:"granted_by"`
		Recent      []sessionRow      `json:"recent_sessions"`
		// recent_error: liste okunamadı. Boş listeyle karıştırılmamalı
		// — "dokunulmadı" ile "bakamadık" farklı şeyler.
		RecentErr bool `json:"recent_error,omitempty"`
		// recent_partial: tarama penceresi doldu, yani bu hedefin daha
		// eski oturumları pencerenin dışında kalmış olabilir. Boş bir
		// liste bu bayrakla birlikte "hiç yok" DEMİYOR.
		RecentPartial bool `json:"recent_partial,omitempty"`
		// recent_scanned: pencerenin büyüklüğü. Ekranın cümlesi somut
		// bir sayı söyleyebilsin diye gidiyor — "son 200 kayıt içinde"
		// ile "hiç" arasındaki fark operatörün kararını değiştiriyor.
		RecentScanned int `json:"recent_scanned,omitempty"`
	}{
		Name:          t.Name,
		Host:          t.Host,
		Port:          t.Port,
		Fingerprint:   fingerprintOf(t),
		Labels:        labels,
		Facts:         toFactsOut(facts),
		GrantedBy:     granting,
		Recent:        recent,
		RecentErr:     recentErr,
		RecentPartial: recentPartial,
		RecentScanned: sessionScanLimit,
	})
}

// sessionScanLimit, hedefe ait oturumları ararken taranan satır sayısı.
//
// Sunucuda "şu hedefin oturumları" diye bir sorgu yok ve eklemek yeni
// bir indeks + yeni bir uç demekti; şimdilik son N oturum taranıp
// süzülüyor.
//
// ⚠️ SINIR CEVAPTA TAŞINIYOR (recent_partial / recent_scanned) ve panel
// onu YAZIYOR. Bu yorum eskiden "sınır panelde yazılı" diyordu ve
// yazmıyordu: ekranda buna dair tek kelime yoktu. Sessizce kırpılmış
// bir denetim listesi, operatöre "olan biten bu kadar" dedirtir.
const sessionScanLimit = 200

// targetSessionRows, hedef sayfasında gösterilen oturum sayısı.
const targetSessionRows = 10

type factsOut struct {
	ServerVersion string `json:"server_version,omitempty"`
	HostKeyType   string `json:"host_key_type,omitempty"`
	LastSeenAt    string `json:"last_seen_at,omitempty"`
	ConnectMS     int    `json:"connect_ms,omitempty"`
	LastErrorAt   string `json:"last_error_at,omitempty"`
	LastError     string `json:"last_error,omitempty"`

	// Aşağıdakiler yalnızca target_probe.enabled ile dolar — yani
	// hedefte komut çalıştırıldıysa. ProbedAt boşsa hedefe dokunulmadı
	// ve panel bunu AYRI söylüyor: "bilmiyoruz" ile "sormadık" farklı.
	Kernel   string `json:"kernel,omitempty"`
	OSName   string `json:"os_name,omitempty"`
	ProbedAt string `json:"probed_at,omitempty"`
}

func toFactsOut(f model.TargetFacts) factsOut {
	out := factsOut{
		ServerVersion: f.ServerVersion,
		HostKeyType:   f.HostKeyType,
		ConnectMS:     f.ConnectMS,
		LastError:     f.LastError,
		Kernel:        f.Probe.Kernel,
		OSName:        f.Probe.OSName,
	}
	if !f.ProbedAt.IsZero() {
		out.ProbedAt = f.ProbedAt.Format(time.RFC3339)
	}
	if !f.LastSeenAt.IsZero() {
		out.LastSeenAt = f.LastSeenAt.Format(time.RFC3339)
	}
	if !f.LastErrorAt.IsZero() {
		out.LastErrorAt = f.LastErrorAt.Format(time.RFC3339)
	}
	return out
}

// fingerprintOf, saklanan authorized_keys satırından parmak izi.
func fingerprintOf(t model.Target) string {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(t.HostKey))
	if err != nil {
		// Ayrıştırılamayan anahtar SESSİZ KALMAMALI: hedef zaten
		// bağlanılamaz durumda ve boş bir hücre bunu gizlerdi.
		return "(invalid key)"
	}
	return ssh.FingerprintSHA256(pub)
}

/*
 * adminScanTarget, bir adresteki makinenin SUNDUĞU host key'i getirir.
 *
 * ⚠️ DÖNEN ANAHTAR GÜVENİLİR DEĞİL ve bu uç öyle davranmıyor: hiçbir şey
 * kaydetmiyor, hiçbir hedefi değiştirmiyor. Yalnızca "o adreste şu anda
 * cevap veren makine bu anahtarı sunuyor" diyor. Güveni kuran adım
 * panelde: parmak izi operatöre gösteriliyor ve makinenin kendisiyle
 * karşılaştırdığını AÇIKÇA onaylaması isteniyor (TOFU).
 *
 * Neden yine de değerli: yapıştırmalı akış da aynı TOFU'ydu — operatör
 * `ssh-keyscan`i çoğu zaman aynı ağdan çalıştırıp yapıştırıyordu. Bu
 * akış yazım hatasını ve alanı boş bırakma cazibesini kaldırıyor.
 */
func (s *Server) adminScanTarget(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Host) == "" {
		writeErr(w, http.StatusBadRequest, "host is required")
		return
	}
	if in.Port <= 0 || in.Port > 65535 {
		writeErr(w, http.StatusBadRequest, "port must be between 1 and 65535")
		return
	}

	key, err := upstream.ScanHostKey(r.Context(), in.Host, in.Port)
	if err != nil {
		// ⚠️ Sebep OPERATÖRE GÖSTERİLİYOR: "bağlanamadım" ile "SSH
		// konuşmuyor" ile "ad çözülmedi" farklı sorunlar ve hepsini tek
		// bir "failed" altına toplamak, kurulum yapan kişiyi karanlıkta
		// bırakırdı. İçerik hedefin adresine dair; sır taşımıyor.
		s.logger.Warn("host key scan failed", "host", in.Host, "port", in.Port, "error", err)
		writeErr(w, http.StatusBadGateway, "could not read a host key from "+
			net.JoinHostPort(in.Host, strconv.Itoa(in.Port))+": "+err.Error())
		return
	}

	// Aynı adres başka bir anahtarla zaten kayıtlıysa SÖYLE. Sessiz
	// kalmak, anahtarı dönmüş (ya da taklit edilen) bir makineyi ikinci
	// kez kaydettirirdi.
	//
	// ⚠️ TÜR FARKI İLE ANAHTAR FARKI AYRI ŞEYLER. İlk hâl yalnızca
	// parmak izlerini karşılaştırıyordu ve aynı makinenin ed25519 yerine
	// ecdsa anahtarı geldiğinde "bu düşündüğünüz makine değil" diyordu —
	// gerçek bir alarmı, sık görülen ve masum bir durumla aynı sesle
	// vermek, alarmı işe yaramaz yapar.
	conflict, conflictKind := "", ""
	if targets, terr := s.store.Targets(r.Context()); terr == nil {
		for _, t := range targets {
			if t.Host != in.Host || t.Port != in.Port {
				continue
			}
			if fingerprintOf(t) == ssh.FingerprintSHA256(key) {
				continue
			}
			conflict = t.Name
			conflictKind = "different-key"
			if pub, _, _, _, perr := ssh.ParseAuthorizedKey([]byte(t.HostKey)); perr == nil &&
				pub.Type() != key.Type() {
				conflictKind = "different-type"
			}
		}
	}

	writeJSON(w, http.StatusOK, struct {
		KeyType       string `json:"key_type"`
		Fingerprint   string `json:"fingerprint"`
		AuthorizedKey string `json:"authorized_key"`
		KeyFile       string `json:"key_file,omitempty"`
		ConflictsWith string `json:"conflicts_with,omitempty"`
		ConflictKind  string `json:"conflict_kind,omitempty"`
	}{
		KeyType:       key.Type(),
		Fingerprint:   ssh.FingerprintSHA256(key),
		AuthorizedKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))),
		// Doğrulama komutunun dosya adı SUNUCUDA türetiliyor: istemcide
		// tür adından uydurmak "ssh_host_ecdsa-sha2-nistp256_key.pub"
		// gibi var olmayan yollar üretiyordu.
		KeyFile:       sshalg.HostKeyFile(key.Type()),
		ConflictsWith: conflict,
		ConflictKind:  conflictKind,
	})
}

/*
 * handleMyTargetDetail: GET /api/targets/{name}
 *
 * ⚠️ HOST/PORT YOK — kart ucundaki gerekçenin aynısı: sıradan kullanıcı
 * hedefe postern üzerinden bağlanıyor ve adresini bilmesi gerekmiyor.
 * Adresi vermek, bir bastion'ın varlık sebebi olan "ağ topolojisini
 * kullanıcıya açmama" özelliğini panelden sızdırırdı.
 *
 * ⚠️ OTURUMLAR YALNIZCA KENDİSİNİN. Aynı hedefe başkalarının ne zaman
 * bağlandığı bir denetim sorusu ve yönetici ekranında duruyor; burada
 * göstermek, sıradan bir kullanıcıya meslektaşlarının çalışma saatlerini
 * verirdi.
 */
func (s *Server) handleMyTargetDetail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	me := sessionUser(r)

	u, err := s.store.User(r.Context(), me)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.clearSessionCookie(w)
			writeErr(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		s.storeErr(w, "targets.mine.detail", err)
		return
	}

	var allowed bool
	for _, role := range u.Roles {
		for _, t := range role.Targets {
			if strings.EqualFold(t, name) {
				allowed = true
			}
		}
	}
	/*
	 * ⚠️ 404, 403 DEĞİL — ve var olmayan hedefle aynı cevap.
	 *
	 * "Bu hedef var ama sana kapalı" demek, adları tek tek deneyen
	 * birine envanteri çıkarma imkânı verir. Erişimi olmayan için
	 * hedefin varlığı da bir bilgi.
	 */
	if !allowed {
		writeErr(w, http.StatusNotFound, "no such target")
		return
	}

	tgt, terr := s.store.Target(r.Context(), name)
	if terr != nil {
		if errors.Is(terr, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "no such target")
			return
		}
		s.storeErr(w, "targets.mine.detail", terr)
		return
	}

	facts, _ := s.store.TargetFacts(r.Context(), tgt.Name)

	/*
	 * Kullanıcının BU hedefteki oturumları.
	 *
	 * Sessions kullanıcıya göre süzülüyor, hedef burada eleniyor:
	 * depoda hedefe göre süzen bir sorgu yok ve tek kullanıcının
	 * geçmişi için ikinci bir indeks açmaya değmez.
	 */
	type sessionRow struct {
		ID      string `json:"id"`
		Started string `json:"started"`
		Ended   string `json:"ended,omitempty"`
		OSUser  string `json:"os_user"`
	}
	rows := make([]sessionRow, 0, 8)
	// ⚠️ Aşağıdaki else dalı bunu zaten log'a yazıyordu; eksik olan,
	// aynı ayrımın CEVAPTA da olmasıydı. Log'a yazılan bir uyarı
	// kullanıcının ekranında görünmüyor.
	sessionsErr := false
	sessionsPartial := false
	if all, serr := s.store.Sessions(r.Context(), me, sessionScanLimit); serr == nil {
		for _, sn := range all {
			if !strings.EqualFold(sn.Target, tgt.Name) {
				continue
			}
			row := sessionRow{
				ID:      sn.ID,
				Started: sn.StartedAt.UTC().Format(time.RFC3339),
				OSUser:  sn.OSUser,
			}
			if !sn.EndedAt.IsZero() {
				row.Ended = sn.EndedAt.UTC().Format(time.RFC3339)
			}
			rows = append(rows, row)
			if len(rows) == 10 {
				break
			}
		}
		// ⚠️ PENCERE DOLDUYSA "HİÇ BAĞLANMADIN" DEME. adminTargetDetail
		// ile aynı: tarama tüm hedeflerin son N oturumuna bakıp süzüyor,
		// bu hedefin oturumları pencerenin dışında kalmış olabilir.
		sessionsPartial = len(all) >= sessionScanLimit
	} else {
		// Geçmiş okunamadı: detayı düşürmüyoruz ama sessiz de
		// geçmiyoruz — boş liste "hiç bağlanmadın" demek, "bakamadık"
		// demek değil.
		s.logger.Error("own session history unavailable",
			"user", me, "target", tgt.Name, "error", serr)
		sessionsErr = true
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"name":           tgt.Name,
		"labels":         tgt.Labels,
		"server_version": facts.ServerVersion,
		"last_seen_at":   stampOrEmpty(facts.LastSeenAt),
		"sessions":       rows,
		// sessions_error: geçmiş okunamadı. Boş listeyle
		// karıştırılmamalı.
		"sessions_error": sessionsErr,
		// sessions_partial: tarama penceresi doldu; boş liste "hiç
		// bağlanmadın" demek değil.
		"sessions_partial": sessionsPartial,
		"sessions_scanned": sessionScanLimit,
	})
}
