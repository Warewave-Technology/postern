package httpapi

import (
	"errors"
	"net/http"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/model"
	"github.com/warewave/postern/internal/store"
)

// registerTargetRoutes, hedeflerle ilgili iki ucu bağlar.
func (s *Server) registerTargetRoutes(mux *http.ServeMux) {
	// ⚠️ ADMIN DEĞİL. Bu uç, oturum sahibinin KENDİ hedeflerini
	// döndürüyor ve ana ekranı besliyor. Yetki sınırı gövdede: liste
	// kullanıcının rollerinden türüyor, istemcinin sorduğundan değil.
	mux.Handle("GET /api/targets", noStore(s.requireSession(http.HandlerFunc(s.handleMyTargets))))

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
	// Boş kullanıcı adı = "hepsi" (bkz. store.Sessions).
	if sessions, serr := s.store.Sessions(r.Context(), "", sessionScanLimit); serr == nil {
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
	}{
		Name:        t.Name,
		Host:        t.Host,
		Port:        t.Port,
		Fingerprint: fingerprintOf(t),
		Labels:      labels,
		Facts:       toFactsOut(facts),
		GrantedBy:   granting,
		Recent:      recent,
	})
}

// sessionScanLimit, hedefe ait oturumları ararken taranan satır sayısı.
//
// Sunucuda "şu hedefin oturumları" diye bir sorgu yok ve eklemek yeni
// bir indeks + yeni bir uç demekti; şimdilik son N oturum taranıp
// süzülüyor. ⚠️ Sınır PANELDE YAZILI: sessizce kırpılmış bir denetim
// listesi, operatöre "olan biten bu kadar" dedirtir.
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
}

func toFactsOut(f model.TargetFacts) factsOut {
	out := factsOut{
		ServerVersion: f.ServerVersion,
		HostKeyType:   f.HostKeyType,
		ConnectMS:     f.ConnectMS,
		LastError:     f.LastError,
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
