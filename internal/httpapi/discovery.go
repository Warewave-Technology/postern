package httpapi

/*
 * Panelden keşif: kaynaklar, koşular, bulunan makineler ve onları hedefe
 * çevirme.
 *
 * ⚠️ SIR HİÇBİR CEVAPTA YOK. Kaynak yazılırken sır gövdede geliyor,
 * store onu mühürleyip saklıyor ve buradan yalnızca "kayıtlı mı" biti
 * dönüyor (store.DiscoverySource'un kendisinde sır alanı yok). Güncelleme
 * gövdesinde sır boşsa "değiştirmedim" demek.
 *
 * ⚠️ MAKİNE KAYDI ERİŞİM VERİYOR (hedef + grup bağı), yani POST ve
 * sameOrigin; koşu başlatma da öyle — hipervizöre ve her makinenin
 * sshd'sine bağlanan bir iş bir <img> etiketiyle tetiklenmemeli.
 */

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Warewave-Technology/postern/internal/discover"
	"github.com/Warewave-Technology/postern/internal/store"
)

// UseDiscovery, keşif hizmetini bağlar. Dinlemeye başlamadan ÖNCE.
func (s *Server) UseDiscovery(svc *discover.Service) { s.discovery = svc }

func (s *Server) registerDiscoveryRoutes(mux *http.ServeMux) {
	if s.discovery == nil {
		return
	}
	admin := func(h http.HandlerFunc) http.Handler {
		return noStore(s.requireSession(s.requireAdmin(s.sameOrigin(h))))
	}
	mux.Handle("GET /api/admin/discovery", admin(s.adminDiscovery))
	mux.Handle("POST /api/admin/discovery/sources", admin(s.adminCreateDiscoverySource))
	mux.Handle("POST /api/admin/discovery/test", admin(s.adminTestDiscoverySource))
	mux.Handle("PUT /api/admin/discovery/sources/{id}", admin(s.adminUpdateDiscoverySource))
	mux.Handle("DELETE /api/admin/discovery/sources/{id}", admin(s.adminDeleteDiscoverySource))
	mux.Handle("POST /api/admin/discovery/sources/{id}/run", admin(s.adminRunDiscoverySource))
	mux.Handle("GET /api/admin/discovery/sources/{id}/runs", admin(s.adminDiscoveryRuns))
	mux.Handle("POST /api/admin/discovery/register", admin(s.adminRegisterDiscovered))
	mux.Handle("POST /api/admin/discovery/ignore", admin(s.adminIgnoreDiscovered))
}

// discoverySourceView, kaynak + son koşusu + bu süreçte koşuyor mu.
type discoverySourceView struct {
	store.DiscoverySource
	LastRun *store.DiscoveryRun `json:"last_run,omitempty"`
	Running bool                `json:"running"`
}

// discoveredMachineView, paneldeki makine satırı.
type discoveredMachineView struct {
	SourceID string   `json:"source_id"`
	Source   string   `json:"source"`
	Ref      string   `json:"ref"`
	Name     string   `json:"name"`
	Host     string   `json:"host"`
	Tags     []string `json:"tags"`
	Running  bool     `json:"running"`
	Group    string   `json:"group,omitempty"`
	// Fingerprint, koşunun okuduğu anahtarın parmak izi; okunamadıysa boş.
	Fingerprint  string `json:"fingerprint,omitempty"`
	Problem      string `json:"problem,omitempty"`
	Target       string `json:"target,omitempty"`
	Ignored      bool   `json:"ignored"`
	FirstSeen    string `json:"first_seen"`
	LastSeen     string `json:"last_seen"`
	MissingSince string `json:"missing_since,omitempty"`
}

func machineView(m store.DiscoveredMachine) discoveredMachineView {
	v := discoveredMachineView{
		SourceID: m.SourceID, Source: m.Source, Ref: m.Ref, Name: m.Name, Host: m.Host,
		Tags: m.Tags, Running: m.Running, Group: m.Group, Problem: m.Problem, Target: m.Target,
		Ignored: m.Ignored, FirstSeen: m.FirstSeen.Format(time.RFC3339),
		LastSeen: m.LastSeen.Format(time.RFC3339),
	}
	if v.Tags == nil {
		v.Tags = []string{}
	}
	if m.HostKey != "" {
		v.Fingerprint = discover.Fingerprint(m.HostKey)
	}
	if !m.MissingSince.IsZero() {
		v.MissingSince = m.MissingSince.Format(time.RFC3339)
	}
	return v
}

// adminDiscovery: GET /api/admin/discovery — ekranın tek isteği.
func (s *Server) adminDiscovery(w http.ResponseWriter, r *http.Request) {
	sources, err := s.store.DiscoverySources(r.Context())
	if err != nil {
		s.storeErr(w, "discovery.list", err)
		return
	}
	latest, err := s.store.LatestDiscoveryRuns(r.Context())
	if err != nil {
		s.storeErr(w, "discovery.list", err)
		return
	}
	machines, err := s.store.DiscoveredMachines(r.Context(), "")
	if err != nil {
		s.storeErr(w, "discovery.list", err)
		return
	}
	views := make([]discoverySourceView, 0, len(sources))
	for _, src := range sources {
		v := discoverySourceView{DiscoverySource: src, Running: s.discovery.Running(src.ID)}
		if run, ok := latest[src.ID]; ok {
			v.LastRun = &run
		}
		views = append(views, v)
	}
	mviews := make([]discoveredMachineView, 0, len(machines))
	for _, m := range machines {
		mviews = append(mviews, machineView(m))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sources": views, "machines": mviews,
		// secrets_available: sır mühürleyen anahtar yoksa kaynak
		// kaydedilemez; panel formu açmadan söylüyor.
		"secrets_available":    s.store.SecretsAvailable(),
		"min_interval_seconds": int(discover.MinInterval / time.Second),
	})
}

// sourceInput, kaynak yazma gövdesi.
type sourceInput struct {
	Name            string `json:"name"`
	Kind            string `json:"kind"`
	URL             string `json:"url"`
	Username        string `json:"username"`
	Secret          string `json:"secret"`
	CAPEM           string `json:"ca_pem"`
	Insecure        bool   `json:"insecure"`
	Node            string `json:"node"`
	TagKey          string `json:"tag_key"`
	NamePattern     string `json:"name_pattern"`
	Port            int    `json:"port"`
	IntervalSeconds int    `json:"interval_seconds"`
	Enabled         *bool  `json:"enabled"`
}

func (in sourceInput) source() store.DiscoverySource {
	d := store.DiscoverySource{
		Name: strings.TrimSpace(in.Name), Kind: in.Kind, URL: strings.TrimSpace(in.URL),
		Username: strings.TrimSpace(in.Username), CAPEM: strings.TrimSpace(in.CAPEM),
		Insecure: in.Insecure, Node: strings.TrimSpace(in.Node), TagKey: strings.TrimSpace(in.TagKey),
		NamePattern: strings.TrimSpace(in.NamePattern), Port: in.Port,
		IntervalSeconds: in.IntervalSeconds, Enabled: in.Enabled == nil || *in.Enabled,
	}
	if d.Port == 0 {
		d.Port = 22
	}
	return d
}

// discoveryErr, store/hizmet hatasını cevaba çevirir: geçersiz girdi 400,
// gerisi storeErr'in bildiği gibi.
func (s *Server) discoveryErr(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, store.ErrInvalid):
		writeErr(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, discover.ErrRunning):
		writeErr(w, http.StatusConflict, err.Error())
	default:
		s.storeErr(w, op, err)
	}
}

func sourceDetails(d store.DiscoverySource) string {
	sched := "runs only when asked"
	if d.IntervalSeconds > 0 {
		sched = "every " + (time.Duration(d.IntervalSeconds) * time.Second).String()
	}
	tls := "verifying TLS"
	if d.Insecure {
		tls = "TLS VERIFICATION OFF"
	}
	return d.Kind + " " + d.URL + " as " + d.Username + ", tag key " + d.TagKey + ", " + sched + ", " + tls
}

// adminCreateDiscoverySource: POST /api/admin/discovery/sources
func (s *Server) adminCreateDiscoverySource(w http.ResponseWriter, r *http.Request) {
	var in sourceInput
	if !readJSON(w, r, &in) {
		return
	}
	d := in.source()
	d.CreatedBy = sessionUser(r)
	if err := discover.ValidateSource(d, in.Secret, true); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := s.store.CreateDiscoverySource(r.Context(), d, in.Secret)
	if err != nil {
		s.discoveryErr(w, "discovery.source_create", err)
		return
	}
	s.audit(r, "discovery.source_create", d.Name, sourceDetails(d))
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

/*
 * adminTestDiscoverySource: POST /api/admin/discovery/test — formdaki
 * değerlerle kaynağa bağlanır ve saydığını döner; HİÇBİR ŞEY YAZMAZ.
 * id doluysa ve sır boşsa kayıtlı sır kullanılıyor: düzenleme ekranı
 * sırrı hiç görmüyor, "kayıtlı sırla dene" demenin başka yolu yok.
 */
func (s *Server) adminTestDiscoverySource(w http.ResponseWriter, r *http.Request) {
	var in struct {
		sourceInput
		ID string `json:"id"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	d := in.source()
	secret := in.Secret
	if secret == "" && in.ID != "" {
		cur, err := s.store.DiscoverySource(r.Context(), in.ID)
		if err != nil {
			s.storeErr(w, "discovery.test", err)
			return
		}
		d.Kind = cur.Kind
		if secret, err = s.store.DiscoverySourceSecret(r.Context(), in.ID); err != nil {
			s.storeErr(w, "discovery.test", err)
			return
		}
	}
	if err := discover.ValidateSource(d, secret, true); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p, err := s.discovery.Probe(r.Context(), d, secret)
	s.logger.Info("discovery source tested", "actor", sessionUser(r), "kind", d.Kind, "url", d.URL, "ok", err == nil)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// adminUpdateDiscoverySource: PUT /api/admin/discovery/sources/{id}
func (s *Server) adminUpdateDiscoverySource(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cur, err := s.store.DiscoverySource(r.Context(), id)
	if err != nil {
		s.storeErr(w, "discovery.source_update", err)
		return
	}
	var in sourceInput
	if !readJSON(w, r, &in) {
		return
	}
	d := in.source()
	d.ID, d.Kind, d.CreatedBy = cur.ID, cur.Kind, cur.CreatedBy
	if err := discover.ValidateSource(d, in.Secret, false); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.UpdateDiscoverySource(r.Context(), d, in.Secret); err != nil {
		s.discoveryErr(w, "discovery.source_update", err)
		return
	}
	details := sourceDetails(d)
	if in.Secret != "" {
		details += ", credentials replaced"
	}
	s.audit(r, "discovery.source_update", d.Name, details)
	ok(w)
}

// adminDeleteDiscoverySource: DELETE /api/admin/discovery/sources/{id}
// Hedefler KALIYOR: kaynağı silmek envanteri silmek değil.
func (s *Server) adminDeleteDiscoverySource(w http.ResponseWriter, r *http.Request) {
	name, err := s.store.DeleteDiscoverySource(r.Context(), r.PathValue("id"))
	if err != nil {
		s.storeErr(w, "discovery.source_delete", err)
		return
	}
	s.audit(r, "discovery.source_delete", name, "its discovered machines were dropped; targets stay")
	ok(w)
}

// adminRunDiscoverySource: POST /api/admin/discovery/sources/{id}/run —
// koşu arka planda; 202 "başladı" demek, "bitti" değil.
func (s *Server) adminRunDiscoverySource(w http.ResponseWriter, r *http.Request) {
	if err := s.discovery.RunNow(r.Context(), r.PathValue("id"), sessionUser(r)); err != nil {
		s.discoveryErr(w, "discovery.run", err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"started": true})
}

// adminDiscoveryRuns: GET /api/admin/discovery/sources/{id}/runs
func (s *Server) adminDiscoveryRuns(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.store.DiscoverySource(r.Context(), id); err != nil {
		s.storeErr(w, "discovery.runs", err)
		return
	}
	runs, err := s.store.DiscoveryRuns(r.Context(), id, 50)
	if err != nil {
		s.storeErr(w, "discovery.runs", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": runs})
}

// adminRegisterDiscovered: POST /api/admin/discovery/register
func (s *Server) adminRegisterDiscovered(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Machines  []discover.MachineRef `json:"machines"`
		Groups    []string              `json:"groups"`
		TagGroups bool                  `json:"tag_roles"`
		Labels    map[string]string     `json:"labels"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	out, err := s.discovery.Register(r.Context(), discover.RegisterRequest{
		Machines: in.Machines, Groups: in.Groups, TagGroups: in.TagGroups, Labels: in.Labels,
		Actor: sessionUser(r),
	})
	if err != nil {
		// Yarım kalan parti de cevapta: hangi makinelerin yazıldığı,
		// hatanın kendisi kadar önemli.
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrInvalid) {
			status = http.StatusBadRequest
		} else {
			s.logger.Error("registering discovered machines failed", "error", err)
		}
		writeJSON(w, status, map[string]any{"error": err.Error(), "results": out})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": out})
}

// adminIgnoreDiscovered: POST /api/admin/discovery/ignore
func (s *Server) adminIgnoreDiscovered(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Machines []discover.MachineRef `json:"machines"`
		Ignored  bool                  `json:"ignored"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	n, err := s.discovery.SetIgnored(r.Context(), in.Machines, in.Ignored, sessionUser(r))
	if err != nil {
		s.storeErr(w, "discovery.ignore", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"changed": n})
}
