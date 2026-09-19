package httpapi

/*
 * Panelden geçici erişim: bir hedefte süreli hesap açmak, listelemek ve
 * geri almak.
 *
 * ⚠️ UÇLAR YALNIZCA YÖNETİM AÇIKKEN KURULUYOR (manage.enabled) — yönetim
 * denetimiyle aynı kapı, aynı gerekçe: kapalı özellik, kapalı yüzey.
 * Root'la iş yapan her uç POST ve sameOrigin; hedefe giden her komut
 * provision'ın planından geçiyor, burada komut kurulmuyor.
 */

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Warewave-Technology/postern/v2/internal/jit"
	"github.com/Warewave-Technology/postern/v2/internal/provision"
	"github.com/Warewave-Technology/postern/v2/internal/store"
	"github.com/Warewave-Technology/postern/v2/internal/sudoers"
)

// UseJIT, geçici erişim hizmetini bağlar. Dinlemeye başlamadan ÖNCE.
func (s *Server) UseJIT(svc *jit.Service) { s.jit = svc }

func (s *Server) registerJITRoutes(mux *http.ServeMux) {
	if s.jit == nil {
		return
	}
	admin := func(h http.HandlerFunc) http.Handler {
		return noStore(s.requireSession(s.requireAdmin(s.sameOrigin(h))))
	}
	mux.Handle("GET /api/admin/grants", admin(s.adminListAllGrants))
	mux.Handle("GET /api/admin/targets/{name}/grants", admin(s.adminListGrants))
	mux.Handle("POST /api/admin/targets/{name}/grants", admin(s.adminCreateGrant))
	mux.Handle("POST /api/admin/grants/{id}/revoke", admin(s.adminRevokeGrant))
}

// grantStep, panelin çizdiği tek bir adım.
type grantStep struct {
	Kind    string `json:"kind"`
	Command string `json:"command"`
	Why     string `json:"why"`
	Outcome string `json:"outcome"`
	Output  string `json:"output,omitempty"`
	Error   string `json:"error,omitempty"`
}

func stepsOf(rep provision.Report) []grantStep {
	out := make([]grantStep, 0, len(rep.Results))
	for _, r := range rep.Results {
		st := grantStep{
			Kind: string(r.Step.Kind), Command: r.Step.Command, Why: r.Step.Why,
			Outcome: string(r.Outcome), Output: r.Output,
		}
		if r.Err != nil {
			st.Error = r.Err.Error()
		}
		out = append(out, st)
	}

	return out
}

// adminListAllGrants: GET /api/admin/grants — bütün hedefler, en yeni önce.
// Sekmenin sorusu "kimin nerede açık hesabı var"; hedef başına liste bu
// soruyu N tıklamaya bölerdi.
func (s *Server) adminListAllGrants(w http.ResponseWriter, r *http.Request) {
	grants, err := s.store.JITGrants(r.Context(), 200)
	if err != nil {
		s.storeErr(w, "grants.list", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"grants": grants, "now": time.Now().UTC()})
}

// adminListGrants: GET /api/admin/targets/{name}/grants
func (s *Server) adminListGrants(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, err := s.store.Target(r.Context(), name); err != nil {
		s.storeErr(w, "grants.list", err)
		return
	}
	grants, err := s.store.JITGrantsForTarget(r.Context(), name, 50)
	if err != nil {
		s.storeErr(w, "grants.list", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"grants": grants, "now": time.Now().UTC()})
}

// adminCreateGrant: POST /api/admin/targets/{name}/grants
func (s *Server) adminCreateGrant(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	var in struct {
		Username string   `json:"username"`
		Groups   []string `json:"groups"`
		Duration string   `json:"duration"`
		/*
		 * ⚠️ GÖVDE ROLÜN KURALIYLA AYNI ŞEKİL (sudoRuleInput) — kopya
		 * değil, aynı tip.
		 *
		 * ÖLÇÜLDÜ: buradaki kopya komut başına hesabı TAŞIMIYORDU, yani
		 * panel "pg_ctl reload"u postgres olarak veremiyor, verebildiği
		 * tek şey root oluyordu. Dar seçeneği sunmayan bir ekran geniş
		 * olanı yazdırır — ve geçici hak tam da dar yetki vermek için
		 * var. İki uç tek tipi paylaşınca alanın birinde olup öbüründe
		 * olmaması diye bir durum kalmıyor.
		 */
		Sudo *sudoRuleInput `json:"sudo"`
		// cleanup_groups yoksa evet: geri almada boş kalan açılmış gruplar
		// silinir. Panel onay kutusunu bu varsayılanla çiziyor.
		CleanupGroups *bool `json:"cleanup_groups"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if in.Username == "" {
		writeErr(w, http.StatusBadRequest, "username is required")
		return
	}
	dur, err := time.ParseDuration(strings.TrimSpace(in.Duration))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "duration must look like 2h or 30m")
		return
	}
	groups := make([]string, 0, len(in.Groups))
	for _, g := range in.Groups {
		if g = strings.TrimSpace(g); g != "" {
			groups = append(groups, g)
		}
	}

	req := jit.Request{
		Username: in.Username, Target: name, Groups: groups, Duration: dur,
		CleanupGroups: in.CleanupGroups == nil || *in.CleanupGroups,
	}
	if in.Sudo != nil {
		rule := in.Sudo.rule()
		/*
		 * ⚠️ KURAL BURADA DA DOĞRULANIYOR, HEDEFE GİTMEDEN. Plan yine
		 * doğruluyor ama o noktada bağlantı açılmış, defter yazılmış oluyor;
		 * kaçış riski taşıyan bir kural için o kadarını harcamaya gerek yok
		 * ve cümle operatörün önüne 400 ile gelmeli, 502 ile değil.
		 */
		if findings := sudoers.Validate(rule); sudoers.Refuses(findings, rule.Acknowledged) {
			// Onay kutusunun görünüp görünmeyeceğini ekran buradan öğreniyor
			// (bkz. adminSetGroupSudo'daki aynı ayrım).
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error":           "sudo rule refused: " + sudoers.Describe(findings),
				"acknowledgeable": !sudoers.Refuses(findings, true),
			})
			return
		}
		req.Sudo = &rule
	}

	out, err := s.jit.Grant(r.Context(), req, sessionUser(r))
	if err != nil {
		s.grantErr(w, "grants.create", out, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"grant": out.Grant, "summary": out.Report.Summary(), "steps": stepsOf(out.Report),
	})
}

// adminRevokeGrant: POST /api/admin/grants/{id}/revoke
func (s *Server) adminRevokeGrant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	out, err := s.jit.Revoke(r.Context(), id, sessionUser(r), "web")
	if err != nil {
		s.grantErr(w, "grants.revoke", out, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"grant": out.Grant, "summary": out.Report.Summary(), "steps": stepsOf(out.Report),
		"sessions_closed": out.Terminated,
	})
}

/*
 * grantErr, bir grant/revoke hatasını cevaba çevirir.
 *
 * ⚠️ HEDEFTE OLAN ŞEY HATAYLA BİRLİKTE GİDİYOR. "1 applied, 1 failed, 2 not
 * attempted" diyen bir koşu makineyi yarım bıraktı; yalnızca "failed"
 * dönmek operatörden tam olarak bakması gereken şeyi saklardı. Sebep
 * metni de gidiyor: operatörün az önce yaptığı isteğe dair ve sır
 * taşımıyor.
 */
func (s *Server) grantErr(w http.ResponseWriter, op string, out jit.Outcome, err error) {
	status := http.StatusBadGateway
	switch {
	case errors.Is(err, store.ErrInvalid):
		status = http.StatusBadRequest
	case errors.Is(err, store.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, jit.ErrRevoked):
		status = http.StatusConflict
	case errors.Is(err, jit.ErrNotEnabled):
		status = http.StatusServiceUnavailable
	}
	if status == http.StatusBadGateway {
		s.logger.Warn("temporary access failed on the target", "op", op, "error", err)
	}
	body := map[string]any{"error": err.Error()}
	if out.Grant.ID != "" {
		body["grant"] = out.Grant
	}
	if len(out.Report.Results) > 0 {
		body["summary"] = out.Report.Summary()
		body["steps"] = stepsOf(out.Report)
	}
	writeJSON(w, status, body)
}
