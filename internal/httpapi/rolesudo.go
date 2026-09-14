package httpapi

/*
 * Rolün sudo kuralı: panelden okumak, yazmak, kaldırmak.
 *
 * ⚠️ KURAL ROLÜN, HAKKIN DEĞİL. Hak başına kural /api/admin/.../grants
 * gövdesinde gidiyor ve hedefte hesabın dosyasına yazılıyor; burası rolün
 * grubuna yazılan kural. İkisi aynı sudoers.Rule biçimini taşıyor, bu
 * yüzden panel tek bir yazım kutusu ve tek bir onay kutusu kullanabiliyor.
 */

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/sudoers"
)

func (s *Server) registerRoleSudoRoutes(mux *http.ServeMux) {
	admin := func(h http.HandlerFunc) http.Handler {
		return noStore(s.requireSession(s.requireAdmin(s.sameOrigin(h))))
	}
	mux.Handle("GET /api/admin/roles/{name}/sudo", admin(s.adminRoleSudo))
	mux.Handle("PUT /api/admin/roles/{name}/sudo", admin(s.adminSetRoleSudo))
	mux.Handle("DELETE /api/admin/roles/{name}/sudo", admin(s.adminDeleteRoleSudo))
}

// sudoRuleView, kuralın panele giden hâli. Komutlar tek satırlık
// dizeler: panel onları olduğu gibi yazım kutusuna koyuyor.
type sudoRuleView struct {
	RunAs        string    `json:"run_as,omitempty"`
	Commands     []string  `json:"commands"`
	Acknowledged bool      `json:"acknowledged"`
	UpdatedBy    string    `json:"updated_by"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func sudoView(rs store.RoleSudo) sudoRuleView {
	out := sudoRuleView{
		RunAs: rs.Rule.RunAs, Acknowledged: rs.Rule.Acknowledged,
		UpdatedBy: rs.UpdatedBy, UpdatedAt: rs.UpdatedAt,
		Commands: make([]string, 0, len(rs.Rule.Commands)),
	}
	for _, c := range rs.Rule.Commands {
		out.Commands = append(out.Commands, c.String())
	}

	return out
}

// sudoRuleInput, panelin gönderdiği kural. Grant gövdesiyle aynı şekil.
type sudoRuleInput struct {
	RunAs    string `json:"run_as"`
	Commands []struct {
		Path string   `json:"path"`
		Args []string `json:"args"`
	} `json:"commands"`
	Acknowledged bool `json:"acknowledged"`
}

func (in sudoRuleInput) rule() sudoers.Rule {
	r := sudoers.Rule{RunAs: strings.TrimSpace(in.RunAs), Acknowledged: in.Acknowledged}
	for _, c := range in.Commands {
		if p := strings.TrimSpace(c.Path); p != "" {
			r.Commands = append(r.Commands, sudoers.Command{Path: p, Args: c.Args})
		}
	}

	return r
}

// adminRoleSudo: GET /api/admin/roles/{name}/sudo
func (s *Server) adminRoleSudo(w http.ResponseWriter, r *http.Request) {
	rs, err := s.store.RoleSudoRule(r.Context(), r.PathValue("name"))
	if err != nil {
		s.storeErr(w, "role.sudo", err)
		return
	}
	writeJSON(w, http.StatusOK, sudoView(rs))
}

/*
 * adminSetRoleSudo: PUT /api/admin/roles/{name}/sudo
 *
 * ⚠️ RET METNİ OLDUĞU GİBİ GİDİYOR. Kaçış riski taşıyan bir kural 422 ile
 * dönüyor ve sebebi (hangi komut, neden) cevabın içinde: operatör onay
 * kutusunu bilerek işaretleyecekse neyi onayladığını görmek zorunda.
 */
func (s *Server) adminSetRoleSudo(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var in sudoRuleInput
	if !readJSON(w, r, &in) {
		return
	}
	rule := in.rule()
	if err := s.store.SetRoleSudo(r.Context(), name, rule, sessionUser(r)); err != nil {
		if errors.Is(err, store.ErrInvalid) {
			writeErr(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		s.storeErr(w, "role.sudo_set", err)
		return
	}
	detail := describeRule(rule)
	if rule.Acknowledged {
		detail += "; acknowledged as a way out to a root shell"
	}
	s.audit(r, "role.sudo_set", name, detail)
	ok(w)
}

/*
 * adminDeleteRoleSudo: DELETE /api/admin/roles/{name}/sudo
 *
 * ⚠️ HEDEFTEKİ DOSYA BUNUNLA GİTMİYOR ve cevap bunu söylüyor. Kural
 * postern'de siliniyor; makinelerdeki /etc/sudoers.d/postern-<rol>
 * postern o hedefe bir daha dokunana kadar duruyor. "Sildim" diyen ama
 * yetkiyi kaldırmayan bir ekran, olmayan bir korumaya güvendirir.
 */
func (s *Server) adminDeleteRoleSudo(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.store.DeleteRoleSudo(r.Context(), name); err != nil {
		s.storeErr(w, "role.sudo_delete", err)
		return
	}
	s.audit(r, "role.sudo_delete", name,
		"the rule is gone from postern; the file on hosts is replaced the next time postern touches them")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"note": "The rule no longer exists in postern. On hosts that already have " +
			"/etc/sudoers.d/postern-" + name + ", the file stays until postern next works on them.",
	})
}

// describeRule, denetim satırı için kısa özet. Komutlar yazılıyor: "bir
// kural verildi" cümlesi, neyin verildiğini söylemiyor.
func describeRule(r sudoers.Rule) string {
	runAs := r.RunAs
	if runAs == "" {
		runAs = "root"
	}
	cmds := make([]string, 0, len(r.Commands))
	for _, c := range r.Commands {
		cmds = append(cmds, c.String())
	}

	return "as " + runAs + ": " + strings.Join(cmds, ", ")
}
