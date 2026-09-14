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

/*
 * sudoCommandView, tek bir komut ve HANGİ HESAPLA çalıştığı.
 *
 * ⚠️ HESAP KOMUT BAŞINA. sudoers bunu taşıyor ve kural başına tek hesap,
 * "nginx'i root olarak sına, pg_ctl'i postgres olarak yeniden yükle"
 * diyen bir role iki ayrı kural yazdırırdı — oysa hedefte bir grubun tek
 * sudoers dosyası var. RunAs boş gitmiyor: ekran "root" yazabilsin diye
 * etkin değer hesaplanmış hâlde geliyor.
 */
type sudoCommandView struct {
	Command string `json:"command"`
	RunAs   string `json:"run_as"`
}

// sudoRuleView, kuralın panele giden hâli.
type sudoRuleView struct {
	Commands     []sudoCommandView `json:"commands"`
	Acknowledged bool              `json:"acknowledged"`
	UpdatedBy    string            `json:"updated_by"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

func sudoView(rs store.RoleSudo) sudoRuleView {
	out := sudoRuleView{
		Acknowledged: rs.Rule.Acknowledged,
		UpdatedBy:    rs.UpdatedBy, UpdatedAt: rs.UpdatedAt,
		Commands: make([]sudoCommandView, 0, len(rs.Rule.Commands)),
	}
	for _, c := range rs.Rule.Commands {
		out.Commands = append(out.Commands, sudoCommandView{
			Command: c.String(), RunAs: c.RunAsOr(rs.Rule.RunAs),
		})
	}

	return out
}

// sudoRuleInput, panelin gönderdiği kural. Grant gövdesiyle aynı şekil.
type sudoRuleInput struct {
	// RunAs, hesabı yazılmamış komutların varsayılanı. Panel komut başına
	// gönderiyor; bu alan eski çağıranlar ve JIT gövdesiyle aynı şekli
	// korumak için duruyor.
	RunAs    string `json:"run_as"`
	Commands []struct {
		Path  string   `json:"path"`
		Args  []string `json:"args"`
		RunAs string   `json:"run_as"`
	} `json:"commands"`
	Acknowledged bool `json:"acknowledged"`
}

func (in sudoRuleInput) rule() sudoers.Rule {
	r := sudoers.Rule{RunAs: strings.TrimSpace(in.RunAs), Acknowledged: in.Acknowledged}
	for _, c := range in.Commands {
		if p := strings.TrimSpace(c.Path); p != "" {
			r.Commands = append(r.Commands, sudoers.Command{
				Path: p, Args: c.Args, RunAs: strings.TrimSpace(c.RunAs),
			})
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
	/*
	 * ⚠️ RET ONAYLANABİLİR Mİ, CEVAP SÖYLÜYOR. Kaçış riski (bir editör,
	 * bir sayfalayıcı, başka program çalıştıran bir komut) operatörün
	 * bilerek kabul edebileceği bir şey; joker, göreli yol ya da ALL
	 * DEĞİL — onlar onayla da geçmiyor. Ekran onay kutusunu yalnızca
	 * kabul edilebilir retlerde göstersin diye ayrım burada yapılıyor,
	 * yoksa panel ret metnini tahmin etmek zorunda kalırdı.
	 *
	 * Kontrol store'da da duruyor (kapı orada); buradaki kopya cevabın
	 * şeklini kurmak için.
	 */
	if findings := sudoers.Validate(rule); sudoers.Refuses(findings, rule.Acknowledged) {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error":           sudoers.Describe(findings),
			"acknowledgeable": !sudoers.Refuses(findings, true),
		})
		return
	}
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
	cmds := make([]string, 0, len(r.Commands))
	for _, c := range r.Commands {
		cmds = append(cmds, c.String()+" (as "+c.RunAsOr(r.RunAs)+")")
	}

	return strings.Join(cmds, ", ")
}
