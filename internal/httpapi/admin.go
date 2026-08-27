package httpapi

// S4.2 — yönetim API'si. Tamamı requireSession + requireAdmin + sameOrigin
// zincirinde. Her başarılı değişiklik admin_log'a düşer (audit yardımcısı).
//
// Admin bayrağını değiştiren uç BİLEREK yok: kendini ya da başkasını admin
// yapabilen panel, ele geçirildiğinde kalıcı yetki demek olurdu; bayrak
// yalnızca hosttaki CLI'dan değişir (user modify --admin).

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/model"
	"github.com/warewave/postern/internal/store"
)

func (s *Server) registerAdminRoutes(mux *http.ServeMux) {
	admin := func(h http.HandlerFunc) http.Handler {
		return s.requireSession(s.requireAdmin(s.sameOrigin(h)))
	}

	mux.Handle("GET /api/admin/users", admin(s.adminListUsers))
	mux.Handle("POST /api/admin/users", admin(s.adminCreateUser))
	mux.Handle("PATCH /api/admin/users/{name}", admin(s.adminPatchUser))
	mux.Handle("DELETE /api/admin/users/{name}", admin(s.adminDeleteUser))
	mux.Handle("POST /api/admin/users/{name}/roles", admin(s.adminAssignRole))
	mux.Handle("DELETE /api/admin/users/{name}/roles/{role}", admin(s.adminRevokeRole))
	mux.Handle("POST /api/admin/users/{name}/keys", admin(s.adminAddKey))
	mux.Handle("POST /api/admin/users/{name}/keys/remove", admin(s.adminRemoveKey))

	mux.Handle("GET /api/admin/roles", admin(s.adminListRoles))
	mux.Handle("POST /api/admin/roles", admin(s.adminCreateRole))
	mux.Handle("DELETE /api/admin/roles/{name}", admin(s.adminDeleteRole))
	mux.Handle("POST /api/admin/roles/{name}/targets", admin(s.adminGrantTarget))
	mux.Handle("DELETE /api/admin/roles/{name}/targets/{target}", admin(s.adminRevokeTarget))
	mux.Handle("GET /api/admin/targets", admin(s.adminListTargets))
	mux.Handle("POST /api/admin/targets", admin(s.adminCreateTarget))
	mux.Handle("DELETE /api/admin/targets/{name}", admin(s.adminDeleteTarget))

	mux.Handle("GET /api/admin/sessions", admin(s.adminListSessions))
	mux.Handle("GET /api/admin/log", admin(s.adminListLog))
}

// requireAdmin, oturum sahibinin admin olduğunu HER İSTEKTE store'dan
// okuyarak doğrular: bayrak CLI'dan alınırsa bir sonraki istekte etkir,
// oturum boyunca önbelleklenmez. 401 "kimsin bilmiyorum" (requireSession
// verdi bile), 403 "kimsin biliyorum, yetkin yok".
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := s.store.User(r.Context(), sessionUser(r))
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeErr(w, http.StatusForbidden, "forbidden")
				return
			}
			s.logger.Error("admin check failed", "error", err)
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		if !u.Admin {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin, değiştiren istekleri site-dışı kaynaklardan koparır —
// SameSite=Lax'ın ikinci katı. Tarayıcı Sec-Fetch-Site'ı kendisi damgalar
// ve site-dışı JS bu başlığı taklit EDEMEZ; başlıksız istemci (curl, eski
// tarayıcı) geçer — katman savunması, tek savunma değil.
func (s *Server) sameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "none" {
			writeErr(w, http.StatusForbidden, "cross-site request rejected")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- ortak yardımcılar ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// readJSON, gövdeyi sınırla okur ve bilinmeyen alanları REDDEDER:
// "role" yerine "rol" yazan istemci sessizce boş istek göndermesin.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return false
	}
	return true
}

// storeErr, store hatalarını HTTP'ye eşler: translateErr sözleşmesinin
// dış yüzü. İç hata gövdeye YAZILMAZ — log'a yazılır.
func (s *Server) storeErr(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrConflict):
		writeErr(w, http.StatusConflict, "conflict: "+err.Error())
	default:
		s.logger.Error("admin api store error", "op", op, "error", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
	}
}

// audit, başarılı bir değişikliği deftere yazar. Yazamamak isteği geri
// almaz (iş çoktan oldu) ama sessiz de kalmaz: Error seviyesinde loglanır.
func (s *Server) audit(r *http.Request, action, entity, details string) {
	err := s.store.LogAdmin(r.Context(), store.AdminLogEntry{
		Actor: sessionUser(r), Via: "web", Action: action, Entity: entity, Details: details,
	})
	if err != nil {
		s.logger.Error("admin audit write failed", "action", action, "entity", entity, "error", err)
	}
}

func ok(w http.ResponseWriter) { writeJSON(w, http.StatusOK, map[string]bool{"ok": true}) }

// parseAuthorizedKey, satırı doğrular ve kanonik blob + yorumunu döner.
func parseAuthorizedKey(w http.ResponseWriter, line string) (ssh.PublicKey, string, bool) {
	pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "not a valid public key")
		return nil, "", false
	}
	return pub, comment, true
}

// --- kullanıcılar ---

func (s *Server) adminListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.Users(r.Context())
	if err != nil {
		s.storeErr(w, "users.list", err)
		return
	}

	type row struct {
		Name   string   `json:"name"`
		OSUser string   `json:"os_user"`
		Admin  bool     `json:"admin"`
		Roles  []string `json:"roles"`
		Keys   int      `json:"keys"`
	}
	out := make([]row, 0, len(users))
	for _, u := range users {
		roles := make([]string, 0, len(u.Roles))
		for _, ro := range u.Roles {
			roles = append(roles, ro.Name)
		}
		keys, err := s.store.PublicKeys(r.Context(), u.Name)
		if err != nil {
			s.storeErr(w, "users.list", err)
			return
		}
		out = append(out, row{Name: u.Name, OSUser: u.OSUser, Admin: u.Admin, Roles: roles, Keys: len(keys)})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) adminCreateUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name   string   `json:"name"`
		OSUser string   `json:"os_user"`
		Email  string   `json:"email"`
		Roles  []string `json:"roles"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Name == "" || in.OSUser == "" {
		writeErr(w, http.StatusBadRequest, "name and os_user are required")
		return
	}

	if _, err := s.store.CreateUser(r.Context(), in.Name, in.Email, in.OSUser); err != nil {
		s.storeErr(w, "user.create", err)
		return
	}
	s.audit(r, "user.create", in.Name, "os_user "+in.OSUser)

	for _, role := range in.Roles {
		if err := s.store.AssignRole(r.Context(), in.Name, role); err != nil {
			// Kullanıcı oluştu, rol atanamadı: kısmi durum. Gövde bunu
			// söyler; CLI'daki "düzelt ve yeniden dene" sözleşmesinin aynısı
			// burada geçerli değil (create tekrar 409 verir), o yüzden rol
			// ataması ayrı uçtan tamamlanabilir.
			if errors.Is(err, store.ErrNotFound) {
				writeErr(w, http.StatusNotFound, "user created but role "+role+" not found; assign it separately")
				return
			}
			s.storeErr(w, "user.create", err)
			return
		}
		s.audit(r, "user.grant_role", in.Name, "role "+role)
	}
	ok(w)
}

func (s *Server) adminPatchUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	// İşaretçiler "verilmedi" ile "boş verildi"yi ayırır: email=""
	// adresi SİLER, alanın yokluğu dokunmaz.
	var in struct {
		Email  *string `json:"email"`
		OSUser *string `json:"os_user"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Email == nil && in.OSUser == nil {
		writeErr(w, http.StatusBadRequest, "nothing to change")
		return
	}

	if in.Email != nil {
		if err := s.store.SetUserEmail(r.Context(), name, *in.Email); err != nil {
			s.storeErr(w, "user.modify", err)
			return
		}
		s.audit(r, "user.modify", name, "email set")
	}
	if in.OSUser != nil {
		if err := s.store.SetUserOSUser(r.Context(), name, *in.OSUser); err != nil {
			s.storeErr(w, "user.modify", err)
			return
		}
		s.audit(r, "user.modify", name, "os_user set to "+*in.OSUser)
	}
	ok(w)
}

func (s *Server) adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.store.DeleteUser(r.Context(), name); err != nil {
		s.storeErr(w, "user.delete", err)
		return
	}
	s.audit(r, "user.delete", name, "")
	ok(w)
}

func (s *Server) adminAssignRole(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var in struct {
		Role string `json:"role"`
	}
	if !readJSON(w, r, &in) || in.Role == "" {
		if in.Role == "" {
			writeErr(w, http.StatusBadRequest, "role is required")
		}
		return
	}
	if err := s.store.AssignRole(r.Context(), name, in.Role); err != nil {
		s.storeErr(w, "user.grant_role", err)
		return
	}
	s.audit(r, "user.grant_role", name, "role "+in.Role)
	ok(w)
}

func (s *Server) adminRevokeRole(w http.ResponseWriter, r *http.Request) {
	name, role := r.PathValue("name"), r.PathValue("role")
	if err := s.store.RevokeRole(r.Context(), name, role); err != nil {
		s.storeErr(w, "user.revoke_role", err)
		return
	}
	s.audit(r, "user.revoke_role", name, "role "+role)
	ok(w)
}

func (s *Server) adminAddKey(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var in struct {
		AuthorizedKey string `json:"authorized_key"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	pub, comment, okKey := parseAuthorizedKey(w, in.AuthorizedKey)
	if !okKey {
		return
	}
	if err := s.store.AddPublicKey(r.Context(), name, pub.Marshal(), comment); err != nil {
		s.storeErr(w, "user.add_key", err)
		return
	}
	s.audit(r, "user.add_key", name, ssh.FingerprintSHA256(pub))
	ok(w)
}

func (s *Server) adminRemoveKey(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var in struct {
		AuthorizedKey string `json:"authorized_key"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	pub, _, okKey := parseAuthorizedKey(w, in.AuthorizedKey)
	if !okKey {
		return
	}
	if err := s.store.RemovePublicKey(r.Context(), name, pub.Marshal()); err != nil {
		s.storeErr(w, "user.remove_key", err)
		return
	}
	s.audit(r, "user.remove_key", name, ssh.FingerprintSHA256(pub))
	ok(w)
}

// --- roller ---

func (s *Server) adminListRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := s.store.Roles(r.Context())
	if err != nil {
		s.storeErr(w, "roles.list", err)
		return
	}
	type row struct {
		Name    string   `json:"name"`
		Targets []string `json:"targets"`
	}
	out := make([]row, 0, len(roles))
	for _, ro := range roles {
		out = append(out, row{Name: ro.Name, Targets: ro.Targets})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) adminCreateRole(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name    string   `json:"name"`
		Targets []string `json:"targets"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	if _, err := s.store.CreateRole(r.Context(), in.Name); err != nil {
		s.storeErr(w, "role.create", err)
		return
	}
	s.audit(r, "role.create", in.Name, "")

	for _, tgt := range in.Targets {
		if err := s.store.GrantTarget(r.Context(), in.Name, tgt); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeErr(w, http.StatusNotFound, "role created but target "+tgt+" not found; grant it separately")
				return
			}
			s.storeErr(w, "role.create", err)
			return
		}
		s.audit(r, "role.grant", in.Name, "target "+tgt)
	}
	ok(w)
}

func (s *Server) adminDeleteRole(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.store.DeleteRole(r.Context(), name); err != nil {
		s.storeErr(w, "role.delete", err)
		return
	}
	s.audit(r, "role.delete", name, "")
	ok(w)
}

func (s *Server) adminGrantTarget(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var in struct {
		Target string `json:"target"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Target == "" {
		writeErr(w, http.StatusBadRequest, "target is required")
		return
	}
	if err := s.store.GrantTarget(r.Context(), name, in.Target); err != nil {
		s.storeErr(w, "role.grant", err)
		return
	}
	s.audit(r, "role.grant", name, "target "+in.Target)
	ok(w)
}

func (s *Server) adminRevokeTarget(w http.ResponseWriter, r *http.Request) {
	name, target := r.PathValue("name"), r.PathValue("target")
	if err := s.store.RevokeTarget(r.Context(), name, target); err != nil {
		s.storeErr(w, "role.revoke", err)
		return
	}
	s.audit(r, "role.revoke", name, "target "+target)
	ok(w)
}

// --- hedefler ---

func (s *Server) adminListTargets(w http.ResponseWriter, r *http.Request) {
	targets, err := s.store.Targets(r.Context())
	if err != nil {
		s.storeErr(w, "targets.list", err)
		return
	}
	type row struct {
		Name        string `json:"name"`
		Host        string `json:"host"`
		Port        int    `json:"port"`
		Fingerprint string `json:"fingerprint"`
	}
	out := make([]row, 0, len(targets))
	for _, t := range targets {
		fp := "(invalid key)"
		if pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(t.HostKey)); err == nil {
			fp = ssh.FingerprintSHA256(pub)
		}
		out = append(out, row{Name: t.Name, Host: t.Host, Port: t.Port, Fingerprint: fp})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) adminCreateTarget(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name    string `json:"name"`
		Host    string `json:"host"`
		Port    int    `json:"port"`
		HostKey string `json:"host_key"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Name == "" || in.Host == "" || in.HostKey == "" {
		writeErr(w, http.StatusBadRequest, "name, host and host_key are required")
		return
	}
	if in.Port == 0 {
		in.Port = 22
	}
	pub, _, okKey := parseAuthorizedKey(w, in.HostKey)
	if !okKey {
		return
	}

	// CLI ile aynı kural: kanonik satır saklanır — aynı anahtarın iki
	// farklı metni iki farklı değer gibi görünmesin.
	_, err := s.store.CreateTarget(r.Context(), model.Target{
		Name: in.Name, Host: in.Host, Port: in.Port,
		HostKey: string(ssh.MarshalAuthorizedKey(pub)),
	})
	if err != nil {
		s.storeErr(w, "target.create", err)
		return
	}
	s.audit(r, "target.create", in.Name, in.Host)
	ok(w)
}

func (s *Server) adminDeleteTarget(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.store.DeleteTarget(r.Context(), name); err != nil {
		s.storeErr(w, "target.delete", err)
		return
	}
	s.audit(r, "target.delete", name, "")
	ok(w)
}

// --- denetim (salt okunur) ---

func (s *Server) adminListSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := s.store.Sessions(r.Context(), "", 200)
	if err != nil {
		s.storeErr(w, "sessions.list", err)
		return
	}
	type row struct {
		ID      string  `json:"id"`
		User    string  `json:"user"`
		Target  string  `json:"target"`
		OSUser  string  `json:"os_user"`
		SrcIP   string  `json:"src_ip"`
		Started string  `json:"started_at"`
		Ended   *string `json:"ended_at"`
	}
	out := make([]row, 0, len(sessions))
	for _, sess := range sessions {
		var ended *string
		if !sess.Open() {
			e := sess.EndedAt.Format(time.RFC3339)
			ended = &e
		}
		out = append(out, row{
			ID: sess.ID, User: sess.User, Target: sess.Target, OSUser: sess.OSUser,
			SrcIP: sess.SrcIP, Started: sess.StartedAt.Format(time.RFC3339), Ended: ended,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) adminListLog(w http.ResponseWriter, r *http.Request) {
	entries, err := s.store.AdminLog(r.Context(), 500)
	if err != nil {
		s.storeErr(w, "log.list", err)
		return
	}
	type row struct {
		At      string `json:"at"`
		Actor   string `json:"actor"`
		Via     string `json:"via"`
		Action  string `json:"action"`
		Entity  string `json:"entity"`
		Details string `json:"details"`
	}
	out := make([]row, 0, len(entries))
	for _, e := range entries {
		out = append(out, row{
			At: e.At.Format(time.RFC3339), Actor: e.Actor, Via: e.Via,
			Action: e.Action, Entity: e.Entity, Details: e.Details,
		})
	}
	writeJSON(w, http.StatusOK, out)
}
