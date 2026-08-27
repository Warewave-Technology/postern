package httpapi

// S5.4 — kimlik federasyonunun yönetim yüzeyi: grup eşlemeleri,
// eşlenmemiş grup teşhisi ve LDAP ayarları.
//
// Hepsi admin zincirinde (requireSession + requireAdmin + sameOrigin) ve
// her değişiklik admin_log'a düşüyor — yönetim yüzeyinin geri kalanıyla
// aynı kurallar.

import (
	"errors"
	"net/http"
	"strings"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/ldap"
	"github.com/warewave/postern/internal/store"
)

func (s *Server) registerFederationRoutes(mux *http.ServeMux) {
	admin := func(h http.HandlerFunc) http.Handler {
		return noStore(s.requireSession(s.requireAdmin(s.sameOrigin(h))))
	}

	mux.Handle("GET /api/admin/mappings", admin(s.adminListMappings))
	mux.Handle("POST /api/admin/mappings", admin(s.adminAddMapping))
	mux.Handle("DELETE /api/admin/mappings/{group}/{role}", admin(s.adminRemoveMapping))
	mux.Handle("GET /api/admin/unmapped-groups", admin(s.adminUnmappedGroups))

	mux.Handle("GET /api/admin/settings", admin(s.adminListSettings))
	mux.Handle("PUT /api/admin/settings", admin(s.adminSetSetting))
	mux.Handle("POST /api/admin/ldap/test", admin(s.adminTestLDAP))
}

// --- grup eşlemeleri ---

func (s *Server) adminListMappings(w http.ResponseWriter, r *http.Request) {
	mappings, err := s.store.GroupMappings(r.Context())
	if err != nil {
		s.storeErr(w, "mappings.list", err)
		return
	}

	type row struct {
		Group     string `json:"group"`
		Role      string `json:"role"`
		CreatedBy string `json:"created_by"`
	}
	out := make([]row, 0, len(mappings))
	for _, m := range mappings {
		out = append(out, row{Group: m.ExternalGroup, Role: m.Role, CreatedBy: m.CreatedBy})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) adminAddMapping(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Group string `json:"group"`
		Role  string `json:"role"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Group == "" || in.Role == "" {
		writeErr(w, http.StatusBadRequest, "group and role are required")
		return
	}

	if err := s.store.AddGroupMapping(r.Context(), in.Group, in.Role, sessionUser(r)); err != nil {
		s.storeErr(w, "mapping.create", err)
		return
	}
	s.audit(r, "mapping.create", in.Group, "role "+in.Role)
	ok(w)
}

func (s *Server) adminRemoveMapping(w http.ResponseWriter, r *http.Request) {
	group, role := r.PathValue("group"), r.PathValue("role")

	if err := s.store.RemoveGroupMapping(r.Context(), group, role); err != nil {
		s.storeErr(w, "mapping.delete", err)
		return
	}
	s.audit(r, "mapping.delete", group, "role "+role)

	// Etki alanını açıkça söyle: mevcut atamalar bir sonraki girişte
	// yenilenir, şu an açık oturumlar etkilenmez.
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":   true,
		"note": "users lose this role on their next login",
	})
}

func (s *Server) adminUnmappedGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.store.UnmappedGroups(r.Context())
	if err != nil {
		s.storeErr(w, "unmapped.list", err)
		return
	}

	type row struct {
		Name      string `json:"name"`
		SeenCount int    `json:"seen_count"`
		LastSeen  string `json:"last_seen"`
	}
	out := make([]row, 0, len(groups))
	for _, g := range groups {
		out = append(out, row{Name: g.Name, SeenCount: g.SeenCount, LastSeen: g.LastSeen.Format("2006-01-02 15:04")})
	}
	writeJSON(w, http.StatusOK, out)
}

// --- ayarlar ---

func (s *Server) adminListSettings(w http.ResponseWriter, r *http.Request) {
	views, err := s.store.Settings(r.Context())
	if err != nil {
		s.storeErr(w, "settings.list", err)
		return
	}

	type row struct {
		Key       string `json:"key"`
		Value     string `json:"value"` // şifreliyse maskeli (store garantisi)
		Secret    bool   `json:"secret"`
		UpdatedBy string `json:"updated_by"`
	}
	out := make([]row, 0, len(views))
	for _, v := range views {
		out = append(out, row{Key: v.Key, Value: v.Value, Secret: v.Secret, UpdatedBy: v.UpdatedBy})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) adminSetSetting(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Key == "" {
		writeErr(w, http.StatusBadRequest, "key is required")
		return
	}
	// Yalnızca tanıdığımız ayarlar yazılabilir: rastgele anahtar yazmak
	// tabloyu çöplüğe çevirir ve yazım hatası sessizce etkisiz kalır.
	if !knownSettingKeys[in.Key] {
		writeErr(w, http.StatusBadRequest, "unknown setting key")
		return
	}

	// Sır olduğu BİZİM tarafımızda belirleniyor, istemcinin dediğine
	// göre değil: istemci "secret: false" diyerek parolayı düz metne
	// düşüremesin.
	isSecret := ldap.SecretKeys[in.Key]

	// ⚠️ HEDEF DEĞİŞİRSE KİMLİK BİLGİSİ DÜŞER.
	//
	// Kapatılan sızıntı: panel admini ldap.url'i kendi kontrolündeki bir
	// sunucuya çevirip "test bağlantısı"na basıyordu; postern o sunucuya
	// SAKLANAN bind parolasıyla bağlanıyor ve parolayı düz metin olarak
	// saldırgana veriyordu. Parolanın mühürlenmesinin ve panelde
	// maskelenmesinin tüm amacı — "admin bile okuyamaz" — bu yolla boşa
	// çıkıyordu.
	//
	// Kural basit ve anlaşılır: nereye bağlanacağını değiştiriyorsan
	// kimlik bilgisini yeniden gireceksin. Bunu ATOMİK yapmak gerekiyor
	// — önce parolayı düşürüp sonra URL'i yazmak, arada kalan bir
	// koşuda bağlantıyı parolasız bırakırdı; sıra bu yüzden tersine.
	if in.Key == ldapURLKey {
		current, err := s.store.Setting(r.Context(), ldapURLKey)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.storeErr(w, "settings.set", err)
			return
		}
		if current != "" && current != in.Value {
			if derr := s.store.DeleteSetting(r.Context(), ldapBindPasswordKey); derr != nil &&
				!errors.Is(derr, store.ErrNotFound) {
				s.storeErr(w, "settings.set", derr)
				return
			}
			s.logger.Warn("ldap url changed; stored bind password dropped",
				"actor", sessionUser(r), "from", current, "to", in.Value)
			s.audit(r, "settings.ldap_url_changed", ldapURLKey,
				"bind password cleared because the directory address changed")
		}
	}

	if err := s.store.SetSetting(r.Context(), in.Key, in.Value, isSecret, sessionUser(r)); err != nil {
		// Anahtar yapılandırılmamışken sır yazmak: kullanıcıya ne
		// yapacağını söyle.
		if strings.Contains(err.Error(), "secret key not configured") {
			writeErr(w, http.StatusBadRequest,
				"cannot store secrets: run `postern secret init` on the bastion host first")
			return
		}
		s.storeErr(w, "setting.set", err)
		return
	}

	detail := in.Key
	if isSecret {
		detail += " (secret)"
	}
	s.audit(r, "setting.set", in.Key, detail)

	// Ayar değişti: grup kaynağını yeniden kurmayı dene. Başarısızsa
	// ESKİSİ kalır — yarım yapılandırma yüzünden çalışan bir kurulumu
	// bozmuyoruz — ama cevapta durumu söylüyoruz.
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"source": s.reloadGroupSource(r),
	})
}

// reloadGroupSource, LDAP ayarlarından kaynağı yeniden kurar ve hangi
// kaynağın etkin olduğunu döner.
//
// Hata durumunda mevcut kaynak KORUNUR: "ldap.url yazdım, user_base
// henüz yok" gibi ara durumlarda çalışan bir kurulum bozulmamalı.
func (s *Server) reloadGroupSource(r *http.Request) string {
	if s.groupSwitch == nil {
		return "claim"
	}

	src, err := ldap.SourceFromStore(r.Context(), s.store)
	switch {
	case err == nil:
		s.groupSwitch.Set(src)
		s.logger.Info("group source switched to ldap")
		return "ldap"
	case errors.Is(err, ldap.ErrNotConfigured):
		s.groupSwitch.Set(auth.ClaimGroups{})
		return "claim"
	default:
		// Yapılandırma var ama eksik/bozuk: dokunma, durumu bildir.
		return "incomplete: " + err.Error()
	}
}

// adminTestLDAP, saklanan yapılandırmayı gerçekten deneyerek doğrular.
//
// Panelin "test et" düğmesi: yanlış base DN ya da bind parolası ilk
// gerçek girişte değil burada ortaya çıksın.
func (s *Server) adminTestLDAP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		User string `json:"user"`
	}
	if r.ContentLength > 0 && !readJSON(w, r, &in) {
		return
	}

	src, err := ldap.SourceFromStore(r.Context(), s.store)
	if err != nil {
		if errors.Is(err, ldap.ErrNotConfigured) {
			writeErr(w, http.StatusBadRequest, "ldap is not configured")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := src.Test(r.Context()); err != nil {
		// Test HATASI 200 döner, gövdede ok:false ile: bu bir teşhis
		// aracı, isteğin kendisi başarılı. 5xx dönmek panelde "sunucu
		// bozuk" gibi görünürdü.
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	res := map[string]any{"ok": true}

	if in.User != "" {
		groups, err := src.Groups(r.Context(), auth.Identity{Username: in.User})
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		roles, unmapped, err := s.store.RolesForGroups(r.Context(), groups)
		if err != nil {
			s.storeErr(w, "ldap.test", err)
			return
		}
		res["groups"] = groups
		res["roles"] = roles
		res["unmapped"] = unmapped
	}

	writeJSON(w, http.StatusOK, res)
}

// knownSettingKeys, panelden yazılabilecek ayarlar.
var knownSettingKeys = map[string]bool{
	ldap.KeyURL:            true,
	ldap.KeyBindDN:         true,
	ldap.KeyBindPassword:   true,
	ldap.KeyUserBase:       true,
	ldap.KeyUserFilter:     true,
	ldap.KeyGroupAttribute: true,
	ldap.KeyGroupBase:      true,
	ldap.KeyGroupFilter:    true,
	ldap.KeyGroupNameFrom:  true,
}

var _ = store.SettingView{}

// LDAP ayar anahtarları — ldap paketindeki adların tek yerde tutulan
// kopyaları, yazım hatası derlemede yakalansın diye.
// #nosec G101 -- kimlik bilgisi değil, settings tablosunun ANAHTAR adları
const (
	ldapURLKey          = "ldap.url"
	ldapBindPasswordKey = "ldap.bind_password"
)
