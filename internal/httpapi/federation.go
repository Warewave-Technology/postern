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
	"strconv"
	"strings"
	"time"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/groupsync"
	"github.com/warewave/postern/internal/ldap"
	"github.com/warewave/postern/internal/model"
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
	// Yalnızca bağlantı + servis hesabı. Sihirbazın ilk adımını
	// sınanabilir yapıyor: dokuz alandan hangisinin yanlış olduğunu
	// dokuzunu da yazdıktan sonra öğrenmek gerekmesin.
	mux.Handle("POST /api/admin/ldap/check-connection", admin(s.adminCheckLDAPConnection))
	// ADAY yapılandırmayı sınar (saklananı değil). Düzenleme ekranı
	// buna dayanıyor: sınanmamış bir değişiklik canlıya çıkmasın.
	mux.Handle("POST /api/admin/ldap/verify", admin(s.adminVerifyLDAP))
	mux.Handle("GET /api/admin/sync/settings", admin(s.adminSyncSettings))
	// Koşuların SONUCU. Bu uç olmadan senkronizasyonun durduğu yalnızca
	// host üzerinde `postern sync runs` ile görülebiliyordu — yani
	// pratikte hiç görülmüyordu.
	mux.Handle("GET /api/admin/sync/runs", admin(s.adminSyncRuns))
	// Yönetici grubu. Önizleme kaydetmeden önce kimlere yetki
	// verildiğini gösterir; yazma ucu ise GÖRÜLEN LİSTEYİ geri
	// istediği için onay atlanamaz.
	mux.Handle("POST /api/admin/ldap/admin-group/preview", admin(s.adminAdminGroupPreview))
	mux.Handle("GET /api/admin/ldap/admin-group", admin(s.adminAdminGroupStatus))
	mux.Handle("POST /api/admin/ldap/admin-group", admin(s.adminAdminGroupSet))
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
		/*
		 * ⚠️ Groups DEĞİL, Lookup.
		 *
		 * Groups iki ayrı cevabı aynı boş dilime katlıyor: "dizin bu
		 * kullanıcıyı hiç tanımıyor" ile "tanıyor, hiçbir grupta değil".
		 * Ölçüldü ve maliyeti görüldü: IdP kullanıcı adı yigit, dizindeki
		 * kayıt yigit.basalma olan bir kurulumda panel yemyeşil
		 * "connection and bind succeeded" diyordu. Bağlantı gerçekten
		 * kurulmuştu — ama operatörün SORDUĞU soru o değildi ve
		 * cevabı hiç görünmüyordu.
		 *
		 * Lookup bu ayrımı zaten yapıyor (senkronizasyon ona dayanıyor);
		 * eksik olan tek şey teşhis aracının onu kullanmasıydı.
		 */
		lr, err := src.Lookup(r.Context(), auth.Identity{Username: in.User})
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
			return
		}

		res["presence"] = lr.Presence.String()
		if lr.Presence != ldap.PresencePresent {
			// Bulunamayan kullanıcı için rol hesaplamak anlamsız:
			// gösterilecek "sıfır rol", kullanıcının değil aramanın
			// sonucu olurdu.
			writeJSON(w, http.StatusOK, res)
			return
		}

		/*
		 * ⚠️ TEŞHİS, GİRİŞİN GÖRDÜĞÜNÜ GÖSTERMELİ.
		 *
		 * Dizin "tanıyorum, hiçbir grupta değil" dediğinde giriş yolu
		 * `unknown` grubunu uyguluyor. Burada ham boş listeyi gösterip
		 * rolleri `unknown` üzerinden hesaplamak, ekranda "grup yok
		 * ama rol var" gibi açıklanamaz bir çift üretirdi — teşhis
		 * aracının yapabileceği en kötü şey.
		 */
		effective := model.ResolvedGroups(lr.Groups)
		roles, unmapped, err := s.store.RolesForGroups(r.Context(), effective)
		if err != nil {
			s.storeErr(w, "ldap.test", err)
			return
		}
		// Boş dilimler nil DEĞİL: JSON'da null ile [] farkı, panelde
		// "veri yok" ile "cevap boş" farkına dönüşüyor.
		res["groups"] = nonNil(effective)
		res["roles"] = nonNil(roles)
		res["unmapped"] = nonNil(unmapped)
		// ⚠️ KAPSAM DIŞI KALANLAR AYRICA SÖYLENİYOR. group_scope
		// varsayılanı "direct"; gruplarını bir OU daha derinde tutan bir
		// kurulum yükseltmeden sonra rol kaybeder ve bunu sessizce
		// yapmak, operatörü kaybolan yetkinin sebebini arayarak
		// dolaştırır.
		res["out_of_scope"] = nonNil(lr.OutOfScope)
	}

	writeJSON(w, http.StatusOK, res)
}

// nonNil, nil dilimi boş dilime çevirir.
//
// JSON'da null ile [] aynı şey değil: panel "alan yok" ile "alan var,
// içi boş" arasında karar veriyor ve nil gönderirsek boş bir cevabı
// hiç gelmemiş sayıp gizliyor.
func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

/*
 * adminSyncRuns, son senkronizasyon koşuları.
 *
 * ⚠️ NEDEN VAR: patlama yarıçapı korumaları bir koşuyu iptal ettiğinde
 * bunun tek izi sync_runs tablosuydu ve o tabloyu okuyan tek şey host
 * üzerindeki `postern sync runs` komutuydu. Yani "hiç kimsenin yetkisi
 * iptal edilmiyor" hâli, panele bakan bir operatör için TAMAMEN
 * görünmezdi. Sessiz bir güvenlik arızasının en pahalı biçimi bu.
 */
func (s *Server) adminSyncRuns(w http.ResponseWriter, r *http.Request) {
	const defaultLimit = 20
	limit := defaultLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > 200 {
			writeErr(w, http.StatusBadRequest, "limit must be a number between 1 and 200")
			return
		}
		limit = n
	}

	runs, err := s.store.SyncRuns(r.Context(), limit)
	if err != nil {
		s.storeErr(w, "sync.runs", err)
		return
	}

	type row struct {
		ID           int64  `json:"id"`
		StartedAt    string `json:"started_at"`
		FinishedAt   string `json:"finished_at"`
		Trigger      string `json:"trigger"`
		Outcome      string `json:"outcome"`
		Reason       string `json:"reason"`
		Considered   int    `json:"considered"`
		Unknown      int    `json:"unknown"`
		Revoked      int    `json:"revoked"`
		RolesChanged int    `json:"roles_changed"`
		DryRun       bool   `json:"dry_run"`
	}
	out := make([]row, 0, len(runs))
	for _, x := range runs {
		fin := ""
		if !x.FinishedAt.IsZero() {
			fin = x.FinishedAt.UTC().Format(time.RFC3339)
		}
		out = append(out, row{
			ID: x.ID, StartedAt: x.StartedAt.UTC().Format(time.RFC3339), FinishedAt: fin,
			Trigger: x.Trigger, Outcome: x.Outcome, Reason: x.Reason,
			Considered: x.Considered, Unknown: x.Unknown, Revoked: x.Revoked,
			RolesChanged: x.RolesChanged, DryRun: x.DryRun,
		})
	}
	writeJSON(w, http.StatusOK, out)
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
	ldap.KeyGroupScope:     true,

	// ⚠️ auth.source ve ldap.admin_group BİLEREK YOK.
	//
	// auth.source panelin hangi kapısının açık olduğunu seçiyor ve
	// yanlış seçim herkesi — düzeltecek kişiyi de — dışarıda bırakıyor.
	// Doğrulamasız bir yazma ucundan geçmemeli; kendi ucu, geçilecek
	// kaynağın gerçekten birini içeri alabildiğini kanıtlıyor
	// (adminAuthSourceSet).
	//
	// ⚠️ ldap.admin_group BİLEREK YOK. Yönetici grubu bu genel uçtan
	// yazılabilseydi onay ekranı tamamen atlanabilir olurdu: bir grup
	// adı yazıp kaydetmek, kime yetki verdiğini hiç görmeden yetki
	// dağıtmak demekti. Kendi ucu var ve orası gördüğün listeyi geri
	// istiyor (adminAdminGroupSet).

	// Dizin senkronizasyonu LDAP'ın bir özelliği ve LDAP panelden
	// yönetiliyor; ayarlarının yalnızca YAML'da olması, en çok
	// ihtiyaç duyulan düğmeyi — dry_run — dosya düzenleyip yeniden
	// başlatmaya bağlıyordu.
	groupsync.KeyEnabled:            true,
	groupsync.KeyInterval:           true,
	groupsync.KeyGrace:              true,
	groupsync.KeyDryRun:             true,
	groupsync.KeyMaxZeroFraction:    true,
	groupsync.KeyMinZeroFloor:       true,
	groupsync.KeyMaxUnknownFraction: true,
	groupsync.KeyMaxRevokePerRun:    true,
}

var _ = store.SettingView{}

// LDAP ayar anahtarları — ldap paketindeki adların tek yerde tutulan
// kopyaları, yazım hatası derlemede yakalansın diye.
// #nosec G101 -- kimlik bilgisi değil, settings tablosunun ANAHTAR adları
const (
	ldapURLKey          = "ldap.url"
	ldapBindPasswordKey = "ldap.bind_password"
)

/*
 * adminCheckLDAPConnection, YALNIZCA dizine ulaşıp servis hesabıyla
 * bind edilebildiğini sınar.
 *
 * adminTestLDAP'in aksine kullanıcı tabanına bakmıyor: sihirbazın
 * "Connection" adımında henüz user_base yazılmamış oluyor ve tam testi
 * çalıştırmak, doldurulmamış bir alanı hata gibi göstermek olurdu.
 *
 * ⚠️ SAKLANAN değerleri okur, gönderileni değil — adminTestLDAP ile aynı
 * sözleşme. Aksi hâlde panelin sunucuya kimlik bilgisi ileten ayrı bir
 * ucu olurdu.
 */
func (s *Server) adminCheckLDAPConnection(w http.ResponseWriter, r *http.Request) {
	err := ldap.CheckConnection(r.Context(), s.store)
	if err == nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	if errors.Is(err, ldap.ErrNotConfigured) {
		writeErr(w, http.StatusBadRequest, "ldap.url is not stored yet — save this step first")
		return
	}
	// Test HATASI 200 döner, gövdede ok:false ile: bu bir teşhis aracı,
	// isteğin kendisi başarılı. 5xx dönmek panelde "sunucu bozuk" gibi
	// görünürdü.
	writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
}

/*
 * adminVerifyLDAP, GÖNDERİLEN yapılandırmayı sınar — saklananı değil.
 *
 * NEDEN GEREKLİ: mevcut test saklanan değerleri okuyor, dolayısıyla yeni
 * bir değeri sınamanın tek yolu onu önce KAYDETMEKTİ. Yani "çalıştığını
 * görmeden kaydetme" kuralı, kendi kendini imkânsız kılıyordu: kaydeden
 * kişi zaten canlı yapılandırmayı bozmuş oluyordu. Bu uç sırayı tersine
 * çeviriyor — önce kanıtla, sonra yaz.
 *
 * ⚠️ SAKLANAN PAROLA YALNIZCA SAKLANAN ADRESE GİDER.
 *
 * Parola gönderilmediğinde saklananı kullanmak kolaydı ve kapatılmış bir
 * sızıntıyı geri açardı (bkz. adminSetSetting'deki "HEDEF DEĞİŞİRSE
 * KİMLİK BİLGİSİ DÜŞER"): panel admini aday URL'i kendi sunucusuna
 * çevirip sınamaya basar, postern oraya SAKLANAN parolayla bağlanır ve
 * parolayı düz metin verirdi. Mühürlemenin tüm amacı — "admin bile
 * okuyamaz" — bu yolla boşa çıkardı.
 *
 * Kural adminSetSetting'inkiyle aynı: nereye bağlanacağını
 * değiştiriyorsan kimlik bilgisini yeniden gireceksin.
 */
func (s *Server) adminVerifyLDAP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		URL            string `json:"url"`
		BindDN         string `json:"bind_dn"`
		BindPassword   string `json:"bind_password"`
		UserBase       string `json:"user_base"`
		UserFilter     string `json:"user_filter"`
		GroupAttribute string `json:"group_attribute"`
		GroupBase      string `json:"group_base"`
		GroupFilter    string `json:"group_filter"`
		GroupNameFrom  string `json:"group_name_from"`

		// User doluysa gruplarını da çözer: "bağlanıyor" ile "bu kişiyi
		// bulabiliyor" ayrı sorular ve ikincisi asıl merak edilen.
		User string `json:"user"`
	}
	if !readJSON(w, r, &in) {
		return
	}

	if in.BindPassword == "" {
		stored, err := s.store.Setting(r.Context(), ldapURLKey)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.storeErr(w, "ldap.verify", err)
			return
		}
		if stored == "" || stored != in.URL {
			writeErr(w, http.StatusBadRequest,
				"enter the bind password: it is only reused for the directory address "+
					"that is already stored, and this address is different")
			return
		}
		pwd, err := s.store.Setting(r.Context(), ldapBindPasswordKey)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.storeErr(w, "ldap.verify", err)
			return
		}
		in.BindPassword = pwd
	}

	src, err := ldap.New(ldap.Config{
		URL: in.URL, BindDN: in.BindDN, BindPassword: in.BindPassword,
		UserBase: in.UserBase, UserFilter: in.UserFilter,
		GroupAttribute: in.GroupAttribute, GroupBase: in.GroupBase,
		GroupFilter: in.GroupFilter, GroupNameFrom: in.GroupNameFrom,
	})
	if err != nil {
		// Yapılandırma hatası: istek başarılı, sonuç olumsuz.
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	if err := src.Test(r.Context()); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	out := map[string]any{"ok": true}
	if in.User != "" {
		gres, gerr := src.Groups(r.Context(), auth.Identity{Username: in.User})
		if gerr != nil {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": gerr.Error()})
			return
		}
		// Teşhis ucu da üç değerli cevabı taşımalı: boş liste ile
		// "böyle bir kullanıcı yok" panelde ayrı şeyler.
		out["presence"] = gres.Presence.String()
		groups := gres.Groups
		// ⚠️ `unknown` YALNIZCA kullanıcı gerçekten bulunduğunda.
		// Bulunamayan biri için "unknown grubundasın" demek, aramanın
		// sonucunu kullanıcının özelliği gibi göstermek olurdu.
		if gres.Presence == auth.GroupsPresent {
			groups = model.ResolvedGroups(groups)
		}
		roles, unmapped, rerr := s.store.RolesForGroups(r.Context(), groups)
		if rerr != nil {
			s.storeErr(w, "ldap.verify", rerr)
			return
		}
		out["groups"] = groups
		out["roles"] = roles
		out["unmapped"] = unmapped
	}
	writeJSON(w, http.StatusOK, out)
}

/*
 * adminSyncSettings, senkronizasyonun ETKİN ayarlarını döner.
 *
 * ⚠️ Saklanan değil ETKİN: saklanan bir anahtar yoksa YAML'daki değer
 * geçerli ve döngü onu kullanıyor. Panelde "ayarlanmamış" yazmak,
 * aslında 15 dakikada bir koşan bir döngü için yanlış bilgi olurdu.
 * overridden, hangilerinin panelden yazıldığını söylüyor — operatör
 * neyin dosyadan geldiğini görebilsin.
 */
func (s *Server) adminSyncSettings(w http.ResponseWriter, r *http.Request) {
	eff, err := groupsync.LoadSettings(r.Context(), s.store, s.syncDefaults)
	if err != nil {
		// Okunamayan bir ayar SESSİZ KALMAMALI: döngü de o yüzden
		// koşmuyor ve operatörün sebebini görmesi gerekiyor.
		writeJSON(w, http.StatusOK, map[string]any{"error": err.Error()})
		return
	}

	stored, err := s.store.Settings(r.Context())
	if err != nil {
		s.storeErr(w, "sync.settings", err)
		return
	}
	overridden := []string{}
	for _, v := range stored {
		if strings.HasPrefix(v.Key, "sync.") && v.Value != "" {
			overridden = append(overridden, v.Key)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":              eff.Enabled,
		"dry_run":              eff.Config.DryRun,
		"interval":             eff.Config.Interval.String(),
		"grace":                eff.Config.Limits.Grace.String(),
		"max_zero_fraction":    eff.Config.Limits.MaxZeroFraction,
		"min_zero_floor":       eff.Config.Limits.MinZeroFloor,
		"max_unknown_fraction": eff.Config.Limits.MaxUnknownFraction,
		"max_revoke_per_run":   eff.Config.Limits.MaxRevokePerRun,
		"overridden":           overridden,
	})
}
