package httpapi

// Kurulum sihirbazının durumu.

import (
	"net/http"
	"strconv"
	"time"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/store"
)

func (s *Server) registerSetupRoutes(mux *http.ServeMux) {
	admin := func(h http.HandlerFunc) http.Handler {
		return noStore(s.requireSession(s.requireAdmin(s.sameOrigin(h))))
	}
	mux.Handle("POST /api/admin/setup/complete", admin(s.adminSetupComplete))
	mux.Handle("POST /api/admin/users/{name}/state", admin(s.adminSetUserState))
}

/*
 * adminSetupComplete: POST /api/admin/setup/complete
 *
 * ⚠️ KAYNAK SEÇİLMEDEN TAMAMLANAMAZ. Sihirbazın var olma sebebi o
 * kararın verilmesi; "tamamlandı" işaretini kararsız bırakmak, ekranı
 * bir daha hiç göstermeyip kurulumu yarım bırakmak olurdu.
 */
func (s *Server) adminSetupComplete(w http.ResponseWriter, r *http.Request) {
	if _, stored, err := s.loginSource(r.Context()); err != nil {
		s.storeErr(w, "setup.complete", err)
		return
	} else if !stored {
		writeErr(w, http.StatusBadRequest,
			"choose a sign-in source before finishing setup — "+
				"otherwise the way in is only inferred from the config file")
		return
	}

	at := strconv.FormatInt(time.Now().Unix(), 10)
	if err := s.store.SetSetting(r.Context(), auth.KeySetupCompleted, at,
		false, sessionUser(r)); err != nil {
		s.storeErr(w, "setup.complete", err)
		return
	}
	s.audit(r, "setup.complete", "", "first-run setup finished")
	s.logger.Info("setup completed", "actor", sessionUser(r))
	ok(w)
}

/*
 * adminSetUserState: POST /api/admin/users/{name}/state
 *
 * ⚠️ PANELDEN YAPILABİLİR ve bu, yönetici bayrağından FARKLI bir karar.
 * is_admin panelden verilemiyor çünkü yetki YÜKSELTİYOR; hesabı
 * pasifleştirmek ise yetkiyi KALDIRIYOR. Kaldırma yönündeki bir işlemi
 * host'a bağlamak, olay müdahalesini yavaşlatmaktan başka bir şey
 * yapmazdı.
 */
func (s *Server) adminSetUserState(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var in struct {
		State string `json:"state"`
	}
	if !readJSON(w, r, &in) {
		return
	}

	switch in.State {
	case store.StateActive, store.StateInactive, store.StateDeleted:
	default:
		writeErr(w, http.StatusBadRequest,
			"state must be active, inactive or deleted")
		return
	}

	/*
	 * ⚠️ KENDİNİ KAPATAMAZSIN.
	 *
	 * Kapatan kişi o anda oturumdadır ve bir sonraki isteğinde
	 * dışarıda kalır — hatasını düzeltmek için gereken kapıyı kendi
	 * kapatmış olur. Başkasını kapatmak serbest; kendini kapatmak,
	 * geri alınamayacağı için değil, geri ALACAK kişi kalmadığı için
	 * yasak.
	 */
	if name == sessionUser(r) && in.State != store.StateActive {
		writeErr(w, http.StatusBadRequest,
			"you cannot deactivate your own account — you would lose the way back")
		return
	}

	if err := s.store.SetAccountState(r.Context(), name, in.State); err != nil {
		s.storeErr(w, "user.state", err)
		return
	}
	s.audit(r, "user.state", name, "set to "+in.State)
	s.logger.Warn("account state changed", "actor", sessionUser(r),
		"user", name, "state", in.State)
	ok(w)
}
