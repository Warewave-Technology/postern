package httpapi

// Kurulum sihirbazının durumu.

import (
	"net/http"
	"strconv"
	"time"

	"github.com/warewave/postern/internal/auth"
)

func (s *Server) registerSetupRoutes(mux *http.ServeMux) {
	admin := func(h http.HandlerFunc) http.Handler {
		return noStore(s.requireSession(s.requireAdmin(s.sameOrigin(h))))
	}
	mux.Handle("POST /api/admin/setup/complete", admin(s.adminSetupComplete))
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
