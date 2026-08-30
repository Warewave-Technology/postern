package httpapi

// Onay kuyruğunun yönetim yüzeyi.
//
// ⚠️ Kuyruk satırı KARARLI KİMLİKLE anahtarlı (göç 022): reddedilen
// kişi kaynakta adını değiştirip yeniden başvuramaz, ve kaç kez
// denerse denesin tek satır oluşur.

import (
	"net/http"
	"strings"
)

func (s *Server) registerPendingRoutes(mux *http.ServeMux) {
	admin := func(h http.HandlerFunc) http.Handler {
		return noStore(s.requireSession(s.requireAdmin(s.sameOrigin(h))))
	}
	mux.Handle("GET /api/admin/pending", admin(s.adminListPending))
	mux.Handle("POST /api/admin/pending/approve", admin(s.adminApprovePending))
	mux.Handle("POST /api/admin/pending/reject", admin(s.adminRejectPending))
	mux.Handle("POST /api/admin/pending/forget", admin(s.adminForgetPending))
}

func (s *Server) adminListPending(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ListPending(r.Context())
	if err != nil {
		s.storeErr(w, "pending.list", err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

/*
 * adminApprovePending, hesabı açar.
 *
 * ⚠️ ROL VERMİYOR ve arayüz bunu söylemek zorunda: roller kişinin bir
 * sonraki girişinde canlı kaynaktan çözülüyor. Onay ekranındaki grup
 * listesi "ne görüldüğü"nü gösteriyor, bir yetki kaydı değil.
 */
func (s *Server) adminApprovePending(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID     string `json:"id"`
		OSUser string `json:"os_user"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.ID) == "" {
		writeErr(w, http.StatusBadRequest, "id is required")
		return
	}

	p, err := s.store.ApprovePending(r.Context(), in.ID,
		strings.TrimSpace(in.OSUser), sessionUser(r))
	if err != nil {
		s.storeErr(w, "pending.approve", err)
		return
	}
	s.audit(r, "pending.approve", p.Username,
		"created from "+p.Source+" identity "+p.Subject)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"username": p.Username,
		// Yetkinin nereden geleceğini açıkça söylüyoruz: hesap açıldı
		// ama rolleri henüz yok.
		"note": "the account exists; its roles are resolved from the source " +
			"at their next sign-in, and any manual role you add stays",
	})
}

func (s *Server) adminRejectPending(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID     string `json:"id"`
		Reason string `json:"reason"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.ID) == "" {
		writeErr(w, http.StatusBadRequest, "id is required")
		return
	}
	// ⚠️ Gerekçe ZORUNLU. Aynı kişi altı ay sonra yeniden başvurduğunda
	// kararı veren kişi orada olmayabilir; "neden hayır dedik" sorusunun
	// cevabı satırda durmalı.
	reason := strings.TrimSpace(in.Reason)
	if reason == "" {
		writeErr(w, http.StatusBadRequest,
			"a reason is required: whoever sees this next needs to know why")
		return
	}

	if err := s.store.RejectPending(r.Context(), in.ID, reason, sessionUser(r)); err != nil {
		s.storeErr(w, "pending.reject", err)
		return
	}
	s.audit(r, "pending.reject", in.ID, reason)
	ok(w)
}

/*
 * adminForgetPending, satırı tamamen siler.
 *
 * Reddi geri almanın yolu. Olmasaydı yanlışlıkla reddedilen biri bir
 * daha hiç başvuramazdı — red yapışkan olduğu için.
 */
func (s *Server) adminForgetPending(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID string `json:"id"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if err := s.store.ForgetPending(r.Context(), in.ID); err != nil {
		s.storeErr(w, "pending.forget", err)
		return
	}
	s.audit(r, "pending.forget", in.ID, "the identity may apply again")
	ok(w)
}
