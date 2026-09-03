package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Warewave-Technology/postern/internal/store"
)

/*
 * Canlı oturumu kesme.
 *
 * ⚠️ BU UÇ ended_at YAZMAZ. Yalnızca oturumun bağlamını iptal eder;
 * bitişi, bugün de yazan yer yazar (proxy.Session.Close). Kestiğini
 * "ended_at = now" diyerek kaydeden bir uygulama, oturum akmaya devam
 * ederken denetim defterine "bitti" yazardı — yani düğme çalışmasa bile
 * çalışmış GÖRÜNÜRDÜ. Kesmenin kanıtı satırı değiştirmek değil, akışı
 * durdurmaktır.
 *
 * ⚠️ DENETİM SATIRI ÖNCE. Depoda iki karşıt örnek var; buradaki
 * recording.go'yu izliyor. Sonra yazsaydık, veritabanı o an düşen bir
 * kurulumda oturum kesilmiş ama KİMİN kestiği kaydedilmemiş olurdu —
 * yöneticinin izsiz iş yapabildiği bir yol. Yazamıyorsak kesmiyoruz.
 */

// adminTerminateSession: POST /api/admin/sessions/{id}/terminate
//
// ⚠️ DELETE DEĞİL. Bu API'de DELETE satır siliyor; oturum satırı ise
// denetim izi ve asla silinmiyor. Yorumda "DELETE" yazmak, POST'un
// önlemek için seçildiği yanlış okumayı geri getirirdi.
func (s *Server) adminTerminateSession(w http.ResponseWriter, r *http.Request) {
	if s.live == nil {
		// Kablolama hatası: UseLiveSessions çağrılmamış. 404 vermek
		// bunu "böyle bir uç yok" diye gösterip aramayı yanlış yere
		// yönlendirirdi.
		s.logger.Error("terminate called but the live-session registry is not wired")
		writeErr(w, http.StatusServiceUnavailable,
			"this bastion cannot close sessions: the live-session registry is not wired")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "session id is required")
		return
	}

	sess, err := s.store.Session(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		s.storeErr(w, "session.terminate", err)
		return
	}

	// ⚠️ ÜÇ AYRI CEVAP, TEK "başarısız" DEĞİL.
	//
	// "Bitmiş", "başka bir süreçte akıyor olabilir" ve "kesildi" farklı
	// gerçekler. Hepsini aynı hataya toplamak, operatöre yapılmamış bir
	// işi yapılmış gösterme riskinin ta kendisi.
	if !sess.Open() {
		writeErr(w, http.StatusConflict, "that session has already ended")
		return
	}

	if !s.live.Running(id) {
		// Satır açık ama bu süreçte akmıyor: ya postern çökmeden önce
		// açılmış sahipsiz bir iz, ya da başka bir örneğin oturumu.
		// İkisinde de yapabileceğimiz bir şey YOK ve bunu söylüyoruz.
		writeErr(w, http.StatusConflict,
			"that session is not running on this instance; its row is open but nothing here is carrying it "+
				"(it can be left over from a crash, or belong to another postern process)")
		return
	}

	actor := sessionUser(r)
	details := sess.User + " on " + sess.Target + " as " + sess.OSUser + " from " + sess.SrcIP

	// ⚠️ Denetim yazılamıyorsa kesmiyoruz — bkz. dosya başı.
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	defer cancel()
	if aerr := s.store.LogAdmin(auditCtx, store.AdminLogEntry{
		Actor: actor, Via: "web", Action: "session.terminate", Entity: id, Details: details,
	}); aerr != nil {
		s.logger.Error("admin audit write failed; refusing to terminate",
			"action", "session.terminate", "entity", id, "error", aerr)
		writeErr(w, http.StatusServiceUnavailable,
			"could not record who is closing this session, so it was not closed; try again shortly")
		return
	}

	if !s.live.Terminate(id, actor) {
		// Yukarıdaki Running ile burası arasında oturum kendiliğinden
		// bitmiş. Denetim satırı yazıldı ve kalıyor: "kesmeye çalıştı"
		// da bir olay. Cevap, olanı anlatıyor.
		s.logger.Info("session ended before it could be terminated", "session_id", id, "actor", actor)
		writeErr(w, http.StatusConflict, "that session ended on its own before it could be closed")
		return
	}

	s.logger.Warn("session terminated by administrator",
		"session_id", id, "actor", actor, "user", sess.User, "target", sess.Target)
	ok(w)
}
