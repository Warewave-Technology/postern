package httpapi

/*
 * Kilitlenmiş hesaplar ve onlarla ilgili insan kararı.
 *
 * ⚠️ BU EKRANIN VARLIK SEBEBİ: otomatik yol hesabı KİLİTLİYOR, silmiyor
 * (spec K3) — çünkü orada insan yok. Kilit geri alınabilir, silme değil.
 * Kararı alacak kişi buraya bakıyor; ekran olmazsa kilitli hesaplar
 * yalnızca veritabanında birikir ve kimse onlara dönmez.
 */

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Warewave-Technology/postern/v2/internal/store"
)

func (s *Server) registerHostAccountRoutes(mux *http.ServeMux) {
	if s.hostAccounts == nil {
		return
	}
	admin := func(h http.HandlerFunc) http.Handler {
		return noStore(s.requireSession(s.requireAdmin(s.sameOrigin(h))))
	}
	mux.Handle("GET /api/admin/host-accounts", admin(s.adminHostAccounts))
	mux.Handle("POST /api/admin/host-accounts/{target}/{username}/keep", admin(s.adminKeepHostAccount))
	mux.Handle("POST /api/admin/host-accounts/{target}/{username}/delete", admin(s.adminDeleteHostAccount))
}

/*
 * HostAccountRemover, hedefteki hesabı silen taraf.
 *
 * ⚠️ ARAYÜZ, ÇÜNKÜ SİLME HEDEFE GİDİYOR. httpapi'nin SSH bilmesi
 * gerekmiyor; bilseydi panelin uçları ile hedefe yazan kod aynı pakette
 * olurdu ve "panel ne yapabilir" sorusu okunmaz hâle gelirdi.
 */
type HostAccountRemover interface {
	Remove(ctx context.Context, target, username, actor string) error
}

// UseHostAccounts, kilitli hesap ekranını açar.
func (s *Server) UseHostAccounts(r HostAccountRemover) { s.hostAccounts = r }

type hostAccountView struct {
	Target   string `json:"target"`
	Username string `json:"username"`
	OSUser   string `json:"os_user"`
	/*
	 * Origin, hesabı postern'in mi açtığı yoksa devraldığı mı.
	 *
	 * ⚠️ EKRANDA GÖRÜNMEK ZORUNDA. Silme düğmesinin anlamı buna göre
	 * değişiyor: postern'in açtığı hesabı silmek onu geri almak, başka
	 * bir aracın açtığını silmek o aracın sahibi olduğu bir şeyi yok
	 * etmek.
	 */
	Origin    string    `json:"origin"`
	LockedAt  time.Time `json:"locked_at"`
	LastError string    `json:"last_error,omitempty"`
}

func (s *Server) adminHostAccounts(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.HostAccountsAwaitingDecision(r.Context())
	if err != nil {
		s.storeErr(w, "host_accounts.list", err)
		return
	}
	out := make([]hostAccountView, 0, len(rows))
	for _, a := range rows {
		out = append(out, hostAccountView{
			Target: a.TargetName, Username: a.Username, OSUser: a.OSUser,
			Origin: a.Origin, LockedAt: a.UpdatedAt,
			LastError: a.LastError,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": out})
}

/*
 * adminKeepHostAccount: hesap kilitli kalsın, bir daha sorma.
 *
 * ⚠️ DURUMU DEĞİŞTİRMİYOR. "Kalsın" demek hesabın açılması değil; kilit
 * duruyor, yalnızca karar bekleyenler listesinden çıkıyor. Açmak ayrı
 * bir şey ve kendiliğinden oluyor: kişi gruba geri alınırsa bir sonraki
 * bağlantısında hesap yeniden hazırlanıyor.
 */
func (s *Server) adminKeepHostAccount(w http.ResponseWriter, r *http.Request) {
	target, username := r.PathValue("target"), r.PathValue("username")
	if err := s.store.DecideHostAccount(r.Context(), target, username); err != nil {
		s.storeErr(w, "host_accounts.keep", err)
		return
	}
	s.audit(r, "account.keep_locked", target,
		username+"'s account stays locked on this target; the home directory is untouched")
	ok(w)
}

/*
 * adminDeleteHostAccount: hesabı hedeften sil.
 *
 * ⚠️ GERİ ALINAMAZ VE EV DİZİNİNİ DE ALIYOR (spec K8). Panel bunu
 * onaylatıyor; sunucu yine de postern'in açmadığı bir hesabı silmeyi
 * reddediyor — kanıt hedefin üstündeki grup üyeliği, bu uçtaki bir
 * parametre değil.
 */
func (s *Server) adminDeleteHostAccount(w http.ResponseWriter, r *http.Request) {
	target, username := r.PathValue("target"), r.PathValue("username")
	if err := s.hostAccounts.Remove(r.Context(), target, username, sessionUser(r)); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	s.audit(r, "account.delete", target,
		username+"'s account and home directory were deleted from this target")
	ok(w)
}
