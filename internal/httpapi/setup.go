package httpapi

// Kurulum sihirbazının durumu.

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/Warewave-Technology/postern/internal/auth"
	"github.com/Warewave-Technology/postern/internal/store"
)

func (s *Server) registerSetupRoutes(mux *http.ServeMux) {
	admin := func(h http.HandlerFunc) http.Handler {
		return noStore(s.requireSession(s.requireAdmin(s.sameOrigin(h))))
	}
	mux.Handle("POST /api/admin/setup/complete", admin(s.adminSetupComplete))
	mux.Handle("POST /api/admin/users/{name}/state", admin(s.adminSetUserState))
	mux.Handle("POST /api/admin/users/{name}/purge", admin(s.adminPurgeUser))
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

	// ⚠️ SİLİNDİYSE AÇIK SEKMESİ DE KAPANIYOR. accountStillOpen bunu
	// bir sonraki istekte zaten yapıyor, ama o istek gelmeden hesap
	// purge edilip ad yeniden kullanılırsa artık yapamıyor (bkz.
	// adminPurgeUser). Burada düşürmek o pencereyi hiç açmıyor.
	if in.State == store.StateDeleted {
		s.webSessions.DestroyUser(name)
	}

	s.audit(r, "user.state", name, "set to "+in.State)
	s.logger.Warn("account state changed", "actor", sessionUser(r),
		"user", name, "state", in.State)
	ok(w)
}

/*
 * adminPurgeUser: POST /api/admin/users/{name}/purge
 *
 * ⚠️ SATIRI SİLMİYOR, ADI SERBEST BIRAKIYOR. Denetim kaydı kullanıcı
 * adını METİN olarak saklıyor; satır yok olursa geçmişteki o adın kime
 * ait olduğu cevapsız kalır ve aynı adı alan yeni kişiyle karışır.
 *
 * Panelden yapılabilir olması bilinçli: nadir ama ENGELLEYİCİ bir işlem
 * (aynı adla yeni biri gelene kadar kimse fark etmiyor), ve host'a
 * bağlamak tam da o an gereken şeyi zorlaştırırdı.
 */
func (s *Server) adminPurgeUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	// Kendi hesabını purge etmek: hesabın zaten 'deleted' olması
	// gerektiği için ulaşılamaz bir durum, ama açıkça kapatıyoruz.
	if name == sessionUser(r) {
		writeErr(w, http.StatusBadRequest, "you cannot purge your own account")
		return
	}

	res, err := s.store.PurgeAccount(r.Context(), name, time.Now())
	if err != nil {
		s.storeErr(w, "user.purge", err)
		return
	}

	/*
	 * ⚠️ AÇIK PANEL OTURUMLARI DA DÜŞÜYOR — VE BU ŞART.
	 *
	 * Oturum haritası kullanıcı adının METNİYLE anahtarlanıyor ve
	 * purge tam olarak o adı serbest bırakıyor. Düşürülmezse, adı
	 * yeniden kullanılan hesabın oturumu YENİ kişiye çözülür:
	 * accountStillOpen her istekte RefuseIfDeleted çağırıyor ama ad
	 * artık yeni satıra denk geldiği için nil dönüyor, yani kontrol
	 * geçiliyor.
	 *
	 * Ayrılan kişinin uyuyan sekmesi, yeni işe girenin rolleriyle,
	 * onun hedeflerinde ve onun adına denetim satırı yazarak
	 * çalışmaya devam ederdi — kayıtlardan ayırt edilemez şekilde.
	 *
	 * accountStillOpen'ın kendi düşürmesi bu boşluğu kapatmıyor: o,
	 * satırın GİTMİŞ olmasına bakıyor ve ad yeniden yaratıldıktan
	 * sonra satır gitmiş değil.
	 */
	dropped := s.webSessions.DestroyUser(name)

	// ⚠️ İZ ŞART: kim, ne zaman, neyi serbest bıraktı.
	s.audit(r, "user.purge", name, fmt.Sprintf(
		"username released on %s; %d key(s), %d role(s) and %d panel session(s) "+
			"removed; the row is kept so audit entries naming %q stay readable",
		res.At.Format("2006-01-02"), res.Keys, res.Roles, dropped, name))
	s.logger.Warn("account purged", "actor", sessionUser(r), "user", name,
		"keys", res.Keys, "roles", res.Roles, "sessions", dropped)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "keys_released": res.Keys, "roles_released": res.Roles,
		"note": "the name is free again; the account row is kept so audit " +
			"entries naming it stay readable",
	})
}
