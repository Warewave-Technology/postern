package httpapi

/*
 * Panelden yönetim erişimini denetleme: postern bu hedefi kendi yönetim
 * hesabıyla açabiliyor mu, ve açınca makinede ne buluyor?
 *
 * ⚠️ BU UÇ HİÇBİR ŞEY DEĞİŞTİRMİYOR. Hedefte koşan komutlar sabit ve salt
 * okuma (`id -un` bile değil; yalnızca upstream.CapabilityCommands ve
 * os-release). Hedefte değişiklik yapan yol ayrı olacak ve yeniden kimlik
 * doğrulama isteyecek; bu uçta istemiyoruz çünkü okumaya root'u
 * açıklayan bir kapı eklemek, okumayı zorlaştırıp hiçbir şeyi
 * korumuyor.
 *
 * ⚠️ AMA BAĞLANTININ KENDİSİ ROOT'LUK BİR KİMLİK. O yüzden denetim satırı
 * bağlanmadan ÖNCE yazılıyor ve yazılamazsa bağlanılmıyor (terminate.go
 * ile aynı kural): hedefin günlüğünde postern'in root girişi görünür
 * olup postern'in defterinde kimin başlattığı yazmıyorsa, o giriş
 * açıklanamaz.
 */

import (
	"context"
	"errors"
	"net/http"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/provision"
	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/upstream"
)

// manageSlots, aynı anda açık olabilecek yönetim bağlantısı sayısı.
const manageSlots = 2

/*
 * manageCheckTimeout, bir denetimin tamamı için üst sınır.
 *
 * El sıkışmanın kendi sınırı (dialTimeout) ve komutların bağlama bağlı
 * sınırı var; bu, ikisinin toplamının bir panel isteğini dakikalarca
 * tutmaması için.
 */
const manageCheckTimeout = 45 * time.Second

/*
 * registerManageRoutes, yönetim uçlarını YALNIZCA manage.enabled açıkken
 * kurar — kapalı özellik, kapalı yüzey. Panel hedef detayındaki
 * manage_enabled bayrağına bakıyor.
 */
func (s *Server) registerManageRoutes(mux *http.ServeMux) {
	if s.manageAuthority == nil {
		return
	}

	// POST, GET değil: hedefe ağdan bağlanan, root'luk bir kimlik kullanan
	// ve denetim satırı yazan bir eylem. GET olsaydı bir <img> etiketiyle
	// tetiklenebilirdi.
	mux.Handle("POST /api/admin/targets/{name}/manage/check",
		noStore(s.requireSession(s.requireAdmin(s.sameOrigin(http.HandlerFunc(s.adminManageCheck))))))
}

// manageCheckResult, denetimin panele giden cevabı.
type manageCheckResult struct {
	Target string `json:"target"`

	/*
	 * Stage, denetimin nerede bittiği: "connect" (bağlanılamadı),
	 * "measure" (bağlanıldı ama makine ölçülemedi) ya da "done".
	 *
	 * ⚠️ "YÖNETİLEMEZ" TEK BİR CEVAP DEĞİL. Hedefin CA'ya güvenmemesi,
	 * makinede visudo olmaması ve makinenin cevap vermemesi operatöre
	 * üç ayrı iş söylüyor; hepsini "not manageable" altında toplamak
	 * yanlış yere baktırırdı.
	 */
	Stage      string `json:"stage"`
	Manageable bool   `json:"manageable"`

	// Reason, operatörün okuyacağı cümle; Detail, arızanın ham metni.
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`

	/*
	 * CAFingerprint, bu bastion'ın CA'sının parmak izi.
	 *
	 * ⚠️ HER CEVAPTA VAR. Reddin en sık sebebi hedefin BAŞKA bir CA'ya
	 * güvenmesi; operatörün hedefteki /etc/ssh/postern_ca.pub ile
	 * karşılaştırabileceği şey bu satır.
	 */
	CAFingerprint string `json:"ca_fingerprint"`

	Family  string            `json:"family,omitempty"`
	Missing []string          `json:"missing"`
	Tools   map[string]string `json:"tools,omitempty"`

	CheckedAt time.Time `json:"checked_at"`
}

// adminManageCheck: POST /api/admin/targets/{name}/manage/check
func (s *Server) adminManageCheck(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	t, err := s.store.Target(r.Context(), name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		s.storeErr(w, "target.manage_check", err)
		return
	}

	// Yuva dolu ise BEKLEMİYORUZ: bekleyen istekler de bağlantı ve
	// goroutine tutuyor, ve tavanın amacı tam olarak o.
	select {
	case s.manageSlots <- struct{}{}:
		defer func() { <-s.manageSlots }()
	default:
		writeErr(w, http.StatusTooManyRequests,
			"another management check is already running; try again in a moment")
		return
	}

	actor := sessionUser(r)

	// ⚠️ Denetim satırı ÖNCE — bkz. dosya başı. Yazamıyorsak bağlanmıyoruz.
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	defer cancel()
	if aerr := s.store.LogAdmin(auditCtx, store.AdminLogEntry{
		Actor: actor, Via: "web", Action: "target.manage_check", Entity: t.Name,
		// ⚠️ "opening", "opened" DEĞİL: satır bağlanmadan önce yazılıyor ve
		// hedef reddederse düzeltilmiyor. Deftere olmuş gibi yazmak, reddedilen
		// bir denemeyi başarılı bir root girişi gibi okutmak olurdu.
		Details: "opening a management connection (two-minute certificate, read-only checks)",
	}); aerr != nil {
		s.logger.Error("admin audit write failed; refusing to open a management connection",
			"target", t.Name, "error", aerr)
		writeErr(w, http.StatusServiceUnavailable,
			"could not record who is opening this management connection, so it was not opened; "+
				"try again shortly")
		return
	}

	res := manageCheckResult{
		Target:        t.Name,
		CAFingerprint: ssh.FingerprintSHA256(s.manageAuthority.PublicKey()),
		Missing:       []string{},
		CheckedAt:     time.Now().UTC(),
	}

	ctx, stop := context.WithTimeout(r.Context(), manageCheckTimeout)
	defer stop()

	runner, err := provision.Connect(ctx, t, s.manageAuthority, actor, "check management access")
	if err != nil {
		res.Stage = "connect"
		res.Reason = connectReason(ctx, err)
		res.Detail = err.Error()
		s.logger.Warn("management check could not connect", "target", t.Name, "error", err)
		writeJSON(w, http.StatusOK, res)
		return
	}
	defer func() { _ = runner.Close() }()

	caps, err := runner.Conn().Capabilities(ctx)
	if err != nil {
		res.Stage = "measure"
		// "did not report", "stopped answering" DEĞİL: exec isteğini reddeden
		// bir hedef bağlantıyı koparmıyor, açıkça cevap veriyor (bkz.
		// upstream.ErrNoAnswer). "Sustu" demek operatörü ağa baktırırdı.
		res.Reason = "postern signed in with its management account, but the target " +
			"did not report whether the tool checks ran (a closed channel, or an exec " +
			"request it refused); nothing was changed"
		res.Detail = err.Error()
		s.logger.Warn("management check could not measure", "target", t.Name, "error", err)
		writeJSON(w, http.StatusOK, res)
		return
	}

	res.Stage = "done"
	res.Manageable = caps.Manageable()
	res.Family = caps.Family
	if caps.Missing != nil {
		res.Missing = caps.Missing
	}
	res.Tools = map[string]string{
		"add_user": caps.AddUser, "add_group": caps.AddGroup, "mod_user": caps.ModUser,
		"del_user": caps.DelUser, "del_group": caps.DelGroup, "visudo": caps.Visudo,
	}
	if !res.Manageable {
		res.Reason = "postern can sign in, but this machine lacks what it needs to be managed " +
			"safely; postern will not half-configure it"
	}

	writeJSON(w, http.StatusOK, res)
}

/*
 * connectReason, bağlanamamanın sebebini operatörün yapacağı işe çevirir.
 *
 * ⚠️ SINIFLAR upstream'den, METİNDEN DEĞİL. Hata dizgisini ayrıştırmak bir
 * bağımlılığın mesajı değiştiği gün sessizce yanlış cümleye düşerdi
 * (bkz. upstream/hostkey.go).
 */
func connectReason(ctx context.Context, err error) string {
	switch {
	/*
	 * ⚠️ İPTAL ÖNCE SORULUYOR. Bağlam el sıkışmanın ortasında dolunca
	 * dialer soketi kapatıyor; hedef host anahtarını çoktan sunmuşsa
	 * kütüphanenin hatası "kapalı soket" oluyor ve sınıflandırıcı bunu
	 * ret sayıyordu — cümle operatörü CA'yı karşılaştırmaya yollardı, oysa
	 * olan şey sekmenin kapanması ya da sürenin dolmasıydı.
	 */
	case ctx.Err() != nil:
		return "the check was cancelled or ran out of time before the target finished " +
			"answering; nothing was changed. Try again, and if it keeps happening the " +
			"target is answering too slowly"
	case errors.Is(err, upstream.ErrRefused):
		return "the target refused postern's management certificate. Either it does not " +
			"trust this bastion's CA (compare the fingerprint below with the target's " +
			"/etc/ssh/postern_ca.pub), or it has no management account — run the " +
			"postern_target role with postern_manage_host: true"
	case errors.Is(err, upstream.ErrHostKeyMismatch):
		return "the target presented a different host key than the one pinned for it, so " +
			"postern did not sign in. Rescan the key only if you know why it changed"
	case errors.Is(err, upstream.ErrHandshake):
		return "the connection opened but the SSH handshake did not finish: a silent target, " +
			"a port that is not SSH, or no algorithm in common"
	case errors.Is(err, upstream.ErrUnreachable):
		return "postern could not open a connection to the target's address"
	default:
		return "postern could not sign in to the target"
	}
}
