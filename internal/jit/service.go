/*
 * Package jit, geçici erişimin yaşam döngüsü: bir hedefte süreli hesap
 * açmak, süresi dolunca oturumlarını kesip hesabı sökmek, ve olmadıysa
 * olmadığını yüksek sesle söylemek.
 *
 * ⚠️ BU PAKET HEDEFTE ROOT'LA İŞ YAPIYOR. Her giriş yolu iki kural
 * taşıyor: denetim satırı BAĞLANMADAN ÖNCE yazılıyor ve yazılamazsa
 * bağlanılmıyor (httpapi/terminate.go ile aynı gerekçe); hedefe giden her
 * komut provision'ın planından geçiyor, burada komut kurulmuyor.
 */
package jit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/Warewave-Technology/postern/internal/ca"
	"github.com/Warewave-Technology/postern/internal/provision"
	"github.com/Warewave-Technology/postern/internal/proxy"
	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/sudoers"
)

const (
	/*
	 * MinDuration / MaxDuration, bir hakkın süresinin sınırları.
	 *
	 * ⚠️ ALT SINIR SÜPÜRÜCÜNÜN TURUNDAN UZUN. Süpürücü dakikada bir
	 * bakıyor; bir dakikalık hak, daha uygulanmadan geri alınmaya
	 * başlayabilirdi. ÜST SINIR "geçici"nin anlamını koruyor: otuz günden
	 * uzun bir hak kalıcı erişimdir ve o rol/hedef bağıyla verilmeli.
	 */
	MinDuration = 5 * time.Minute
	MaxDuration = 30 * 24 * time.Hour

	// sweepEvery, süpürücünün iki turu arasındaki süre.
	sweepEvery = time.Minute
)

var (
	ErrNotEnabled = errors.New("jit: management is not enabled on this bastion")
	ErrRevoked    = errors.New("jit: the grant has already been revoked")
)

// Service, hakların yaşam döngüsünü yürütür.
type Service struct {
	store     *store.Store
	authority *ca.CA
	live      *proxy.Live
	logger    *slog.Logger

	// now, testlerin saati ileri alabilmesi için.
	now func() time.Time
}

// New, hizmeti kurar. live nil olabilir: o zaman süresi dolan hakkın açık
// oturumları kesilmez (yalnızca hesap sökülür) ve bu loglanır.
func New(db *store.Store, authority *ca.CA, live *proxy.Live, logger *slog.Logger) *Service {
	return &Service{store: db, authority: authority, live: live, logger: logger, now: time.Now}
}

// Request, istenen hak.
type Request struct {
	// Username, postern kullanıcısı; hedefteki hesap onun os_user'ı.
	Username string
	Target   string
	Groups   []string
	Sudo     *sudoers.Rule
	Duration time.Duration
	// CleanupGroups, geri almada postern'in bu hak için açtığı gruplardan
	// boş kalanları silme izni. Panelin onay kutusu; varsayılan evet.
	CleanupGroups bool
}

// Outcome, bir grant ya da revoke koşusunun sonucu: kayıt ve hedefte
// adım adım ne olduğu.
type Outcome struct {
	Grant  store.JITGrant
	Report provision.Report
	// Terminated, geri almada kesilen açık oturum sayısı.
	Terminated int
}

/*
 * Grant, hedefte süreli hesap açar.
 *
 * Sıra: doğrula → denetim satırı → bağlan → yeteneği ölç → durumu oku →
 * planla → KAYDI YAZ → uygula → sonucu yaz. Kayıt uygulamadan önce
 * yazılıyor (bkz. store.CreateJITGrant); plan uygulamadan önce reddederse
 * (yönetilemeyen makine, önceden var olan hesap, kötü ad) hedefe hiç
 * dokunulmadığı için kayıt da yok.
 */
func (s *Service) Grant(ctx context.Context, req Request, actor string) (Outcome, error) {
	if s == nil || s.authority == nil {
		return Outcome{}, ErrNotEnabled
	}
	if req.Duration < MinDuration || req.Duration > MaxDuration {
		return Outcome{}, fmt.Errorf("jit: duration must be between %s and %s: %w",
			MinDuration, MaxDuration, store.ErrInvalid)
	}

	user, err := s.store.User(ctx, req.Username)
	if err != nil {
		return Outcome{}, fmt.Errorf("jit: user %q: %w", req.Username, err)
	}
	target, err := s.store.Target(ctx, req.Target)
	if err != nil {
		return Outcome{}, fmt.Errorf("jit: target %q: %w", req.Target, err)
	}

	now := s.now()
	grant := store.JITGrant{
		Username: user.Name, Target: target.Name, OSUser: user.OSUser,
		Groups: req.Groups, Sudo: req.Sudo, CleanupGroups: req.CleanupGroups,
		GrantedBy: actor, GrantedAt: now, ExpiresAt: now.Add(req.Duration),
	}
	desired := provision.Desired{Users: []provision.User{{
		Name: user.OSUser, Groups: req.Groups, JIT: true, ExpiresAt: grant.ExpiresAt, Sudo: req.Sudo,
	}}}
	for _, g := range req.Groups {
		desired.Groups = append(desired.Groups, provision.Group{Name: g})
	}

	details := fmt.Sprintf("granting %s (account %s) on %s for %s; groups %s",
		user.Name, user.OSUser, target.Name, req.Duration, listOrNone(req.Groups))
	if req.Sudo != nil {
		details += "; with a sudo rule"
	}
	if err := s.audit(ctx, actor, "jit.grant", target.Name, details); err != nil {
		return Outcome{}, err
	}

	runner, err := provision.Connect(ctx, target, s.authority, actor, "grant to "+user.Name)
	if err != nil {
		return Outcome{}, s.failed(ctx, actor, "jit.grant", target.Name, "could not connect", err)
	}
	defer func() { _ = runner.Close() }()

	caps, err := runner.Conn().Capabilities(ctx)
	if err != nil {
		return Outcome{}, s.failed(ctx, actor, "jit.grant", target.Name, "could not measure the target", err)
	}
	// Hedefin sshd'si principals dosyası istiyorsa geçici hesabınki de
	// yazılacak — yoksa hesap açılır ama sertifika onu açamaz.
	desired.PrincipalsFile = caps.PrincipalsFile
	observed, err := provision.Observe(ctx, runner, desired)
	if err != nil {
		return Outcome{}, s.failed(ctx, actor, "jit.grant", target.Name, "could not read the target", err)
	}
	steps, err := provision.Plan(caps, desired, observed)
	if err != nil {
		return Outcome{}, s.failed(ctx, actor, "jit.grant", target.Name, "refused before touching the target", err)
	}

	id, err := s.store.CreateJITGrant(ctx, grant)
	if err != nil {
		return Outcome{}, s.failed(ctx, actor, "jit.grant", target.Name, "could not record the grant", err)
	}
	grant.ID = id

	report := provision.Apply(ctx, runner, steps)
	/*
	 * Postern'in bu hak için AÇTIĞI gruplar kayda giriyor: geri almada
	 * boşsa silinecek olanlar bunlar — önceden var olan bir grup değil.
	 * Rapordan okunuyor (adım koştu ve "done" dedi), plandan değil:
	 * yarım kalan koşuda açılmamış grubu silmeye kalkmak olmaz.
	 *
	 * ⚠️ postern-jit KAYDA GİRMİYOR: ilk hak onu da açıyor ve rapor "done"
	 * diyor; kayda girseydi geri alma planı onu silmeye kalkıp reddedilir,
	 * hesap makinede kalırdı (entegrasyon testi tam bunu yaptı).
	 */
	var created []string
	for _, res := range report.Results {
		if res.Step.Kind == provision.StepGroupAdd && res.Outcome == provision.OutcomeDone &&
			res.Step.Subject != provision.JITGroup {
			created = append(created, res.Step.Subject)
		}
	}
	if len(created) > 0 {
		if cerr := s.store.SetJITGrantCreatedGroups(ctx, id, created); cerr != nil {
			s.logger.Error("groups created for a grant could not be recorded; they will not be cleaned up",
				"grant", id, "groups", created, "error", cerr)
		} else {
			grant.CreatedGroups = created
		}
	}
	if merr := s.store.MarkJITGrantApplied(ctx, id, report.OK(), report.Summary(), s.now()); merr != nil {
		// Makine değişti ama kayıt güncellenemedi: süpürücü kaydı vadesi
		// gelince toplayacak. Yüksek sesle, çünkü panel bu hakkı
		// "uygulanmadı" gösterecek.
		s.logger.Error("jit grant applied but its record could not be updated",
			"grant", id, "target", target.Name, "error", merr)
	}

	out := Outcome{Grant: grant, Report: report}
	if !report.OK() {
		return out, s.failed(ctx, actor, "jit.grant", target.Name, report.Summary(), report.FirstError())
	}
	_ = s.audit(ctx, actor, "jit.grant.applied", target.Name,
		fmt.Sprintf("grant %s for %s: %s; expires %s", id, user.Name, report.Summary(),
			grant.ExpiresAt.UTC().Format(time.RFC3339)))

	return out, nil
}

/*
 * Revoke, hakkı geri alır: açık oturumlar kesilir, hesap ve dosyaları
 * sökülür. Elle ve otomatik geri alma bu tek yoldan geçiyor.
 *
 * ⚠️ OTURUMLAR ÖNCE, HESAP SONRA. Hesap silinirken oturum açık kalsaydı,
 * kabuk sahipsiz bir UID ile koşmaya devam ederdi; sökme planı süreçleri
 * öldürüyor ama bastion'daki oturum kaydı ancak burada kapanıyor.
 */
func (s *Service) Revoke(ctx context.Context, id, actor, via string) (Outcome, error) {
	if s == nil || s.authority == nil {
		return Outcome{}, ErrNotEnabled
	}
	g, err := s.store.JITGrant(ctx, id)
	if err != nil {
		return Outcome{}, err
	}
	if !g.Active() {
		return Outcome{Grant: g}, ErrRevoked
	}

	if err := s.auditVia(ctx, actor, via, "jit.revoke", g.Target,
		fmt.Sprintf("revoking grant %s: %s (account %s)", g.ID, g.Username, g.OSUser)); err != nil {
		return Outcome{Grant: g}, err
	}

	out := Outcome{Grant: g}
	out.Terminated = s.terminateSessions(ctx, g, actor)

	target, err := s.store.Target(ctx, g.Target)
	if err != nil {
		return out, s.revokeFailed(ctx, g, actor, via, "target is no longer registered", err)
	}
	runner, err := provision.Connect(ctx, target, s.authority, actor, "revoke grant "+g.ID)
	if err != nil {
		return out, s.revokeFailed(ctx, g, actor, via, "could not connect", err)
	}
	defer func() { _ = runner.Close() }()

	caps, err := runner.Conn().Capabilities(ctx)
	if err != nil {
		return out, s.revokeFailed(ctx, g, actor, via, "could not measure the target", err)
	}
	facts, err := provision.Account(ctx, runner, g.OSUser)
	if err != nil {
		return out, s.revokeFailed(ctx, g, actor, via, "could not read the account", err)
	}

	var steps []provision.Step
	var sudoFiles []string
	if g.Sudo != nil {
		sudoFiles = []string{provision.UserSudoPath(g.OSUser)}
	}
	principals, err := provision.PrincipalsPath(caps.PrincipalsFile, g.OSUser)
	if err != nil {
		return out, s.revokeFailedAfter(ctx, g, actor, via, "refused to locate the principals file", err, 6*time.Hour)
	}
	deleteGroups, err := s.groupsToDelete(ctx, runner, g)
	if err != nil {
		return out, s.revokeFailed(ctx, g, actor, via, "could not read the groups", err)
	}
	if facts.Exists {
		steps, err = provision.RevokePlan(caps, provision.Revoke{
			User: g.OSUser, Mode: provision.ModeDelete, UID: facts.UID,
			InJITGroup: facts.InJITGroup(), Home: facts.Home, SudoFiles: sudoFiles,
			PrincipalsFile: principals, DeleteGroups: deleteGroups,
		})
		if err != nil {
			/*
			 * ⚠️ PLANIN REDDİ TEKRARLA GEÇMEZ. "Hesap postern-jit'te değil"
			 * bir sonraki turda da öyle olacak; sık denemek hedefin
			 * günlüğünü root girişleriyle doldurmaktan başka işe yaramaz.
			 * Hata kayıtta duruyor, panel gösteriyor, karar yöneticinin.
			 */
			return out, s.revokeFailedAfter(ctx, g, actor, via, "refused to delete the account", err, 6*time.Hour)
		}
	} else {
		/*
		 * Hesap gitmiş (yedek süre, elle silme, önceki yarım deneme) ama
		 * sudo dosyası kalmış olabilir. Sökme planı hesapsız çalışmıyor;
		 * yalnızca dosya kaldırılıyor ve yol, planın kabul edeceği yolun
		 * aynısı.
		 */
		steps, err = provision.RemoveSudoFilesPlan(sudoFiles)
		if err != nil {
			return out, s.revokeFailedAfter(ctx, g, actor, via, "refused to remove the sudo file", err, 6*time.Hour)
		}
		// Principals dosyası da kalmış olabilir; hesapsız da kaldırılıyor.
		if principals != "" {
			st, perr := provision.PrincipalRemoveStep(principals, g.OSUser)
			if perr != nil {
				return out, s.revokeFailedAfter(ctx, g, actor, via, "refused to remove the principals file", perr, 6*time.Hour)
			}
			steps = append(steps, st)
		}
		// Açılmış gruplar da: hesap gitmiş, grup boş kalmış olabilir.
		gsteps, gerr := provision.GroupDeleteSteps(caps, deleteGroups)
		if gerr != nil {
			return out, s.revokeFailedAfter(ctx, g, actor, via, "refused to remove a group", gerr, 6*time.Hour)
		}
		steps = append(steps, gsteps...)
	}

	report := provision.Apply(ctx, runner, steps)
	out.Report = report
	if !report.OK() {
		return out, s.revokeFailed(ctx, g, actor, via, report.Summary(), report.FirstError())
	}

	summary := report.Summary()
	if !facts.Exists {
		summary = "account was already gone; " + summary
	}
	if leftover := leftoverReport(report); leftover != "" {
		summary += "; left behind: " + leftover
	}
	if merr := s.store.MarkJITGrantRevoked(ctx, g.ID, summary, s.now()); merr != nil {
		s.logger.Error("jit grant revoked but its record could not be updated", "grant", g.ID, "error", merr)
	}
	_ = s.auditVia(ctx, actor, via, "jit.revoke.done", g.Target,
		fmt.Sprintf("grant %s for %s: %s; %d open session(s) closed", g.ID, g.Username, summary, out.Terminated))

	return out, nil
}

/*
 * groupsToDelete, hakla açılmış gruplardan artık KİMSENİN kullanmadığını
 * seçer: hesap dışında üyesi yok ve kimsenin birincil grubu değil.
 *
 * ⚠️ YALNIZCA POSTERN'İN AÇTIKLARI (CreatedGroups) ve yalnızca izinle
 * (CleanupGroups). Sistem numaralı bir grup listede olamaz (groupadd
 * GID_MIN üstü verir) ama yine de atlanıyor: "boş" görünen bir sistem
 * grubunu silmek makineyi bozar.
 */
func (s *Service) groupsToDelete(ctx context.Context, r provision.Runner, g store.JITGrant) ([]string, error) {
	if !g.CleanupGroups {
		return nil, nil
	}
	var out []string
	for _, name := range g.CreatedGroups {
		u, err := provision.GroupUsage(ctx, r, name)
		if err != nil {
			return nil, err
		}
		if !u.Exists || u.GID < provision.MinJITGID || u.UsedByOthers(g.OSUser) {
			continue
		}
		out = append(out, name)
	}
	return out, nil
}

/*
 * Sweep, süresi dolmuş hakları geri alır. Her turda her hak için ayrı bir
 * bağlantı; başarısızlık bir sonraki hakkı durdurmuyor.
 */
func (s *Service) Sweep(ctx context.Context) (revoked, failed int) {
	due, err := s.store.DueJITGrants(ctx, s.now())
	if err != nil {
		s.logger.Error("jit sweep could not list due grants", "error", err)
		return 0, 0
	}
	for _, g := range due {
		if ctx.Err() != nil {
			return revoked, failed
		}
		if _, err := s.Revoke(ctx, g.ID, "system", "system"); err != nil {
			failed++
			s.logger.Warn("jit grant could not be revoked", "grant", g.ID,
				"user", g.Username, "target", g.Target, "attempt", g.RevokeAttempts+1, "error", err)
			continue
		}
		revoked++
		s.logger.Info("jit grant revoked", "grant", g.ID, "user", g.Username, "target", g.Target)
	}

	return revoked, failed
}

// Run, süpürücüyü bağlam bitene kadar koşturur; açılışta bir tur yapıyor
// ki yeniden başlatma sırasında dolan haklar bir dakika daha beklemesin.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(sweepEvery)
	defer t.Stop()
	for {
		s.Sweep(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// terminateSessions, hakkın sahibinin o hedefteki açık oturumlarını keser.
func (s *Service) terminateSessions(ctx context.Context, g store.JITGrant, actor string) int {
	if s.live == nil {
		s.logger.Warn("jit revoke cannot close open sessions: live registry not wired",
			"grant", g.ID)
		return 0
	}
	open, err := s.store.OpenSessions(ctx)
	if err != nil {
		s.logger.Error("jit revoke could not list open sessions", "grant", g.ID, "error", err)
		return 0
	}
	n := 0
	for _, sn := range open {
		if sn.User != g.Username || sn.Target != g.Target {
			continue
		}
		if s.live.Terminate(sn.ID, actor) {
			n++
		}
	}

	return n
}

func (s *Service) audit(ctx context.Context, actor, action, entity, details string) error {
	return s.auditVia(ctx, actor, "web", action, entity, details)
}

/*
 * auditVia, denetim satırını yazar; yazamazsa HATA döner ve çağıran
 * bağlanmıyor.
 *
 * ⚠️ İSTEK BAĞLAMI KULLANILMIYOR (WithoutCancel): satır, olan bir şeyin
 * kaydı; isteği yarıda bırakan biri izi sildirmemeli.
 */
func (s *Service) auditVia(ctx context.Context, actor, via, action, entity, details string) error {
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := s.store.LogAdmin(actx, store.AdminLogEntry{
		Actor: actor, Via: via, Action: action, Entity: entity, Details: details,
	}); err != nil {
		s.logger.Error("admin audit write failed; refusing to touch the target",
			"action", action, "entity", entity, "error", err)
		return fmt.Errorf("jit: could not record %s in the admin log, so nothing was done: %w", action, err)
	}

	return nil
}

// failed, bir grant koşusunun neden bitmediğini deftere ve çağırana söyler.
func (s *Service) failed(ctx context.Context, actor, action, entity, what string, err error) error {
	_ = s.audit(ctx, actor, action+".failed", entity, what+": "+err.Error())
	return fmt.Errorf("jit: %s: %w", what, err)
}

func (s *Service) revokeFailed(ctx context.Context, g store.JITGrant, actor, via, what string, err error) error {
	return s.revokeFailedAfter(ctx, g, actor, via, what, err, backoff(g.RevokeAttempts))
}

func (s *Service) revokeFailedAfter(ctx context.Context, g store.JITGrant, actor, via, what string, err error, wait time.Duration) error {
	reason := what + ": " + err.Error()
	if merr := s.store.MarkJITGrantRevokeFailed(ctx, g.ID, reason, s.now().Add(wait)); merr != nil {
		s.logger.Error("jit revoke failed and the failure could not be recorded", "grant", g.ID, "error", merr)
	}
	_ = s.auditVia(ctx, actor, via, "jit.revoke.failed", g.Target,
		fmt.Sprintf("grant %s for %s: %s; next attempt in %s", g.ID, g.Username, reason, wait))

	return fmt.Errorf("jit: %s: %w", what, err)
}

/*
 * backoff, başarısız geri alma denemeleri arasındaki bekleme.
 *
 * ⚠️ ÜST SINIR BİR SAAT. Süresi dolmuş bir root hesabı için "yarın
 * dene" kabul edilebilir bir cevap değil; ama her dakika denemek de
 * kapalı bir makineye karşı anlamsız. Hata her denemede kayıtta.
 */
func backoff(attempts int) time.Duration {
	switch {
	case attempts <= 0:
		return 2 * time.Minute
	case attempts == 1:
		return 5 * time.Minute
	case attempts == 2:
		return 15 * time.Minute
	default:
		return time.Hour
	}
}

// leftoverReport, sökme raporundaki "hesabın geride bıraktıkları" listesi.
func leftoverReport(rep provision.Report) string {
	for _, res := range rep.Results {
		if res.Step.Kind == provision.StepReportOwned && strings.TrimSpace(res.Output) != "" {
			return strings.TrimSpace(res.Output)
		}
	}

	return ""
}

func listOrNone(in []string) string {
	if len(in) == 0 {
		return "none"
	}

	return strings.Join(in, ",")
}
