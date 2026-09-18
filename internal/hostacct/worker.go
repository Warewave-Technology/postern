package hostacct

/*
 * Push path'in delivery'si: group'u düşen kişinin hesabını hedefte
 * kapatan döngü.
 *
 * ⚠️ NEDEN BİR WORKER, NEDEN store.RevokeGroup'un İÇİ DEĞİL. Bir
 * veritabanı yazmasını N hedefe SSH'a bağımlı yapmak, ağdaki bir arızayı
 * "grup kaldıramıyorum"a çevirirdi — ve panelde bir düğme, yüz makineye
 * bağlanma süresi kadar dönerdi.
 *
 * ⚠️ NEDEN İŞARET SÜTUNU YOK. İş, durumun kendisinden türetiliyor
 * (store.HostAccountsOwedALock): hedefte açık olan ama kişinin artık
 * erişemediği her satır borçlu. Bir `pending` bayrağı, onu yazmayı
 * unutan her yeni yazma yolunda sessiz bir boşluk açardı — ve o boşluk
 * tam olarak "group'u düşen kişi makinede açık kaldı" olurdu.
 *
 * ⚠️ SATIRA "locked" YAZMAK, HEDEF GERÇEKTEN KİLİTLENDİKTEN SONRA.
 * Önce yazmak kayda yalan yazmaktır: panel "kapandı" der, makinede hesap
 * durmaya devam eder ve kimse bir daha bakmaz.
 */

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/provision"
	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/upstream"
)

// WorkerDeps, döngünün dışarıya bağlandığı yerler.
type WorkerDeps struct {
	Owed   func(ctx context.Context, now time.Time) ([]store.HostAccount, error)
	Active func(ctx context.Context) (int, error)
	Target func(ctx context.Context, name string) (model.Target, error)
	Save   func(ctx context.Context, a store.HostAccount) error
	Audit  func(ctx context.Context, target, detail string) error

	Connect func(ctx context.Context, t model.Target, reason string) (Runner, error)
	Caps    func(ctx context.Context, r Runner) (upstream.ManageCapabilities, error)

	Logger *slog.Logger
	Now    func() time.Time

	/*
	 * MaxFraction ve MinFloor, tek koşuda kilitlenebilecek hesap tavanı.
	 *
	 * ⚠️ groupsync'teki tavanların aynısı ve aynı sebeple: dizindeki bir
	 * hata — yanlış kaldırılan bir grup, boşalan bir OU — bir anda
	 * herkesin erişimini bitirebilir. Tavan aşıldığında HİÇBİR ŞEY
	 * yapılmıyor; yarısını uygulamak hem hasarı verip hem sebebi
	 * gizlemek olurdu.
	 *
	 * İKİSİ BİRDEN aşılmalı: küçük bir kurulumda oran tek kişide
	 * tetiklenir, büyük bir kurulumda taban tek başına anlamsız kalır.
	 */
	MaxFraction float64
	MinFloor    int
}

func (d WorkerDeps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}

	return time.Now()
}

// Worker, periyodik kapatma döngüsü.
type Worker struct {
	deps     WorkerDeps
	interval time.Duration
}

func NewWorker(d WorkerDeps, interval time.Duration) *Worker {
	if interval <= 0 {
		interval = time.Minute
	}
	if d.MaxFraction <= 0 {
		d.MaxFraction = 0.25
	}
	if d.MinFloor <= 0 {
		d.MinFloor = 5
	}

	return &Worker{deps: d, interval: interval}
}

// Run, ctx bitene kadar koşar.
func (w *Worker) Run(ctx context.Context) {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.Tick(ctx)
		}
	}
}

// Tick, borçlu satırları kapatır. Hata döndürmüyor: döngü durmamalı.
func (w *Worker) Tick(ctx context.Context) {
	d := w.deps
	now := d.now()

	owed, err := d.Owed(ctx, now)
	if err != nil {
		w.log("could not read the accounts owed a lock", "error", err)
		return
	}
	if len(owed) == 0 {
		return
	}

	active, aerr := d.Active(ctx)
	if aerr != nil {
		w.log("could not count active accounts", "error", aerr)
		return
	}
	if blocked, why := capExceeded(len(owed), active, d.MaxFraction, d.MinFloor); blocked {
		/*
		 * ⚠️ HİÇBİR ŞEY YAPILMIYOR VE SEBEP YAZILIYOR. Yarısını
		 * uygulamak, hasarı verip sebebi gizlemek olurdu; operatörün
		 * göreceği tek şey "bazıları kapandı" olurdu ve hangisinin neden
		 * kapandığı sorusunun cevabı hiçbir yerde durmazdı.
		 */
		w.log("refusing to lock: the blast radius cap was reached", "reason", why)
		return
	}

	for _, row := range owed {
		w.lockOne(ctx, row, now)
	}
}

func (w *Worker) lockOne(ctx context.Context, row store.HostAccount, now time.Time) {
	d := w.deps

	target, terr := d.Target(ctx, row.TargetName)
	if terr != nil {
		w.retry(ctx, row, now, "the target could not be read: "+terr.Error())
		return
	}

	runner, cerr := d.Connect(ctx, target, "locking "+row.Username+"'s account")
	if cerr != nil {
		w.retry(ctx, row, now, "could not reach the target: "+cerr.Error())
		return
	}
	defer func() { _ = runner.Close() }()

	caps, kerr := d.Caps(ctx, runner)
	if kerr != nil {
		w.retry(ctx, row, now, "could not measure the target: "+kerr.Error())
		return
	}

	principals := provision.PrincipalsPatternFor(ctx, runner, row.OSUser, caps.PrincipalsFile)
	var file string
	if principals != "" {
		if p, perr := provision.PrincipalsPath(principals, row.OSUser); perr == nil {
			file = p
		}
	}

	/*
	 * ⚠️ HESABIN GERÇEKLERİ HEDEFTEN OKUNUYOR. RevokePlan sistem
	 * hesaplarına dokunmayı UID'ye bakarak reddediyor; numarayı
	 * vermemek, kilidin her seferinde reddedilmesi demek.
	 */
	facts, ferr := provision.Account(ctx, runner, row.OSUser)
	if ferr != nil {
		w.retry(ctx, row, now, "could not read the account on the target: "+ferr.Error())
		return
	}
	if !facts.Exists {
		/*
		 * Hesap makinede yok: kapatılacak bir şey de yok. Satır kilitli
		 * yazılıyor ki döngü onu her turda yeniden denemesin.
		 */
		w.settleLocked(ctx, row, now, "the account is not on the target any more")
		return
	}

	steps, perr := provision.RevokePlan(caps, RevokeFor(facts, row.OSUser, file))
	if perr != nil {
		w.retry(ctx, row, now, "refused before touching the target: "+perr.Error())
		return
	}

	rep := provision.Apply(ctx, runner, steps)
	if rep.Failed() > 0 || rep.Unreachable() > 0 {
		w.retry(ctx, row, now, fmt.Sprintf("%d of %d steps did not finish on the target",
			rep.Failed()+rep.Unreachable(), len(steps)))
		return
	}

	/*
	 * ⚠️ BURADA, VE ANCAK BURADA "locked" YAZILIYOR. Ve awaiting_decision
	 * ile birlikte: bu yolda insan yoktu, dolayısıyla hesabın silinip
	 * silinmeyeceğine bir kişi bakacak (K3).
	 */
	w.settleLocked(ctx, row, now, "")
}

// settleLocked, kilidi satıra yazar ve deftere geçer.
func (w *Worker) settleLocked(ctx context.Context, row store.HostAccount, now time.Time, note string) {
	d := w.deps
	row.State = store.HostAccountLocked
	row.AwaitingDecision = true
	row.Attempts = 0
	row.LastError = ""
	row.NextAttemptAt = time.Time{}
	row.UpdatedAt = now
	if serr := d.Save(ctx, row); serr != nil {
		w.log("the target was locked but the record could not be written",
			"target", row.TargetName, "user", row.Username, "error", serr)
		return
	}
	detail := fmt.Sprintf(
		"locked %s (account %s): no group grants this target any more; "+
			"the home directory is untouched and a person decides whether it goes",
		row.Username, row.OSUser)
	if note != "" {
		detail = fmt.Sprintf("%s (account %s): %s", row.Username, row.OSUser, note)
	}
	if d.Audit != nil {
		_ = d.Audit(ctx, row.TargetName, detail)
	}
	w.log("locked an account on a target", "target", row.TargetName, "user", row.Username)
}

func (w *Worker) retry(ctx context.Context, row store.HostAccount, now time.Time, reason string) {
	row.Attempts++
	row.LastError = reason
	row.NextAttemptAt = now.Add(backoff(row.Attempts))
	row.UpdatedAt = now
	_ = w.deps.Save(ctx, row)
	w.log("could not lock an account; will try again",
		"target", row.TargetName, "user", row.Username, "reason", reason,
		"next_attempt", row.NextAttemptAt)
}

func (w *Worker) log(msg string, args ...any) {
	if w.deps.Logger != nil {
		w.deps.Logger.Warn(msg, args...)
	}
}

/*
 * capExceeded, tavanın aşılıp aşılmadığı.
 *
 * İKİSİ BİRDEN aşılmalı: küçük bir kurulumda oran tek kişide tetiklenir
 * (bir hesabın kapanması %100'dür), büyük bir kurulumda taban tek başına
 * anlamsız kalır (on bin hesapta beş hesap bir hata değil, olağan gün).
 */
func capExceeded(owed, active int, maxFraction float64, minFloor int) (bool, string) {
	if owed < minFloor {
		return false, ""
	}
	if active <= 0 {
		return false, ""
	}
	share := float64(owed) / float64(active)
	if share <= maxFraction {
		return false, ""
	}

	return true, fmt.Sprintf("%d of %d active accounts (%.0f%%) would be locked in one run; "+
		"the cap is %.0f%% and at least %d", owed, active, share*100, maxFraction*100, minFloor)
}
