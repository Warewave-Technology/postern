package hostacct

/*
 * Sıcak yolun kablolanmış hâli.
 *
 * ⚠️ TEK YERDE KURULUYOR, ÇÜNKÜ İKİ KAPI VAR. SSH kanalı ve panelin web
 * terminali aynı proxy.Deps'ten geçiyor; kancayı iki yerde kurmak,
 * birinde unutulduğunda "terminalden girince hesap açılıyor, ssh'tan
 * girince açılmıyor" gibi açıklanamaz bir fark üretirdi.
 */

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/Warewave-Technology/postern/v2/internal/ca"
	"github.com/Warewave-Technology/postern/v2/internal/model"
	"github.com/Warewave-Technology/postern/v2/internal/provision"
	"github.com/Warewave-Technology/postern/v2/internal/store"
	"github.com/Warewave-Technology/postern/v2/internal/upstream"
)

/*
 * Hook, proxy.Deps.EnsureAccount'a takılacak fonksiyonu üretir.
 *
 * ⚠️ DÖNEN HATA OTURUMU KESMİYOR — çağıran onu yalnızca dial hatasına
 * ekliyor (bkz. proxy.Deps.EnsureAccount). Burada hata döndürmek,
 * "hazırlanamadı" cümlesini taşımanın yolu; "içeri alma" emri değil.
 */
func Hook(db *store.Store, authority *ca.CA, logger *slog.Logger, poolMin, poolMax int) func(context.Context, model.User, model.Target) error {
	deps := Deps{
		Rules: db.GroupSudoRules,
		Row:   db.HostAccountFor,
		Save:  db.SaveHostAccount,
		/*
		 * ⚠️ SIRA: DİZİN, SONRA HAVUZ. AllocateUIDFromPool kişiye zaten
		 * ayrılmış bir numara varsa onu döndürüyor — dizinin verdiği
		 * numara senkron döngüsünde oraya yazılmış oluyor. Havuzdan
		 * numara yalnızca dizin bir şey söylemediğinde veriliyor;
		 * tersi, posixAccount koşan bir kurulumda aynı kişiyi iki
		 * numarayla yaşatırdı.
		 */
		UID: func(ctx context.Context, u model.User) (int, error) {
			row, err := db.AllocateUIDFromPool(ctx, u.Name, poolMin, poolMax)
			if err != nil {
				return 0, err
			}

			return row.UID, nil
		},
		Connect: func(ctx context.Context, t model.Target, reason string) (Runner, error) {
			return provision.Connect(ctx, t, authority, "system", reason)
		},
		Caps: func(ctx context.Context, r Runner) (upstream.ManageCapabilities, error) {
			sr, ok := r.(*provision.SSHRunner)
			if !ok {
				return upstream.ManageCapabilities{}, errNotSSH
			}

			return sr.Conn().Capabilities(ctx)
		},
		Audit: func(ctx context.Context, target, detail string) error {
			/*
			 * ⚠️ HEDEFE YAZILDIĞINDA DEFTERE SATIR, HIZLI ŞERİTTE YOK.
			 * Her bağlantı satır yazsaydı defter, hiçbir şeyin
			 * değişmediği milyonlarca satırla dolar ve içindeki gerçek
			 * yazma olayları görünmez olurdu.
			 */
			return db.LogAdmin(ctx, store.AdminLogEntry{
				At: time.Now(), Actor: "system", Via: "sync",
				Action: "account.provision", Entity: target, Details: detail,
			})
		},
	}

	return func(ctx context.Context, u model.User, t model.Target) error {
		out := Ensure(ctx, deps, u, t)
		if out.Reason != "" {
			return errReason(out.Reason)
		}
		if out.Wrote && logger != nil {
			logger.Info("prepared an account on a target",
				"target", t.Name, "user", u.Name, "os_user", u.OSUser)
		}

		return nil
	}
}

/*
 * VerifyHook, proxy.Deps.VerifyAccount'a takılacak fonksiyonu üretir.
 *
 * ⚠️ ONARIM İÇİN SICAK YOLUN KENDİSİ VERİLİYOR, İKİNCİ BİR YAZMA YOLU
 * DEĞİL. Hesabı hazırlamanın tek bir uygulaması olmalı; buraya ikinci
 * bir "eksikse şunu yaz" yazsaydık, biri değişip öbürü kaldığında aynı
 * makinede iki farklı istenen durum üretirdi.
 */
func VerifyHook(db *store.Store, logger *slog.Logger,
	repair func(context.Context, model.User, model.Target) error,
) func(context.Context, *upstream.Conn, model.User, model.Target) {
	d := VerifyDeps{
		Rules: db.GroupSudoRules,
		Row:   db.HostAccountFor,
		Save:  db.SaveHostAccount,
		/*
		 * ⚠️ AKTÖR KİŞİ, "system" DEĞİL. Komut onun bağlantısında,
		 * hedefin günlüklerinde onun adına koştu; deftere sistem adına
		 * yazmak, hedefteki izle postern'in defterini birbirine
		 * bağlanamaz hâle getirirdi. via=probe, çünkü bu da kişinin
		 * yazmadığı bir komut (bkz. proxy.maybeProbe).
		 */
		Audit: func(ctx context.Context, target, actor, detail string) error {
			return db.LogAdmin(ctx, store.AdminLogEntry{
				At: time.Now(), Actor: actor, Via: "probe",
				Action: "account.verify", Entity: target, Details: detail,
			})
		},
		Repair: repair,
		Logger: logger,
	}

	return func(ctx context.Context, c *upstream.Conn, u model.User, t model.Target) {
		Verify(ctx, d, c, u, t)
	}
}

type errReason string

func (e errReason) Error() string { return string(e) }

const errNotSSH = errReason("the management connection is not an SSH runner")

/*
 * NewLockWorker, push path'in delivery'sini kurar.
 *
 * ⚠️ AYNI KABLOLAMA, AYNI YERDE. Hook ile birlikte kuruluyor: hesap
 * açabilen ama kapatamayan bir kurulum, CyberArk'ın var olma sebebinin
 * tam tersi olurdu — ve ikisini ayrı anahtarlara bağlamak, birini
 * unutmayı mümkün kılardı (JIT süpürücüsünün yanındaki aynı gerekçe).
 */
func NewLockWorker(db *store.Store, authority *ca.CA, logger *slog.Logger, interval time.Duration) *Worker {
	return NewWorker(WorkerDeps{
		Owed:   db.HostAccountsOwedALock,
		Active: db.ActiveHostAccounts,
		Target: db.Target,
		Save:   db.SaveHostAccount,
		Connect: func(ctx context.Context, t model.Target, reason string) (Runner, error) {
			return provision.Connect(ctx, t, authority, "system", reason)
		},
		Caps: func(ctx context.Context, r Runner) (upstream.ManageCapabilities, error) {
			sr, ok := r.(*provision.SSHRunner)
			if !ok {
				return upstream.ManageCapabilities{}, errNotSSH
			}

			return sr.Conn().Capabilities(ctx)
		},
		Audit: func(ctx context.Context, target, detail string) error {
			return db.LogAdmin(ctx, store.AdminLogEntry{
				At: time.Now(), Actor: "system", Via: "sync",
				Action: "account.lock", Entity: target, Details: detail,
			})
		},
		Logger: logger,
	}, interval)
}

/*
 * Remover, kilitli bir hesabı hedeften silen taraf (panelin kararı).
 *
 * ⚠️ SİLME KANIT İSTİYOR VE KANIT HEDEFTE. postern'in açmadığı bir
 * hesabı silmek geri alınamaz ve o hesap postern'in değil; kanıt,
 * makinedeki postern-managed (ya da geçici hesapta postern-jit)
 * üyeliği. Veritabanındaki kaynak kaydı yetmiyor: host yeniden kurulmuş
 * ya da aynı adla başka biri hesap açmış olabilir.
 */
type Remover struct {
	db        *store.Store
	authority *ca.CA
	logger    *slog.Logger
}

func NewRemover(db *store.Store, authority *ca.CA, logger *slog.Logger) *Remover {
	return &Remover{db: db, authority: authority, logger: logger}
}

func (rm *Remover) Remove(ctx context.Context, targetName, username, actor string) error {
	row, err := rm.db.HostAccountFor(ctx, targetName, username)
	if err != nil {
		return err
	}
	target, terr := rm.db.Target(ctx, targetName)
	if terr != nil {
		return terr
	}

	runner, cerr := provision.Connect(ctx, target, rm.authority, actor, "deleting "+username+"'s account")
	if cerr != nil {
		return errReason("could not reach the target: " + cerr.Error())
	}
	defer func() { _ = runner.Close() }()

	caps, kerr := runner.Conn().Capabilities(ctx)
	if kerr != nil {
		return errReason("could not measure the target: " + kerr.Error())
	}
	facts, ferr := provision.Account(ctx, runner, row.OSUser)
	if ferr != nil {
		return errReason("could not read the account on the target: " + ferr.Error())
	}
	if !facts.Exists {
		// Hedefte zaten yok: kayıt buna göre kapanıyor.
		return rm.db.RemoveHostAccount(ctx, targetName, username)
	}

	principals := provision.PrincipalsPatternFor(ctx, runner, row.OSUser, caps.PrincipalsFile)
	var file string
	if principals != "" {
		if p, perr := provision.PrincipalsPath(principals, row.OSUser); perr == nil {
			file = p
		}
	}

	steps, perr := provision.RevokePlan(caps, provision.Revoke{
		User: row.OSUser, Mode: provision.ModeDelete,
		UID: facts.UID, Home: facts.Home,
		CreatedByPostern: facts.CreatedByPostern(),
		PrincipalsFile:   file,
	})
	if perr != nil {
		return errReason(perr.Error())
	}

	rep := provision.Apply(ctx, runner, steps)
	if rep.Failed() > 0 || rep.Unreachable() > 0 {
		return errReason(fmt.Sprintf("%d of %d steps did not finish on the target",
			rep.Failed()+rep.Unreachable(), len(steps)))
	}

	return rm.db.RemoveHostAccount(ctx, targetName, username)
}

/*
 * NewSweeper, sürüklenme süpürücüsünü kurar.
 *
 * precreate false ise Grants BAĞLANMIYOR — yani önden açma kodu hiç
 * koşmuyor, bir bayrağın içinde "hayır" diye durmuyor. Manifestonun
 * cümlesi varsayılanda kodun şeklinde görünsün diye.
 */
func NewSweepWorker(db *store.Store, authority *ca.CA, logger *slog.Logger,
	interval time.Duration, precreate bool, poolMin, poolMax int,
) *Sweeper {
	d := SweepDeps{
		Rows:   db.ActiveHostAccountRows,
		User:   db.User,
		Target: db.Target,
		Rules:  db.GroupSudoRules,
		Save:   db.SaveHostAccount,
		UID: func(ctx context.Context, u model.User) (int, error) {
			row, err := db.AllocateUIDFromPool(ctx, u.Name, poolMin, poolMax)
			if err != nil {
				return 0, err
			}

			return row.UID, nil
		},
		Connect: func(ctx context.Context, t model.Target, reason string) (Runner, error) {
			return provision.Connect(ctx, t, authority, "system", reason)
		},
		Caps: func(ctx context.Context, r Runner) (upstream.ManageCapabilities, error) {
			sr, ok := r.(*provision.SSHRunner)
			if !ok {
				return upstream.ManageCapabilities{}, errNotSSH
			}

			return sr.Conn().Capabilities(ctx)
		},
		Audit: func(ctx context.Context, target, detail string) error {
			return db.LogAdmin(ctx, store.AdminLogEntry{
				At: time.Now(), Actor: "system", Via: "sync",
				Action: "account.sweep", Entity: target, Details: detail,
			})
		},
		Logger: logger,
	}
	if precreate {
		d.Grants = db.GrantsWithoutAccounts
	}

	return NewSweeper(d, interval)
}
