package groupsync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/ldap"
	"github.com/warewave/postern/internal/store"
)

// Directory, senkronizasyonun dizinden istediği tek şey.
//
// ⚠️ auth.GroupSource DEĞİL, ve bu bilinçli: ClaimGroups (OIDC claim
// kaynağı) bu soruları cevaplayamaz — bir claim ancak kullanıcı giriş
// yaparken gelir, "bu kişi hâlâ var mı" diye sorulamaz. ClaimGroups'u
// bu arayüze uydurmak, OIDC-only bir kurulumda sessizce herkesi iptal
// eden bir döngü başlatmak olurdu.
type Directory interface {
	Lookup(context.Context, auth.Identity) (ldap.LookupResult, error)
	Probe(context.Context) error
}

// Runner, periyodik senkronizasyonu yürütür.
type Runner struct {
	db     *store.Store
	logger *slog.Logger
	limits Limits

	// open, HER KOŞUDA yeni bir dizin bağlantısı üretir.
	//
	// Yapıcıda yakalanmış bir *ldap.Source DEĞİL: LDAP ayarları
	// panelden çalışma zamanında değişebiliyor (SwitchableGroupSource)
	// ve yakalanmış bir kaynak, operatörün çoktan değiştirdiği bir
	// dizine sorgu atmaya devam ederdi.
	open func(context.Context) (Directory, error)

	interval time.Duration
	timeout  time.Duration
	dryRun   bool
}

// Config, Runner'ın ayarları.
type Config struct {
	Interval time.Duration
	Timeout  time.Duration
	DryRun   bool
	Limits   Limits
}

func NewRunner(db *store.Store, open func(context.Context) (Directory, error),
	cfg Config, logger *slog.Logger) *Runner {
	if cfg.Interval <= 0 {
		cfg.Interval = 15 * time.Minute
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Minute
	}
	return &Runner{
		db: db, logger: logger, limits: cfg.Limits, open: open,
		interval: cfg.Interval, timeout: cfg.Timeout, dryRun: cfg.DryRun,
	}
}

// Report, bir koşunun sonucu.
type Report struct {
	Outcome string
	Reason  string

	Considered, Present, Absent, Unknown, Revoked, RolesChanged int

	// KeptManual, iptal edilmiş ama elle verilmiş rolleri DURAN
	// kullanıcılar. Ayrı raporlanıyor çünkü "iptal edildi" okuyup
	// erişimin tamamen bittiğini sanmak kolay.
	KeptManual []string
}

// RunOnce, tek bir senkronizasyon koşusu yapar.
func (r *Runner) RunOnce(ctx context.Context, trigger string) (Report, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	runID, err := r.db.StartSyncRun(ctx, "ldap", trigger, r.dryRun)
	if err != nil {
		return Report{}, err
	}

	rep, runErr := r.run(ctx, runID)

	// Koşu satırı her hâlükârda kapatılmalı — iptal edilen bir koşunun
	// SEBEBİ, olmayan bir koşudan daha değerli.
	finishCtx, fcancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer fcancel()

	if ferr := r.db.FinishSyncRun(finishCtx, store.SyncRun{
		ID: runID, Outcome: rep.Outcome, Reason: rep.Reason,
		Considered: rep.Considered, Present: rep.Present, Absent: rep.Absent,
		Unknown: rep.Unknown, Revoked: rep.Revoked, RolesChanged: rep.RolesChanged,
	}); ferr != nil {
		r.logger.Error("sync run bookkeeping failed", "run", runID, "error", ferr)
	}

	return rep, runErr
}

func (r *Runner) run(ctx context.Context, runID int64) (Report, error) {
	// 1) Kilit. Alamadıysak başka bir süreç zaten senkronize ediyor.
	release, acquired, err := r.db.TryLockSync(ctx)
	if err != nil {
		return Report{Outcome: "failed", Reason: err.Error()}, err
	}
	if !acquired {
		return Report{Outcome: "skipped", Reason: "another sync is already running"}, nil
	}
	defer release()

	// 2) Dizin yapılandırılmış mı?
	dir, err := r.open(ctx)
	if err != nil {
		if errors.Is(err, ldap.ErrNotConfigured) {
			return Report{Outcome: "skipped", Reason: "no directory configured"}, nil
		}
		return Report{Outcome: "failed", Reason: err.Error()}, err
	}

	// 3) ⚠️ HİÇBİR ŞEYE DOKUNMADAN ÖNCE: dizin şu an veri veriyor mu?
	//
	// Sıfır kullanıcı döndüren bir dizin ya arızalı ya geri yükleme
	// ortasında — herkesin silindiği bir şirket değil.
	if err := dir.Probe(ctx); err != nil {
		reason := "directory probe failed: " + err.Error()
		r.logger.Warn("sync aborted before touching anything", "run", runID, "reason", reason)
		return Report{Outcome: "aborted", Reason: reason}, nil
	}

	// 4) Adayları topla.
	candidates, err := r.db.SyncCandidates(ctx)
	if err != nil {
		return Report{Outcome: "failed", Reason: err.Error()}, err
	}

	rep := Report{Considered: len(candidates)}
	obs := make([]Observation, 0, len(candidates))

	for _, c := range candidates {
		if ctx.Err() != nil {
			return Report{Outcome: "failed", Reason: ctx.Err().Error()}, ctx.Err()
		}

		// ⚠️ POSTERN'İN sakladığı kullanıcı adı gönderiliyor, dizinin
		// döndürdüğü değil: users.username harf DUYARLI karşılaştırılıyor
		// (ciColumns'ta yok) ve dizinden gelen bir yazımı geri yazmak
		// eşleşmeyi bozardı.
		res, lerr := dir.Lookup(ctx, auth.Identity{Username: c.Username, Email: c.Email})
		if lerr != nil {
			r.logger.Debug("directory lookup failed", "user", c.Username, "error", lerr)
		}

		o := Observation{
			Username:     c.Username,
			Presence:     res.Presence,
			MissingSince: c.MissingSince,
			ManualRoles:  c.ManualRoles,
		}

		if res.Presence == ldap.PresencePresent {
			roles, _, rerr := r.db.RolesForGroups(ctx, res.Groups)
			if rerr != nil {
				// Rol çözümü başarısızsa bu kullanıcı hakkında bir şey
				// bilmiyoruz demektir — "grupsuz" saymak yanlış olurdu.
				o.Presence = ldap.PresenceUnknown
			} else {
				o.MappedRoles = roles
			}
		}

		switch o.Presence {
		case ldap.PresencePresent:
			rep.Present++
		case ldap.PresenceAbsent:
			rep.Absent++
		default:
			rep.Unknown++
		}
		obs = append(obs, o)
	}

	// 5) Karar (saf fonksiyon).
	plan := BuildPlan(time.Now(), obs, r.limits)
	if plan.Abort != "" {
		r.logger.Warn("sync aborted by blast-radius guard",
			"run", runID, "reason", plan.Abort,
			"considered", rep.Considered, "unknown", rep.Unknown)
		rep.Outcome, rep.Reason = "aborted", plan.Abort
		return rep, nil
	}

	if r.dryRun {
		for _, a := range plan.Apply {
			if a.Revoking {
				rep.Revoked++
			}
		}
		rep.Outcome = "ok"
		rep.Reason = "dry run: nothing was written"
		r.logger.Info("sync dry run", "run", runID,
			"would_revoke", rep.Revoked, "would_apply", len(plan.Apply))
		return rep, nil
	}

	// 6) Uygula.
	now := time.Now()
	for _, a := range plan.Apply {
		if err := r.db.SyncRoles(ctx, a.Username, a.Roles); err != nil {
			r.logger.Error("sync roles failed", "user", a.Username, "error", err)
			continue
		}
		rep.RolesChanged++

		if a.Revoking {
			rep.Revoked++
			if a.ManualRoles > 0 {
				rep.KeptManual = append(rep.KeptManual, a.Username)
			}

			// Denetim satırı: iptal, bir insanın sonradan sorabileceği
			// bir olay.
			details := "directory no longer lists this user"
			if a.ManualRoles > 0 {
				details += fmt.Sprintf("; %d manually granted role(s) kept", a.ManualRoles)
			}
			if err := r.db.LogAdmin(ctx, store.AdminLogEntry{
				Actor: "system", Via: "sync", Action: "role.sync_revoke",
				Entity: a.Username, Details: details,
			}); err != nil {
				r.logger.Error("sync audit write failed", "user", a.Username, "error", err)
			}
		}
	}

	// 7) Varlık durumunu güncelle.
	for _, o := range obs {
		switch o.Presence {
		case ldap.PresencePresent:
			r.db.MarkDirectorySeen(ctx, o.Username, now)
		case ldap.PresenceAbsent:
			r.db.MarkDirectoryMissing(ctx, o.Username, now)
			// PresenceUnknown: DOKUNMA. Bilmediğimiz bir şeyi
			// "kayıp" diye işaretlemek, kesintiyi grace saatinin
			// başlangıcına çevirirdi.
		}
	}

	rep.Outcome = "ok"
	r.logger.Info("sync complete", "run", runID,
		"considered", rep.Considered, "present", rep.Present,
		"absent", rep.Absent, "unknown", rep.Unknown,
		"revoked", rep.Revoked, "held", len(plan.Hold))

	return rep, nil
}

// Start, periyodik döngüyü çalıştırır ve ctx bitene kadar döner.
func (r *Runner) Start(ctx context.Context) {
	r.logger.Info("directory sync started",
		"interval", r.interval, "grace", r.limits.Grace,
		"max_zero_fraction", r.limits.MaxZeroFraction,
		"max_unknown_fraction", r.limits.MaxUnknownFraction,
		"max_revoke_per_run", r.limits.MaxRevokePerRun,
		"dry_run", r.dryRun)

	t := time.NewTicker(r.interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("directory sync stopped")
			return
		case <-t.C:
			if _, err := r.RunOnce(ctx, "timer"); err != nil {
				r.logger.Error("sync run failed", "error", err)
			}
		}
	}
}
