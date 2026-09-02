package groupsync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/ldap"
	"github.com/warewave/postern/internal/model"
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

	// settings, HER KOŞUDA ayarları yeniden okur.
	//
	// ⚠️ open ile aynı gerekçe: ayarlar panelden çalışma zamanında
	// değişiyor ve yapıcıda yakalanmış bir değer, operatörün çoktan
	// kapattığı bir döngüyü çalıştırmaya devam ederdi. En çok önemsenen
	// düğme dry_run: yetki iptal eden bir döngüyü izlemeye almak anlık
	// olmalı, yeniden başlatma gerektirmemeli.
	//
	// nil ise ayarlar sabit (testler ve YAML-only kurulumlar).
	settings func(context.Context) (Settings, error)

	// mu, yukarıdaki dryRun/limits/timeout alanlarını korur.
	//
	// ⚠️ BUGÜN YARIŞ YOK — refresh ve RunOnce aynı goroutine'de
	// (Start döngüsü) çalışıyor, CLI ise ayrı bir süreç. Kilit, ileride
	// "şimdi koştur" diye bir uç eklendiğinde sessizce yarışa dönmesin
	// diye: ayarların çalışma zamanında değişebilir olması bu tuzağı
	// yeni yarattı.
	mu sync.Mutex
}

// snapshot, koşunun kullanacağı ayarların anlık kopyası.
func (r *Runner) snapshot() (bool, Limits, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dryRun, r.limits, r.timeout
}

// UseSettings, ayarları her koşuda yeniden okuyan kaynağı bağlar.
// Start'tan ÖNCE çağrılmalı.
func (r *Runner) UseSettings(fn func(context.Context) (Settings, error)) {
	r.settings = fn
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
	// Ayarların anlık kopyası: koşunun ortasında değişen bir tavan,
	// planın yarısını bir eşikle diğer yarısını başkasıyla
	// değerlendirmek olurdu.
	dryRun, limits, timeout := r.snapshot()

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	runID, err := r.db.StartSyncRun(ctx, "ldap", trigger, dryRun)
	if err != nil {
		return Report{}, err
	}

	rep, runErr := r.run(ctx, runID, dryRun, limits)

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

/*
 * run, asıl koşu.
 *
 * ⚠️ dryRun ve limits PARAMETRE, r'den okunmuyor: ayarlar çalışma
 * zamanında değişiyor ve RunOnce ile run arasında değişen bir tavan,
 * koşunun başını bir eşikle sonunu başkasıyla değerlendirmek olurdu.
 * Anlık kopya bir kez alınıp buraya geçiliyor.
 */
func (r *Runner) run(ctx context.Context, runID int64, dryRun bool, limits Limits) (Report, error) {
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

		/*
		 * ⚠️ KİMLİĞİ BAĞLIYSA ADLA DEĞİL, KİMLİKLE SOR.
		 *
		 * Adla arama, dizinde YENİDEN ADLANDIRILAN kişiyi SİLİNMİŞ
		 * kişiden ayırt edemiyor: ikisi de PresenceAbsent döner ve
		 * aşağıdaki plan ikincisini rol iptaline çevirir. Yani bir
		 * soyadı güncellemesi, kimsenin baktığı bir yerde olmadan
		 * erişim kaybına dönüşüyordu.
		 *
		 * Bağlı değilse ad kalıyor: postern'in SAKLADIĞI ad gönderiliyor,
		 * dizinin döndürdüğü değil — users.username harf duyarlı
		 * karşılaştırılıyor ve dizinden gelen bir yazımı geri yazmak
		 * eşleşmeyi bozardı.
		 */
		res, lerr := lookupCandidate(ctx, dir, c)
		if lerr != nil {
			r.logger.Debug("directory lookup failed", "user", c.Username, "error", lerr)
		}

		o := Observation{
			Username:     c.Username,
			Presence:     res.Presence,
			MissingSince: c.MissingSince,
			ManualRoles:  c.ManualRoles,
			SSORoles:     c.SSORoles,
		}

		if res.Presence == ldap.PresencePresent {
			roles, _, rerr := r.db.RolesForGroups(ctx, model.ResolvedGroups(res.Groups))
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
	plan := BuildPlan(time.Now(), obs, limits)
	if plan.Abort != "" {
		r.logger.Warn("sync aborted by blast-radius guard",
			"run", runID, "reason", plan.Abort,
			"considered", rep.Considered, "unknown", rep.Unknown)
		rep.Outcome, rep.Reason = "aborted", plan.Abort
		return rep, nil
	}

	if dryRun {
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
	// ⚠️ ÖNCE AYARLARI OKU, sonra logla. İlk hâlde açılış satırı
	// YAML'daki varsayılanı yazıyordu: veritabanında dry_run açıkken
	// log "dry_run=false" diyordu — yani operatörün en çok güvenmesi
	// gereken satır, en çok önemsediği bayrak hakkında yanlış.
	enabled, interval := r.refresh(ctx)
	if interval <= 0 {
		interval = r.interval
	}
	dryRun, limits, _ := r.snapshot()
	r.logger.Info("directory sync loop started",
		"enabled", enabled,
		"interval", interval, "grace", limits.Grace,
		"max_zero_fraction", limits.MaxZeroFraction,
		"max_unknown_fraction", limits.MaxUnknownFraction,
		"max_revoke_per_run", limits.MaxRevokePerRun,
		"dry_run", dryRun)

	/*
	 * ⚠️ DÖNGÜ HER ZAMAN ÇALIŞIR, ayar kapalıyken bile.
	 *
	 * Eskiden serve yalnızca cfg.Sync.Enabled iken Runner'ı
	 * başlatıyordu; ayar panele taşınınca bu, "panelden açtım ama
	 * hiçbir şey olmuyor" demek olurdu — çalışacak bir döngü yok.
	 *
	 * ⚠️ AYAR OKUMA SIKLIĞI, KOŞU SIKLIĞINDAN AYRI.
	 *
	 * İlk hâlde tik aralığı = senkronizasyon aralığıydı ve ayarlar
	 * yalnızca tikte okunuyordu. Sonucu: 15 dakikalık aralıkta panelden
	 * "enabled" yapan operatör 15 dakika boyunca hiçbir şey görmüyordu —
	 * ve haklı olarak bozuk sanıyordu. Aynısı dry_run için de geçerli,
	 * ki o düğmenin varlık sebebi HIZLI müdahale.
	 *
	 * Şimdi döngü settingsPoll'da bir uyanıp ayarı okuyor, koşuyu ise
	 * yalnızca aralık dolduğunda yapıyor.
	 */
	t := time.NewTicker(settingsPoll)
	defer t.Stop()

	var last time.Time
	for {
		select {
		case <-ctx.Done():
			r.logger.Info("directory sync stopped")
			return
		case <-t.C:
			enabled, interval := r.refresh(ctx)
			if !enabled {
				continue
			}
			if interval <= 0 {
				interval = r.interval
			}
			if time.Since(last) < interval {
				continue
			}
			last = time.Now()
			if _, err := r.RunOnce(ctx, "timer"); err != nil {
				r.logger.Error("sync run failed", "error", err)
			}
		}
	}
}

/*
 * settingsPoll, ayarların yeniden okunma sıklığı.
 *
 * Senkronizasyon aralığından bağımsız ve KISA: buradaki maliyet tek bir
 * küçük sorgu, karşılığında panelden yapılan bir değişiklik — özellikle
 * dry_run — saniyeler içinde etkili oluyor.
 */
const settingsPoll = 15 * time.Second

/*
 * refresh, ayarları yeniden okur ve döngünün açık olup olmadığını döner.
 *
 * ⚠️ HATA DURUMUNDA KOŞMUYOR. Okunamayan bir ayarla devam etmek, hangi
 * patlama yarıçapı tavanının geçerli olduğunu bilmeden yetki iptal
 * etmek demekti — bu döngüde bilinmeyenle devam etmenin bedeli, bir tik
 * atlamaktan çok daha yüksek.
 */
func (r *Runner) refresh(ctx context.Context) (bool, time.Duration) {
	if r.settings == nil {
		return true, r.interval
	}

	s, err := r.settings(ctx)
	if err != nil {
		r.logger.Error("sync settings unreadable; skipping this run", "error", err)
		return false, r.interval
	}

	// ⚠️ YOK SAYILAN AYAR SESSİZ KALMIYOR. Patlama yarıçapı tavanları
	// artık yalnızca config dosyasından okunuyor; ayarlar tablosunda
	// kalmış bir satır, operatörün yürürlükte sandığı bir değer demek.
	for _, k := range s.IgnoredKeys {
		r.logger.Warn("stored setting is ignored; this ceiling is read from the config file only",
			"key", k, "where", "sync.* in postern.yaml")
	}

	r.mu.Lock()
	r.dryRun = s.Config.DryRun
	r.limits = s.Config.Limits
	if s.Config.Timeout > 0 {
		r.timeout = s.Config.Timeout
	}
	r.mu.Unlock()

	return s.Enabled, s.Config.Interval
}

/*
 * lookupCandidate, adayı dizinde çözer — kimliği bağlıysa KİMLİKLE.
 *
 * Directory arayüzü kimlikle aramayı isteğe bağlı bırakıyor: claim
 * tabanlı bir kaynak zaten bu döngüye hiç girmiyor, ama arayüzü
 * genişletmek onu uygulayan her şeyi zorlardı. Desteklemeyen kaynak
 * ada düşüyor — yani davranış eskisi gibi kalıyor.
 */
func lookupCandidate(ctx context.Context, dir Directory, c store.SyncCandidate) (ldap.LookupResult, error) {
	if c.DirSubject != "" {
		if bySubject, ok := dir.(interface {
			LookupBySubject(context.Context, string) (ldap.LookupResult, error)
		}); ok {
			return bySubject.LookupBySubject(ctx, c.DirSubject)
		}
	}
	return dir.Lookup(ctx, auth.Identity{Username: c.Username, Email: c.Email})
}
