package hostacct

/*
 * Üçüncü yol: süpürme (spec §4.1).
 *
 * ⚠️ SICAK YOL VE İTME YOLU NEYİ GÖREMİYOR. Sıcak yol yalnızca kişi
 * bağlandığında koşuyor ve parmak izi tutuyorsa hiç koşmuyor; itme yolu
 * yalnızca postern'in KENDİ kaydına bakıyor. İkisi de HEDEFTE elle
 * yapılan değişikliği göremiyor: silinen bir sudoers dosyası, elle
 * kaldırılmış bir üyelik, ya da — asıl olan — postern'in `postern-<grup>`
 * grubuna ELLE EKLENEN bir hesap. Sonuncusu postern'in yazdığı sudo
 * kuralını, postern'in hiç tanımadığı birine veriyor.
 *
 * ⚠️ HEDEF BAŞINA TEK BAĞLANTI. provision.Desired birden çok kullanıcı
 * taşıyabiliyor; süpürme bir makinedeki herkesi tek Observe/Plan/Apply
 * turunda geçiriyor. Kişi başına bağlanmak, elli kişilik bir makinede
 * her turda elli SSH demek olurdu ve özellik ilk büyük filoda kapatılırdı.
 *
 * ⚠️ VARSAYILAN KAPALI. Her turda filodaki her hedefe bağlanmak,
 * okunmadan yapılan bir yükseltmenin üretimde yapabileceği en görünür
 * sürpriz; manage.sweep_interval yazılmadıkça bu döngü hiç kurulmuyor.
 */

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/Warewave-Technology/postern/v2/internal/model"
	"github.com/Warewave-Technology/postern/v2/internal/provision"
	"github.com/Warewave-Technology/postern/v2/internal/store"
	"github.com/Warewave-Technology/postern/v2/internal/upstream"
)

// SweepDeps, süpürmenin dışarıya bağlandığı yerler.
type SweepDeps struct {
	// Rows, hedefte AÇIK olan bütün satırlar.
	Rows func(ctx context.Context) ([]store.HostAccount, error)
	/*
	 * Grants, bir grubun verdiği ama hiç satırı olmayan (kişi, hedef)
	 * çiftleri — önden açmanın iş listesi.
	 *
	 * ⚠️ nil İSE ÖNDEN AÇMA KAPALI, VE VARSAYILANI BU. Manifestonun
	 * cümlesi "hesap kullanıldığı yerde vardır": postern'in var olma
	 * sebebi, N kullanıcıyı M makineye basmamak. Önden açmak bazı
	 * kurumların gerçek ihtiyacı (dosya sahipliği, cron, mail) ama
	 * varsayılan olursa ürün tam da yerine geçtiği şeye döner.
	 */
	Grants func(ctx context.Context, now time.Time) ([]store.Grant, error)

	User   func(ctx context.Context, name string) (model.User, error)
	Target func(ctx context.Context, name string) (model.Target, error)
	Rules  func(ctx context.Context) (map[string]store.GroupSudo, error)
	UID    func(ctx context.Context, u model.User) (int, error)
	Save   func(ctx context.Context, a store.HostAccount) error
	Audit  func(ctx context.Context, target, detail string) error

	Connect func(ctx context.Context, t model.Target, reason string) (Runner, error)
	Caps    func(ctx context.Context, r Runner) (upstream.ManageCapabilities, error)

	Logger *slog.Logger
	Now    func() time.Time

	/*
	 * MaxRemovals, TEK HEDEFTE tek turda kaldırılabilecek fazla üyelik
	 * tavanı.
	 *
	 * ⚠️ AŞILDIĞINDA HİÇBİRİ KALDIRILMIYOR. Yarısını uygulamak, hem
	 * hasarı verip hem sebebi gizlemek olurdu. Tavanın var olma sebebi
	 * somut: postern'in kayıtları bir an için eksik okunursa (göç
	 * yarıda, sorgu zaman aşımı) "beklenen üye yok" çıkar ve zorlama
	 * bütün makineyi kendi grubundan atardı.
	 */
	MaxRemovals int
}

func (d SweepDeps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}

	return time.Now()
}

// Sweeper, periyodik sürüklenme süpürücüsü.
type Sweeper struct {
	deps     SweepDeps
	interval time.Duration
}

func NewSweeper(d SweepDeps, interval time.Duration) *Sweeper {
	if interval <= 0 {
		interval = time.Hour
	}
	if d.MaxRemovals <= 0 {
		d.MaxRemovals = 10
	}

	return &Sweeper{deps: d, interval: interval}
}

// Run, ctx bitene kadar koşar.
func (s *Sweeper) Run(ctx context.Context) {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Tick(ctx)
		}
	}
}

/*
 * Tick, bir tur süpürür. Hata döndürmüyor: döngü durmamalı.
 */
func (s *Sweeper) Tick(ctx context.Context) {
	d := s.deps
	now := d.now()

	rows, err := d.Rows(ctx)
	if err != nil {
		s.log("could not read the active accounts", "error", err)
		return
	}

	// Hedef → o hedefte bakılacak kişiler; satırlar kişi adıyla.
	work := map[string][]string{}
	known := map[string]store.HostAccount{}
	for _, r := range rows {
		work[r.TargetName] = append(work[r.TargetName], r.Username)
		known[r.TargetName+"\x00"+r.Username] = r
	}

	if d.Grants != nil {
		grants, gerr := d.Grants(ctx, now)
		if gerr != nil {
			s.log("could not read the grants without accounts", "error", gerr)
			return
		}
		for _, g := range grants {
			work[g.TargetName] = append(work[g.TargetName], g.Username)
		}
	}

	if len(work) == 0 {
		return
	}

	names := make([]string, 0, len(work))
	for name := range work {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		people := work[name]
		sort.Strings(people)
		s.sweepTarget(ctx, name, people, known, now)
	}
}

/*
 * sweepTarget, bir hedefteki herkesi tek turda geçirir.
 *
 * Sıra: istenen durumu kur → gözle → kaynağı çöz → onar → FAZLA üyeliği
 * kaldır → satırları yaz.
 */
func (s *Sweeper) sweepTarget(ctx context.Context, name string, people []string,
	known map[string]store.HostAccount, now time.Time,
) {
	d := s.deps

	target, terr := d.Target(ctx, name)
	if terr != nil {
		s.log("the target could not be read", "target", name, "error", terr)
		return
	}
	rules, rerr := d.Rules(ctx)
	if rerr != nil {
		s.log("the groups' sudo rules could not be read", "error", rerr)
		return
	}

	type person struct {
		user model.User
		row  store.HostAccount
		want Want
	}
	crew := make([]person, 0, len(people))
	for _, username := range people {
		u, uerr := d.User(ctx, username)
		if uerr != nil {
			s.log("the person could not be read", "user", username, "error", uerr)
			continue
		}
		row, ok := known[name+"\x00"+username]
		if !ok {
			row = store.HostAccount{TargetName: name, Username: username, FirstSeen: now}
		}
		var uid int
		if d.UID != nil {
			// Numarasız devam: gerekçe Deps.UID'in yanında.
			if n, err := d.UID(ctx, u); err == nil {
				uid = n
			}
		}
		crew = append(crew, person{user: u, row: row, want: Compute(u, target, rules,
			Account{Managed: row.Origin == store.OriginCreated, UID: uid})})
	}
	if len(crew) == 0 {
		return
	}

	runner, cerr := d.Connect(ctx, target, "sweeping accounts")
	if cerr != nil {
		s.log("could not reach the target", "target", name, "error", cerr)
		return
	}
	defer func() { _ = runner.Close() }()

	caps, kerr := d.Caps(ctx, runner)
	if kerr != nil {
		s.log("could not measure the target", "target", name, "error", kerr)
		return
	}

	wants := make([]Want, 0, len(crew))
	for _, p := range crew {
		wants = append(wants, p.want)
	}
	desired := desiredFor(wants)
	/*
	 * Kaynağı bilinmeyen bir satır varsa marker grubu da soruluyor;
	 * gerekçesi Ensure'deki ile aynı (ölçüldü: sorulmayan grup her
	 * seferinde yeniden açılmaya çalışılıyor).
	 */
	origins := make([]string, 0, len(crew))
	for _, p := range crew {
		origins = append(origins, p.row.Origin)
	}
	if needsMarkerLookup(origins) && !hasGroupNamed(desired.Groups, provision.ManagedGroup) {
		desired.Groups = append(desired.Groups, provision.Group{Name: provision.ManagedGroup})
	}
	desired.PrincipalsFile = provision.PrincipalsPatternFor(ctx, runner, crew[0].want.OSUser, caps.PrincipalsFile)

	observed, oerr := provision.Observe(ctx, runner, desired)
	if oerr != nil {
		s.log("could not read the target", "target", name, "error", oerr)
		return
	}

	// Kaynak çözülüyor ve istenen durum ona göre yeniden kuruluyor.
	changed := false
	for i := range crew {
		if crew[i].row.Origin != "" {
			continue
		}
		if _, existed := observed.Users[crew[i].want.OSUser]; existed {
			crew[i].row.Origin = store.OriginAdopted
		} else {
			crew[i].row.Origin = store.OriginCreated
		}
		crew[i].want = Compute(crew[i].user, target, rules, Account{
			Managed: crew[i].row.Origin == store.OriginCreated,
			UID:     crew[i].want.UID,
		})
		changed = true
	}
	if changed {
		wants = wants[:0]
		for _, p := range crew {
			wants = append(wants, p.want)
		}
		pf := desired.PrincipalsFile
		desired = desiredFor(wants)
		desired.PrincipalsFile = pf
	}

	steps, perr := provision.Plan(caps, desired, observed)
	if perr != nil {
		s.log("refused before touching the target", "target", name, "error", perr)
		return
	}
	if len(steps) > 0 {
		rep := provision.Apply(ctx, runner, steps)
		if rep.Failed() > 0 || rep.Unreachable() > 0 {
			s.log("the drift repair did not finish", "target", name,
				"failed", rep.Failed()+rep.Unreachable(), "of", len(steps))

			return
		}
		s.audit(ctx, name, fmt.Sprintf("swept %s: repaired %d drifted step(s) for %d account(s): %s",
			name, len(steps), len(crew), driftReasons(steps)))
	}

	s.enforceMembership(ctx, runner, caps, name, observed, wants)

	for _, p := range crew {
		row := p.row
		row.OSUser = p.want.OSUser
		row.State = store.HostAccountActive
		row.DesiredFP = p.want.Fingerprint
		row.AppliedFP = p.want.Fingerprint
		row.AppliedAt = now
		row.Attempts = 0
		row.LastError = ""
		row.NextAttemptAt = time.Time{}
		row.UpdatedAt = now
		if err := d.Save(ctx, row); err != nil {
			s.log("the target was swept but a record could not be written",
				"target", name, "user", row.Username, "error", err)
		}
	}
}

/*
 * enforceMembership, postern'in ad uzayındaki fazla üyelikleri kaldırır.
 *
 * ⚠️ ASIL BULGU BU. Hedefte elle `postern-dba` grubuna eklenen bir hesap,
 * postern'in o gruba yazdığı sudo kuralını alıyor ve postern'in hiçbir
 * kaydında görünmüyor — yani postern'in verdiği yetki, postern'in
 * bilmediği birinde. Plan bunu düzeltemiyor: `usermod -a -G` katıcı,
 * yalnızca ekliyor.
 */
func (s *Sweeper) enforceMembership(ctx context.Context, runner Runner,
	caps upstream.ManageCapabilities, target string, observed provision.Observed, wants []Want,
) {
	d := s.deps

	expected := map[string][]string{}
	for _, w := range wants {
		for _, g := range w.Groups {
			expected[g.Name] = append(expected[g.Name], w.OSUser)
		}
	}
	/*
	 * ⚠️ HİÇ ÜYESİ BEKLENMEYEN GRUP DA LİSTEDE OLMALI. Gruptaki herkesin
	 * grubu düştüyse beklenen liste boş ve ORADAKİ HERKES fazladır;
	 * grubu listeye hiç koymamak, o durumu "bu grubu bilmiyorum" ile
	 * aynı yapar ve zorlama hiç koşmaz.
	 */
	for g := range observed.GroupMembers {
		if _, ok := expected[g]; !ok {
			expected[g] = nil
		}
	}

	extras := provision.ExtraMembers(observed, expected)
	if len(extras) == 0 {
		return
	}
	if len(extras) > d.MaxRemovals {
		s.log("refusing to enforce group membership: the cap was reached",
			"target", target, "extras", len(extras), "cap", d.MaxRemovals)
		s.audit(ctx, target, fmt.Sprintf(
			"%d accounts are in postern's groups without a postern grant on %s, "+
				"which is more than the cap of %d; nothing was changed",
			len(extras), target, d.MaxRemovals))

		return
	}

	steps, perr := provision.MembershipPlan(caps, extras)
	if perr != nil {
		s.log("cannot enforce group membership here", "target", target, "error", perr)
		return
	}
	rep := provision.Apply(ctx, runner, steps)
	if rep.Failed() > 0 || rep.Unreachable() > 0 {
		s.log("membership enforcement did not finish", "target", target,
			"failed", rep.Failed()+rep.Unreachable(), "of", len(steps))

		return
	}
	for _, e := range extras {
		s.audit(ctx, target, fmt.Sprintf(
			"took %s out of %s: no postern group puts them there, and that group carries "+
				"the sudo rule postern wrote for it", e.User, e.Group))
	}
	s.log("took accounts out of postern's groups on a target",
		"target", target, "count", len(extras))
}

func (s *Sweeper) audit(ctx context.Context, target, detail string) {
	if s.deps.Audit != nil {
		_ = s.deps.Audit(ctx, target, detail)
	}
}

func (s *Sweeper) log(msg string, args ...any) {
	if s.deps.Logger != nil {
		s.deps.Logger.Warn(msg, args...)
	}
}

/*
 * desiredFor, birden çok kişinin istenen hâlini TEK bir Desired'a
 * katlar: gruplar adına göre tekilleşiyor, kullanıcılar olduğu gibi
 * geçiyor.
 *
 * ⚠️ TEKİLLEŞTİRME ŞART. Aynı gruptan erişen iki kişi aynı grubu iki kez
 * istiyor; Observe onu iki kez sorar, Plan iki `groupadd` üretir ve
 * ikincisi "grup zaten var" diye düşerek bütün turu başarısız gösterir.
 */
func desiredFor(wants []Want) provision.Desired {
	var d provision.Desired
	seen := map[string]bool{}
	for _, w := range wants {
		for _, g := range w.Groups {
			if seen[g.Name] {
				continue
			}
			seen[g.Name] = true
			d.Groups = append(d.Groups, provision.Group{Name: g.Name, Sudo: g.Sudo})
		}
		d.Users = append(d.Users, provision.User{
			Name:   w.OSUser,
			Groups: groupNames(w.Groups),
			UID:    w.UID,
		})
	}

	return d
}

/*
 * driftReasons, onarılan sürüklenmenin SEBEPLERİNİ tek cümlede toplar.
 *
 * ⚠️ SAYI TEK BAŞINA YANILTIYOR — ÖLÇÜLDÜ. Defterde iki kez "repaired 5
 * drifted step(s)" duruyordu ve sayı, o hesabın ilk kurulumunun adım
 * sayısıyla aynıydı; süpürmenin her turda bütün planı yeniden koştuğunu
 * sandım. Sebep yazılı olsaydı ("grup yok", "üyelik yok") cevap ilk
 * bakışta görünürdü: hedef tazelenmiş, postern'in yazdığı her şey
 * gitmişti. Bir denetim satırının işi, okuyanı makineye gönderip
 * ölçtürmemek.
 *
 * sudo dosyasının doğrulama ve yerine koyma adımları dışarıda: ikisi de
 * ilk adımın devamı ve kendi cümleleri sürüklenmeyi değil, yazma yordamını
 * anlatıyor.
 */
func driftReasons(steps []provision.Step) string {
	const most = 5
	seen := map[string]bool{}
	reasons := make([]string, 0, most)
	extra := 0
	for _, st := range steps {
		if st.Kind == provision.StepSudoCheck || st.Kind == provision.StepSudoInstall {
			continue
		}
		if st.Why == "" || seen[st.Why] {
			continue
		}
		seen[st.Why] = true
		if len(reasons) == most {
			extra++

			continue
		}
		reasons = append(reasons, st.Why)
	}
	if len(reasons) == 0 {
		return "no reason was recorded"
	}
	out := strings.Join(reasons, "; ")
	if extra > 0 {
		out += fmt.Sprintf(" (and %d more)", extra)
	}

	return out
}

// needsMarkerLookup, kaynağı henüz bilinmeyen bir satır var mı.
func needsMarkerLookup(origins []string) bool {
	for _, o := range origins {
		if o == "" {
			return true
		}
	}

	return false
}

func hasGroupNamed(gs []provision.Group, name string) bool {
	for _, g := range gs {
		if g.Name == name {
			return true
		}
	}

	return false
}
