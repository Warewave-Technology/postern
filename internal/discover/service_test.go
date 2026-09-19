package discover

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/v2/internal/model"
	"github.com/Warewave-Technology/postern/v2/internal/secret"
	"github.com/Warewave-Technology/postern/v2/internal/store"
	"github.com/Warewave-Technology/postern/v2/internal/upstream"
)

// fakeSource, hipervizör yerine testin verdiği liste.
type fakeSource struct {
	mu       sync.Mutex
	machines []Machine
	err      error
}

func (f *fakeSource) Name() string { return "fake" }
func (f *fakeSource) Machines(context.Context) ([]Machine, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Machine(nil), f.machines...), f.err
}
func (f *fakeSource) set(ms ...Machine) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.machines = ms
}

type fixture struct {
	svc    *Service
	db     *store.Store
	src    *fakeSource
	source store.DiscoverySource
	secret string
	host   string
	port   int
	now    time.Time
}

// newFixture: veritabanı + mühür anahtarı + sahte kaynak + gerçek host
// anahtarı taraması (fakeSSH gerçek bir sshd el sıkışması yapıyor).
func newFixture(t *testing.T) *fixture {
	t.Helper()
	db := newStore(t)
	box, err := secret.Init(filepath.Join(t.TempDir(), "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	db.UseSecretBox(box)
	host, port := fakeSSH(t)

	f := &fixture{db: db, src: &fakeSource{}, host: host, port: port, now: time.Now().Truncate(time.Second)}
	f.svc = NewService(db, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	f.svc.open = func(_ store.DiscoverySource, secret string) (Source, error) {
		f.secret = secret
		return f.src, nil
	}
	f.svc.now = func() time.Time { return f.now }

	id, err := db.CreateDiscoverySource(context.Background(), store.DiscoverySource{
		Name: "lab", Kind: KindProxmox, URL: "https://pve.example:8006", Username: "a!b",
		TagKey: "role", Port: port, IntervalSeconds: 300, Enabled: true, CreatedBy: "ops",
	}, "gizli")
	if err != nil {
		t.Fatal(err)
	}
	f.source, _ = db.DiscoverySource(context.Background(), id)
	return f
}

func (f *fixture) run(t *testing.T) store.DiscoveryRun {
	t.Helper()
	rep, err := f.svc.Run(context.Background(), f.source.ID, "web", "ops")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return rep
}

func (f *fixture) machine(t *testing.T, ref string) store.DiscoveredMachine {
	t.Helper()
	m, err := f.db.DiscoveredMachine(context.Background(), f.source.ID, ref)
	if err != nil {
		t.Fatalf("makine %s: %v", ref, err)
	}
	return m
}

func keyOf(t *testing.T, host string, port int) string {
	t.Helper()
	k, err := upstream.ScanHostKey(context.Background(), host, port)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

/*
 * ⚠️ KOŞU HEDEF YAZMIYOR. Platformun bildirdiği makine satıra giriyor —
 * okunan anahtarı, etiketten çıkan grubu ve engeliyle — ama targets
 * tablosuna hiçbir şey yazılmıyor. Kaynağın sırrı açılıp hipervizöre
 * gidiyor, başka yere değil.
 */
func TestARunRecordsMachinesWithoutWritingTargets(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.src.set(
		Machine{Name: "web-01", Host: f.host, Tags: []string{"env_prod", "role_ops"}, Running: true, Key: "qemu/101", Ref: "qemu/101@n1"},
		Machine{Name: "db-01", Tags: []string{"role_dba"}, Running: false, Key: "qemu/102", Ref: "qemu/102@n1"},
		Machine{Name: "Bad Name", Host: f.host, Running: true, Key: "qemu/103", Ref: "qemu/103@n1"},
	)

	rep := f.run(t)
	if rep.Outcome != store.DiscoveryOK || rep.Seen != 3 || rep.NewMachines != 3 || rep.Unreachable != 0 || rep.Missing != 0 {
		t.Fatalf("rapor: %+v", rep)
	}
	if f.secret != "gizli" {
		t.Errorf("kaynağa giden sır %q", f.secret)
	}
	web := f.machine(t, "qemu/101")
	if web.Group != "ops" || !web.Tagged || web.HostKey != keyOf(t, f.host, f.port) || web.Problem != "" || web.Host != f.host {
		t.Errorf("web-01: %+v", web)
	}
	db := f.machine(t, "qemu/102")
	if db.HostKey != "" || !strings.Contains(db.Problem, "not running") || db.Group != "dba" {
		t.Errorf("kapalı makine: %+v", db)
	}
	if bad := f.machine(t, "qemu/103"); !strings.Contains(bad.Problem, "cannot be a target name") || bad.Group != "" {
		t.Errorf("adı bozuk makine: %+v", bad)
	}
	if targets, _ := f.db.Targets(ctx); len(targets) != 0 {
		t.Fatalf("KOŞU HEDEF YAZDI: %+v", targets)
	}
	if groups, _ := f.db.Groups(ctx); len(groups) != 0 {
		t.Fatalf("KOŞU ROL YAZDI: %+v", groups)
	}
	runs, _ := f.db.DiscoveryRuns(ctx, f.source.ID, 5)
	if len(runs) != 1 || runs[0].Outcome != store.DiscoveryOK || runs[0].Trigger != "web" || runs[0].Actor != "ops" {
		t.Errorf("koşu satırı: %+v", runs)
	}

	// İkinci koşu db-01'i bildirmiyor: kayıp işaretleniyor, silinmiyor.
	f.now = f.now.Add(time.Minute)
	f.src.set(
		Machine{Name: "web-01", Host: f.host, Tags: []string{"role_ops"}, Running: true, Key: "qemu/101"},
		Machine{Name: "Bad Name", Host: f.host, Running: true, Key: "qemu/103"},
	)
	rep = f.run(t)
	if rep.Missing != 1 || rep.NewMachines != 0 || rep.Seen != 2 {
		t.Errorf("ikinci koşu: %+v", rep)
	}
	if m := f.machine(t, "qemu/102"); m.MissingSince.IsZero() {
		t.Error("bildirilmeyen makine kayıp işaretlenmedi")
	}
	if m := f.machine(t, "qemu/101"); !m.MissingSince.IsZero() || !m.LastSeen.Equal(f.now) {
		t.Errorf("görülen makine: %+v", m)
	}

	/*
	 * ⚠️ BOŞ LİSTE "HEPSİ GİTTİ" DEĞİL: yetkisi daralan bir jeton hata
	 * değil boş liste döndürüyor. Koşu başarısız sayılıyor ve hiçbir
	 * satır kayıp işaretlenmiyor.
	 */
	f.src.set()
	if _, err := f.svc.Run(ctx, f.source.ID, "web", "ops"); err == nil || !strings.Contains(err.Error(), "no machines") {
		t.Fatalf("boş liste kabul edildi: %v", err)
	}
	if m := f.machine(t, "qemu/101"); !m.MissingSince.IsZero() {
		t.Error("boş listede web-01 kayıp işaretlendi")
	}
	runs, _ = f.db.DiscoveryRuns(ctx, f.source.ID, 5)
	if runs[0].Outcome != store.DiscoveryFailed || runs[0].Reason == "" {
		t.Errorf("başarısız koşu satırı: %+v", runs[0])
	}

	// Kaynak hata verirse de aynı: satır 'failed', makinelere dokunulmuyor.
	f.src.err = errors.New("401 unauthorized")
	if _, err := f.svc.Run(ctx, f.source.ID, "web", "ops"); err == nil {
		t.Fatal("kaynak hatası yutuldu")
	}
}

/*
 * ⚠️ DEĞİŞEN HOST ANAHTARI BİR BULGU, GÜNCELLEME DEĞİL. Kayıtlı hedefin
 * makinesi başka bir anahtarla cevap verince satır bunu yazıyor ve
 * sayıyor; hedefteki anahtar yerinde duruyor.
 */
func TestAChangedHostKeyIsAFindingAndTheTargetIsLeftAlone(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.src.set(Machine{Name: "web-01", Host: f.host, Running: true, Key: "qemu/101"})
	f.run(t)
	out, err := f.svc.Register(ctx, RegisterRequest{
		Machines: []MachineRef{{SourceID: f.source.ID, Ref: "qemu/101"}}, Actor: "ops",
	})
	if err != nil || len(out) != 1 || out[0].Error != "" || out[0].Target != "web-01" {
		t.Fatalf("kayıt: %+v (%v)", out, err)
	}
	pinned, _ := f.db.Target(ctx, "web-01")

	otherHost, otherPort := fakeSSH(t)
	f.source.Port = otherPort
	if err := f.db.UpdateDiscoverySource(ctx, f.source, ""); err != nil {
		t.Fatal(err)
	}
	f.src.set(Machine{Name: "web-01", Host: otherHost, Running: true, Key: "qemu/101"})
	rep := f.run(t)
	if rep.KeyChanged != 1 {
		t.Fatalf("anahtar değişimi sayılmadı: %+v", rep)
	}
	m := f.machine(t, "qemu/101")
	if !strings.Contains(m.Problem, "differs from") || m.Target != "web-01" {
		t.Errorf("bulgu satırda yok: %+v", m)
	}
	if after, _ := f.db.Target(ctx, "web-01"); after.HostKey != pinned.HostKey {
		t.Fatal("HEDEFİN ANAHTARI SESSİZCE GÜNCELLENDİ")
	}
	// Bulgu varken kayıt da yok: makine zaten kayıtlı.
	out, _ = f.svc.Register(ctx, RegisterRequest{Machines: []MachineRef{{SourceID: f.source.ID, Ref: "qemu/101"}}, Actor: "ops"})
	if out[0].Error == "" {
		t.Error("kayıtlı makine yeniden kaydedildi")
	}
}

/*
 * ⚠️ AYNI AD KANIT DEĞİL, AYNI ANAHTAR KANIT. Elle/CLI ile kayıtlı bir
 * hedef bu makine olabilir; bağ yalnızca okunan anahtar sabitlenmiş
 * anahtarla aynıysa kuruluyor. Farklıysa satır bunu söylüyor ve makine
 * kaydedilemiyor (ad çakışırdı).
 */
func TestANameMatchLinksOnlyWhenTheKeyMatches(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	otherHost, otherPort := fakeSSH(t)
	if _, err := f.db.CreateTarget(ctx, model.Target{Name: "web-01", Host: f.host, Port: f.port, HostKey: keyOf(t, f.host, f.port)}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.CreateTarget(ctx, model.Target{Name: "db-01", Host: otherHost, Port: otherPort, HostKey: keyOf(t, otherHost, otherPort)}); err != nil {
		t.Fatal(err)
	}
	f.src.set(
		Machine{Name: "web-01", Host: f.host, Running: true, Key: "qemu/101"},
		Machine{Name: "db-01", Host: f.host, Running: true, Key: "qemu/102"},
	)
	f.run(t)
	if m := f.machine(t, "qemu/101"); m.Target != "web-01" || m.Problem != "" {
		t.Errorf("aynı anahtarlı hedefe bağlanmadı: %+v", m)
	}
	m := f.machine(t, "qemu/102")
	if m.Target != "" || !strings.Contains(m.Problem, "different host key") {
		t.Errorf("farklı anahtarlı aynı ad bağlandı ya da söylenmedi: %+v", m)
	}
	out, _ := f.svc.Register(ctx, RegisterRequest{Machines: []MachineRef{{SourceID: f.source.ID, Ref: "qemu/102"}}, Actor: "ops"})
	if len(out) != 1 || !strings.Contains(out[0].Error, "already exists") {
		t.Errorf("ad çakışan makinenin kaydı: %+v", out)
	}
}

/*
 * ⚠️ KAYIT KOŞUNUN OKUDUĞU ANAHTARI SABİTLİYOR, seçilen gruplara ve
 * etiketin grubuna bağlıyor (yoksa açıyor), etiketleri takıyor ve her
 * adımı deftere yazıyor. Anahtarı olmayan makine kaydedilmiyor; olmayan
 * grup isteği baştan reddediliyor.
 */
func TestRegisterPinsTheRecordedKeyGrantsGroupsAndWritesTheLedger(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.db.CreateGroup(ctx, "ops"); err != nil {
		t.Fatal(err)
	}
	f.src.set(
		Machine{Name: "web-01", Host: f.host, Tags: []string{"role_web"}, Running: true, Key: "qemu/101"},
		Machine{Name: "db-01", Running: false, Key: "qemu/102"},
	)
	f.run(t)

	if _, err := f.svc.Register(ctx, RegisterRequest{
		Machines: []MachineRef{{SourceID: f.source.ID, Ref: "qemu/101"}}, Groups: []string{"yok"}, Actor: "ops",
	}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("olmayan grup: %v", err)
	}
	out, err := f.svc.Register(ctx, RegisterRequest{
		Machines: []MachineRef{{SourceID: f.source.ID, Ref: "qemu/101"}, {SourceID: f.source.ID, Ref: "qemu/102"}, {SourceID: f.source.ID, Ref: "yok"}},
		Groups:   []string{"ops"}, TagGroups: true, Labels: map[string]string{"env": "prod"}, Actor: "ayse",
	})
	if err != nil || len(out) != 3 {
		t.Fatalf("Register: %+v (%v)", out, err)
	}
	if out[0].Target != "web-01" || strings.Join(out[0].Groups, ",") != "ops,web" || strings.Join(out[0].CreatedGroups, ",") != "web" {
		t.Errorf("web-01 sonucu: %+v", out[0])
	}
	if !strings.Contains(out[1].Error, "no host key") {
		t.Errorf("anahtarsız makine: %+v", out[1])
	}
	if !strings.Contains(out[2].Error, "not found") {
		t.Errorf("olmayan makine: %+v", out[2])
	}

	tgt, err := f.db.Target(ctx, "web-01")
	if err != nil || strings.TrimSpace(tgt.HostKey) != keyOf(t, f.host, f.port) || tgt.Host != f.host || tgt.Port != f.port {
		t.Fatalf("hedef: %+v (%v)", tgt, err)
	}
	if labels, _ := f.db.TargetLabels(ctx, "web-01"); labels["env"] != "prod" {
		t.Errorf("etiket takılmadı: %v", labels)
	}
	granted := map[string]bool{}
	groups, _ := f.db.Groups(ctx)
	for _, r := range groups {
		for _, tn := range r.Targets {
			granted[r.Name+"→"+tn] = true
		}
	}
	if !granted["ops→web-01"] || !granted["web→web-01"] {
		t.Errorf("grup bağları: %v", granted)
	}
	if m := f.machine(t, "qemu/101"); m.Target != "web-01" {
		t.Errorf("makine hedefe bağlanmadı: %+v", m)
	}

	seen := map[string]int{}
	logs, _ := f.db.AdminLog(ctx, 50)
	for _, e := range logs {
		if e.Actor == "ayse" && e.Via == "web" {
			seen[e.Action]++
		}
	}
	if seen["target.create"] != 1 || seen["group.create"] != 1 || seen["group.grant"] != 2 {
		t.Errorf("defter: %v", seen)
	}

	// Bir sonraki koşu bağı koruyor ve makine 'kayıtlı' kalıyor.
	f.run(t)
	if m := f.machine(t, "qemu/101"); m.Target != "web-01" || m.Problem != "" {
		t.Errorf("koşu bağı düşürdü: %+v", m)
	}
}

/*
 * ⚠️ YOK SAYILAN MAKİNE TARANMIYOR ve yok sayma koşuyla silinmiyor.
 * Tarama sayısı ölçülüyor: "taranmadı" ancak sayarak kanıtlanır.
 */
func TestIgnoredMachinesAreNotScanned(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var mu sync.Mutex
	scanned := map[string]int{}
	real := f.svc.scan
	f.svc.scan = func(ctx context.Context, host string, port int) (ssh.PublicKey, error) {
		mu.Lock()
		scanned[host]++
		mu.Unlock()
		return real(ctx, host, port)
	}
	f.src.set(
		Machine{Name: "web-01", Host: f.host, Running: true, Key: "qemu/101"},
		// "localhost" aynı sshd'ye gidiyor ama sayaçta f.host'tan ayrı duruyor.
		Machine{Name: "db-01", Host: "localhost", Running: true, Key: "qemu/102"},
	)
	f.run(t)
	n, err := f.svc.SetIgnored(ctx, []MachineRef{{SourceID: f.source.ID, Ref: "qemu/102"}}, true, "ops")
	if err != nil || n != 1 {
		t.Fatalf("SetIgnored: %d (%v)", n, err)
	}
	mu.Lock()
	scanned = map[string]int{}
	mu.Unlock()
	f.run(t)
	mu.Lock()
	defer mu.Unlock()
	if scanned["localhost"] != 0 || scanned[f.host] != 1 {
		t.Errorf("taramalar: %v", scanned)
	}
	if m := f.machine(t, "qemu/102"); !m.Ignored {
		t.Error("koşu yok saymayı kaldırdı")
	}
	logs, _ := f.db.AdminLog(ctx, 10)
	if len(logs) == 0 || logs[0].Action != "discovery.ignore" || logs[0].Entity != "db-01" {
		t.Errorf("yok sayma defterde yok: %+v", logs)
	}
	if n, _ := f.svc.SetIgnored(ctx, []MachineRef{{SourceID: f.source.ID, Ref: "qemu/102"}}, true, "ops"); n != 0 {
		t.Error("değişmeyen yok sayma sayıldı")
	}
}

/*
 * ⚠️ ZAMANLAYICI YALNIZCA VADESİ GELENİ KOŞTURUYOR: kapalı kaynak hiç,
 * yeni koşmuş kaynak aralık dolana kadar değil. Aynı kaynağın iki koşusu
 * üst üste binmiyor (ErrRunning).
 */
func TestTheSchedulerRunsOnlyWhatIsDue(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.src.set(Machine{Name: "web-01", Host: f.host, Running: true, Key: "qemu/101"})

	f.svc.Tick(ctx)
	runs, _ := f.db.DiscoveryRuns(ctx, f.source.ID, 10)
	if len(runs) != 1 || runs[0].Trigger != "timer" || runs[0].Actor != "system" {
		t.Fatalf("ilk tik: %+v", runs)
	}
	f.now = f.now.Add(time.Minute)
	f.svc.Tick(ctx)
	if runs, _ = f.db.DiscoveryRuns(ctx, f.source.ID, 10); len(runs) != 1 {
		t.Fatalf("aralık dolmadan yeniden koştu: %d", len(runs))
	}
	f.now = f.now.Add(5 * time.Minute)
	f.svc.Tick(ctx)
	if runs, _ = f.db.DiscoveryRuns(ctx, f.source.ID, 10); len(runs) != 2 {
		t.Fatalf("aralık dolunca koşmadı: %d", len(runs))
	}

	f.source.Enabled = false
	if err := f.db.UpdateDiscoverySource(ctx, f.source, ""); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Hour)
	f.svc.Tick(ctx)
	if runs, _ = f.db.DiscoveryRuns(ctx, f.source.ID, 10); len(runs) != 2 {
		t.Error("kapalı kaynak koştu")
	}

	// Sürmekte olan koşu: ikincisi reddediliyor.
	f.svc.claim(f.source.ID)
	if _, err := f.svc.Run(ctx, f.source.ID, "web", "ops"); !errors.Is(err, ErrRunning) {
		t.Errorf("üst üste koşu: %v", err)
	}
	if err := f.svc.RunNow(ctx, f.source.ID, "ops"); !errors.Is(err, ErrRunning) {
		t.Errorf("üst üste RunNow: %v", err)
	}
	f.svc.release(f.source.ID)
}

func TestValidateSourceRefusesWhatWouldNotWork(t *testing.T) {
	ok := store.DiscoverySource{
		Name: "lab", Kind: KindProxmox, URL: "https://pve:8006", Username: "a!b", TagKey: "role", Port: 22,
		IntervalSeconds: 3600,
	}
	if err := ValidateSource(ok, "s", true); err != nil {
		t.Fatalf("geçerli kaynak reddedildi: %v", err)
	}
	if err := ValidateSource(ok, "", false); err != nil {
		t.Fatalf("güncellemede boş sır reddedildi: %v", err)
	}
	cases := map[string]func(*store.DiscoverySource, *string){
		"boş ad":             func(d *store.DiscoverySource, _ *string) { d.Name = " " },
		"http adres":         func(d *store.DiscoverySource, _ *string) { d.URL = "http://pve:8006" },
		"bilinmeyen tür":     func(d *store.DiscoverySource, _ *string) { d.Kind = "aws" },
		"boş kullanıcı":      func(d *store.DiscoverySource, _ *string) { d.Username = "" },
		"yeni kaynak sırsız": func(_ *store.DiscoverySource, s *string) { *s = "" },
		"boşluklu anahtar":   func(d *store.DiscoverySource, _ *string) { d.TagKey = "role name" },
		"bozuk kalıp":        func(d *store.DiscoverySource, _ *string) { d.NamePattern = "web-[" },
		"port 0":             func(d *store.DiscoverySource, _ *string) { d.Port = 0 },
		"çok sık":            func(d *store.DiscoverySource, _ *string) { d.IntervalSeconds = 60 },
		"çok seyrek":         func(d *store.DiscoverySource, _ *string) { d.IntervalSeconds = 40 * 24 * 3600 },
		"CA ve insecure":     func(d *store.DiscoverySource, _ *string) { d.CAPEM = "x"; d.Insecure = true },
		"PEM değil":          func(d *store.DiscoverySource, _ *string) { d.CAPEM = "sertifika değil" },
	}
	for name, mut := range cases {
		d, s := ok, "s"
		mut(&d, &s)
		if err := ValidateSource(d, s, true); err == nil {
			t.Errorf("%s kabul edildi", name)
		}
	}
	for _, name := range []string{"Web 01", "a:b", "", strings.Repeat("x", 129)} {
		if err := ValidTargetName(name); err == nil {
			t.Errorf("hedef adı %q kabul edildi", name)
		}
	}
	if !matchesPattern("web-*, db-*", "DB-01") || matchesPattern("web-*", "db-01") || !matchesPattern("", "anything") {
		t.Error("ad kalıbı yanlış eşleşiyor")
	}
}

/*
 * ⚠️ TEST BAĞLANTISI HİÇBİR ŞEY YAZMIYOR: ne kaynak, ne makine, ne koşu.
 * Sayımlar formun dört sorusunu cevaplıyor: adres/sır doğru mu (liste
 * geldi mi), ad kalıbı kaç makineyi tutuyor, etiket anahtarı kaç makinede
 * var ve hangi gruplar çıkıyor; sıfırsa görülen etiketler ne.
 */
func TestProbeCountsWhatThePlatformReportsWithoutWriting(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.src.set(
		Machine{Name: "web-01", Host: f.host, Tags: []string{"role_ops", "env_prod"}, Running: true, Key: "qemu/101"},
		Machine{Name: "db-01", Tags: []string{"role_dba"}, Running: false, Key: "qemu/102"},
		Machine{Name: "other", Running: true, Key: "qemu/103"},
	)
	src := f.source
	src.NamePattern = "web-*, db-*"
	p, err := f.svc.Probe(ctx, src, "test-sır")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if f.secret != "test-sır" {
		t.Errorf("kaynağa giden sır %q", f.secret)
	}
	if p.Machines != 3 || p.Running != 2 || p.WithAddress != 1 || p.Matching != 2 || p.Tagged != 2 ||
		strings.Join(p.Groups, ",") != "ops,dba" || len(p.Tags) != 3 {
		t.Errorf("sayımlar: %+v", p)
	}
	if runs, _ := f.db.DiscoveryRuns(ctx, f.source.ID, 5); len(runs) != 0 {
		t.Errorf("test koşu satırı yazdı: %+v", runs)
	}
	if ms, _ := f.db.DiscoveredMachines(ctx, ""); len(ms) != 0 {
		t.Errorf("test makine yazdı: %+v", ms)
	}
	src.TagKey = "yanlis"
	if p, _ = f.svc.Probe(ctx, src, "x"); p.Tagged != 0 || len(p.Tags) == 0 {
		t.Errorf("yanlış anahtar: %+v", p)
	}
	f.src.err = errors.New("401 unauthorized")
	if _, err := f.svc.Probe(ctx, src, "x"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("kaynak hatası: %v", err)
	}
}
