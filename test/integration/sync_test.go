//go:build integration

package integration

// Periyodik dizin senkronizasyonu: dizinde silinen kullanıcının yetkisi
// gerçekten iptal ediliyor mu, ve bir dizin arızası KİMSEYİ iptal
// etmiyor mu?
//
// İkinci soru birincisinden önemli: yanlış cevap, bir LDAP kesintisinde
// şirketin tamamını dışarıda bırakır.
//
//	go test -tags integration -run TestSync -v ./test/integration/

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/groupsync"
	"github.com/warewave/postern/internal/ldap"
	"github.com/warewave/postern/internal/model"
	"github.com/warewave/postern/internal/store"
	"github.com/warewave/postern/internal/testdb"
)

// syncFixture, gerçek bir LDAP ve gerçek bir veritabanıyla senkronizasyon
// kurar.
type syncFixture struct {
	db     *store.Store
	source *ldap.Source
	limits groupsync.Limits
}

func newSyncFixture(t *testing.T) *syncFixture {
	t.Helper()
	ctx := context.Background()

	url := startOpenLDAP(t)
	src, err := ldap.New(ldapConfig(url))
	if err != nil {
		t.Fatalf("ldap.New: %v", err)
	}

	db, err := store.Open(ctx, testdb.DSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	// Roller ve eşlemeler: sysadmins → ops, dbteam → dba, hr → hr
	for _, r := range []string{"ops", "dba", "hr"} {
		if _, err := db.CreateRole(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	for group, role := range map[string]string{
		"sysadmins": "ops", "dbteam": "dba", "hr": "hr",
	} {
		if err := db.AddGroupMapping(ctx, group, role, "test"); err != nil {
			t.Fatal(err)
		}
	}

	limits := groupsync.DefaultLimits()
	// Grace'i sıfıra yakın tut: testin bir saat beklemesi gerekmesin.
	limits.Grace = time.Millisecond

	return &syncFixture{db: db, source: src, limits: limits}
}

// provision, kullanıcıyı JIT yolundan (sso_only=true) oluşturur.
func (f *syncFixture) provision(t *testing.T, username, email string, groups []string) {
	t.Helper()

	if _, err := f.db.ProvisionUser(context.Background(), store.ProvisionRequest{
		// Bu testlerin konusu hesabın AÇILMASI; otomatik
		// açılış anahtarı ayrı bir testte sınanıyor.
		AutoCreate: true,
		Username:   username, Email: email, Groups: groups,
		// Bu yardımcı "dizin cevap verdi" hâlini kuruyor: senkron
		// testlerinin başlangıç durumu, rolleri gerçekten olan bir
		// kullanıcı.
		GroupsResolved: true,
		// Kimlik (issuer, subject) ile bağlanıyor; username tek başına
		// eşleştirme anahtarı DEĞİL (bkz. göç 011).
		Issuer: "https://idp.test", Subject: "sub-" + username,
	}); err != nil {
		t.Fatalf("ProvisionUser(%s): %v", username, err)
	}
}

func (f *syncFixture) runner(t *testing.T, dir groupsync.Directory, dryRun bool) *groupsync.Runner {
	t.Helper()
	return groupsync.NewRunner(f.db,
		func(context.Context) (groupsync.Directory, error) { return dir, nil },
		groupsync.Config{Timeout: time.Minute, DryRun: dryRun, Limits: f.limits},
		slog.New(slog.NewTextHandler(os.Stderr, nil)))
}

// runTwice, grace penceresi yüzünden gereken iki koşuyu yapar.
//
// İLK koşu kullanıcıyı "kayıp" işaretler ve saati başlatır; iptal ancak
// grace dolduktan SONRAKİ koşuda olur. Bu, tek bir çoğaltma
// gecikmesinin yetki silmesini önleyen mekanizmanın kendisi — testin de
// ona uyması gerekiyor.
func (f *syncFixture) runTwice(t *testing.T, dir groupsync.Directory, dryRun bool) groupsync.Report {
	t.Helper()
	ctx := context.Background()

	r := f.runner(t, dir, dryRun)
	if _, err := r.RunOnce(ctx, "test"); err != nil {
		t.Fatalf("birinci koşu: %v", err)
	}
	// Grace milisaniye mertebesinde; dolması için kısa bir bekleme.
	time.Sleep(20 * time.Millisecond)

	rep, err := r.RunOnce(ctx, "test")
	if err != nil {
		t.Fatalf("ikinci koşu: %v", err)
	}
	return rep
}

func (f *syncFixture) rolesOf(t *testing.T, username string) []string {
	t.Helper()
	u, err := f.db.User(context.Background(), username)
	if err != nil {
		t.Fatalf("User(%s): %v", username, err)
	}
	var out []string
	for _, r := range u.Roles {
		out = append(out, r.Name)
	}
	return out
}

// Dizinde OLMAYAN kullanıcının SSO rolleri iptal edilmeli; dizinde olanın
// rollerine dokunulmamalı.
func TestSyncRevokesUsersRemovedFromDirectory(t *testing.T) {
	f := newSyncFixture(t)
	ctx := context.Background()

	// yigit.basalma ve ayse.yilmaz dizinde VAR (seed.ldif).
	f.provision(t, "yigit.basalma", "yigit@warewave.io", []string{"sysadmins", "dbteam"})
	f.provision(t, "ayse.yilmaz", "ayse@warewave.io", []string{"hr"})
	// Bu kişi dizinde YOK: işten ayrılmış birini temsil ediyor.
	f.provision(t, "ayrilan.kisi", "ayrilan@warewave.io", []string{"sysadmins"})

	if got := f.rolesOf(t, "ayrilan.kisi"); len(got) == 0 {
		t.Fatal("tohumlama başarısız: ayrılan kişinin başlangıçta rolü olmalıydı")
	}

	rep := f.runTwice(t, f.source, false)
	if rep.Outcome != "ok" {
		t.Fatalf("sonuç = %s (%s)", rep.Outcome, rep.Reason)
	}

	if got := f.rolesOf(t, "ayrilan.kisi"); len(got) != 0 {
		t.Errorf("dizinde olmayan kullanıcının rolleri duruyor: %v", got)
	}
	if got := f.rolesOf(t, "yigit.basalma"); len(got) != 2 {
		t.Errorf("dizindeki kullanıcının rolleri = %v, 2 tane bekleniyordu", got)
	}
	if got := f.rolesOf(t, "ayse.yilmaz"); len(got) != 1 {
		t.Errorf("dizindeki kullanıcının rolleri = %v, 1 tane bekleniyordu", got)
	}

	// İptal denetim kaydına düşmeli.
	logs, err := f.db.AdminLog(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, l := range logs {
		if l.Action == "role.sync_revoke" && l.Entity == "ayrilan.kisi" && l.Via == "sync" {
			found = true
		}
	}
	if !found {
		t.Error("iptal admin_log'a düşmedi")
	}
}

// deadDirectory, hiçbir soruya cevap veremeyen bir dizin.
type deadDirectory struct{}

func (deadDirectory) Lookup(context.Context, auth.Identity) (ldap.LookupResult, error) {
	return ldap.LookupResult{Presence: ldap.PresenceUnknown}, errDirectoryDown
}
func (deadDirectory) Probe(context.Context) error { return errDirectoryDown }

// ⚠️ BU TESTİN GEÇMESİ ÖZELLİĞİN VAR OLMA ŞARTI.
//
// Dizin ulaşılamazken senkronizasyon HİÇBİR ŞEYE dokunmamalı. Naif bir
// uygulama "grup listesi boş geldi, üyelikler bitmiş" der ve bir LDAP
// kesintisinde şirketin tamamını dışarıda bırakır.
func TestSyncRevokesNobodyWhenDirectoryIsDown(t *testing.T) {
	f := newSyncFixture(t)
	ctx := context.Background()

	f.provision(t, "yigit.basalma", "yigit@warewave.io", []string{"sysadmins", "dbteam"})
	f.provision(t, "ayse.yilmaz", "ayse@warewave.io", []string{"hr"})

	before := map[string]int{
		"yigit.basalma": len(f.rolesOf(t, "yigit.basalma")),
		"ayse.yilmaz":   len(f.rolesOf(t, "ayse.yilmaz")),
	}

	rep, err := f.runner(t, deadDirectory{}, false).RunOnce(ctx, "test")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	if rep.Outcome != "aborted" {
		t.Errorf("sonuç = %q, \"aborted\" bekleniyordu (%s)", rep.Outcome, rep.Reason)
	}
	if rep.Revoked != 0 {
		t.Errorf("%d iptal yapıldı, 0 olmalıydı", rep.Revoked)
	}
	for user, want := range before {
		if got := len(f.rolesOf(t, user)); got != want {
			t.Errorf("%s: %d rol kaldı, %d bekleniyordu — DİZİN ARIZASI YETKİ SİLDİ",
				user, got, want)
		}
	}
	t.Logf("iptal sebebi: %s", rep.Reason)
}

// Elle verilmiş roller iptalden SONRA da durmalı ve rapor bunu ayrıca
// söylemeli.
func TestSyncKeepsManualRolesAndReportsThem(t *testing.T) {
	f := newSyncFixture(t)
	ctx := context.Background()

	f.provision(t, "ayrilan.kisi", "ayrilan@warewave.io", []string{"sysadmins"})
	// Yönetici ELLE bir rol daha vermiş.
	if err := f.db.AssignRole(ctx, "ayrilan.kisi", "hr", time.Time{}); err != nil {
		t.Fatal(err)
	}
	f.provision(t, "yigit.basalma", "yigit@warewave.io", []string{"sysadmins"})

	rep := f.runTwice(t, f.source, false)
	if rep.Outcome != "ok" {
		t.Fatalf("sonuç = %s (%s)", rep.Outcome, rep.Reason)
	}

	roles := f.rolesOf(t, "ayrilan.kisi")
	if len(roles) != 1 || roles[0] != "hr" {
		t.Errorf("roller = %v, elle verilen [hr] durmalıydı", roles)
	}

	var reported bool
	for _, u := range rep.KeptManual {
		if u == "ayrilan.kisi" {
			reported = true
		}
	}
	if !reported {
		t.Error("elle verilen rolü duran kullanıcı raporda yok — " +
			"operatör 'iptal edildi' okuyup erişimin bittiğini sanar")
	}
}

// Kuru koşu hiçbir şey yazmamalı.
func TestSyncDryRunWritesNothing(t *testing.T) {
	f := newSyncFixture(t)
	ctx := context.Background()

	f.provision(t, "ayrilan.kisi", "ayrilan@warewave.io", []string{"sysadmins"})
	f.provision(t, "yigit.basalma", "yigit@warewave.io", []string{"sysadmins"})

	before := len(f.rolesOf(t, "ayrilan.kisi"))

	// Kuru koşuda da iki tur gerekiyor — ama kuru koşu "kayıp"
	// işaretini de YAZMADIĞI için saat hiç başlamaz. Bu yüzden önce
	// ıslak bir tur atıp işareti koyuyoruz, sonra kuru turu ölçüyoruz.
	if _, err := f.runner(t, f.source, false).RunOnce(ctx, "test"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)

	rep, err := f.runner(t, f.source, true).RunOnce(ctx, "test")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if rep.Outcome != "ok" {
		t.Fatalf("sonuç = %s (%s)", rep.Outcome, rep.Reason)
	}
	if rep.Revoked == 0 {
		t.Error("kuru koşu iptal edilecekleri saymadı — raporu işe yaramaz")
	}
	if got := len(f.rolesOf(t, "ayrilan.kisi")); got != before {
		t.Errorf("kuru koşu rolleri DEĞİŞTİRDİ: %d → %d", before, got)
	}
}

// Koşu geçmişi kaydedilmeli: görülmeyen bir iptal, hiç senkronizasyon
// olmamasıyla aynı arıza.
func TestSyncRunsAreRecorded(t *testing.T) {
	f := newSyncFixture(t)
	ctx := context.Background()

	f.provision(t, "yigit.basalma", "yigit@warewave.io", []string{"sysadmins"})

	if _, err := f.runner(t, f.source, false).RunOnce(ctx, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.runner(t, deadDirectory{}, false).RunOnce(ctx, "test"); err != nil {
		t.Fatal(err)
	}

	runs, err := f.db.SyncRuns(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 {
		t.Fatalf("%d koşu kaydı, 2 bekleniyordu", len(runs))
	}
	// En yeni önce: arızalı olan.
	if runs[0].Outcome != "aborted" || runs[0].Reason == "" {
		t.Errorf("iptal edilen koşu = %+v, sebebiyle kaydedilmeliydi", runs[0])
	}
	if runs[1].Outcome != "ok" {
		t.Errorf("başarılı koşu = %s", runs[1].Outcome)
	}
	for _, r := range runs {
		if r.FinishedAt.IsZero() {
			t.Errorf("koşu %d kapatılmamış", r.ID)
		}
	}
}

var errDirectoryDown = errors.New("directory is unreachable")

var _ = model.Target{}
