package groupsync

import (
	"strings"
	"testing"
	"time"

	"github.com/warewave/postern/internal/ldap"
)

var now = time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

// long, Grace süresini kesin aşan bir geçmiş an.
func long() time.Time { return now.Add(-24 * time.Hour) }

func present(name string, roles ...string) Observation {
	return Observation{Username: name, Presence: ldap.PresencePresent, MappedRoles: roles}
}

func absent(name string, since time.Time) Observation {
	return Observation{Username: name, Presence: ldap.PresenceAbsent, MissingSince: since}
}

func unknown(name string) Observation {
	return Observation{Username: name, Presence: ldap.PresenceUnknown}
}

// EN ÖNEMLİ TEST: dizin cevap veremiyorsa KİMSENİN yetkisi iptal
// edilmez.
//
// Bu senaryo tam olarak özelliğin var olma sebebinin karşı yüzü. Naif
// bir senkronizasyon "grup listesi boş geldi, demek ki üyelikler bitmiş"
// der ve bir LDAP kesintisinde şirketin tamamını dışarıda bırakır.
func TestOutageRevokesNobody(t *testing.T) {
	obs := []Observation{
		unknown("a"), unknown("b"), unknown("c"), unknown("d"),
		present("e", "ops"),
	}

	plan := BuildPlan(now, obs, DefaultLimits())

	if plan.Abort == "" {
		t.Fatal("dizin 5 kullanıcının 4'üne cevap veremezken koşu iptal edilmedi")
	}
	if len(plan.Apply) != 0 {
		t.Errorf("iptal edilen koşuda %d uygulama var, 0 olmalı", len(plan.Apply))
	}
	t.Logf("iptal sebebi: %s", plan.Abort)
}

// Kısmen geri yüklenmiş dizin: kullanıcı aramaları CEVAPLANIR, grup
// aramaları BOŞ döner.
//
// Bu, "yok" değil "var ama grupsuz" olarak görünür — ve kişi bazında
// bakan bir mantık bunu meşru iptaller sanır. İki durumun AYNI sayaçta
// toplanmasının sebebi bu.
func TestHalfRestoredDirectoryAborts(t *testing.T) {
	var obs []Observation
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"} {
		obs = append(obs, present(n)) // var, ama hiç grubu yok
	}

	plan := BuildPlan(now, obs, DefaultLimits())

	if plan.Abort == "" {
		t.Fatal("herkes sıfır role düşerken koşu iptal edilmedi — " +
			"kişi bazında bakan mantık bunu meşru iptal sanardı")
	}
	if len(plan.Apply) != 0 {
		t.Errorf("%d uygulama var, 0 olmalı", len(plan.Apply))
	}
	t.Logf("iptal sebebi: %s", plan.Abort)
}

// Tek bir ayrılan kişi normal iş: tavanı tetiklememeli.
func TestSingleDepartureIsApplied(t *testing.T) {
	obs := []Observation{
		absent("ayrilan", long()),
	}
	for i := 0; i < 30; i++ {
		obs = append(obs, present("kalan"+string(rune('a'+i%26)), "ops"))
	}

	plan := BuildPlan(now, obs, DefaultLimits())

	if plan.Abort != "" {
		t.Fatalf("tek ayrılma iptal edildi: %s", plan.Abort)
	}

	var revoked []string
	for _, a := range plan.Apply {
		if a.Revoking {
			revoked = append(revoked, a.Username)
		}
	}
	if len(revoked) != 1 || revoked[0] != "ayrilan" {
		t.Errorf("iptal edilenler = %v, [ayrilan] bekleniyordu", revoked)
	}
}

// Grace penceresi: yeni kaybolan kullanıcı BEKLETİLİR, iptal edilmez.
func TestGraceWindowHolds(t *testing.T) {
	limits := DefaultLimits()

	t.Run("yeni kaybolan bekletilir", func(t *testing.T) {
		obs := []Observation{absent("x", now.Add(-10*time.Minute))}
		plan := BuildPlan(now, obs, limits)

		if len(plan.Apply) != 0 {
			t.Errorf("grace dolmadan iptal edildi: %+v", plan.Apply)
		}
		if len(plan.Hold) != 1 || plan.Hold[0] != "x" {
			t.Errorf("Hold = %v, [x] bekleniyordu", plan.Hold)
		}
	})

	t.Run("ilk kez kaybolan bekletilir", func(t *testing.T) {
		// MissingSince sıfır: bu, kullanıcının ilk kez bulunamadığı
		// koşu. Saati burada başlatıyoruz, iptal etmiyoruz.
		obs := []Observation{absent("x", time.Time{})}
		plan := BuildPlan(now, obs, limits)

		if len(plan.Apply) != 0 {
			t.Errorf("ilk kayıpta iptal edildi: %+v", plan.Apply)
		}
		if len(plan.Hold) != 1 {
			t.Errorf("Hold = %v", plan.Hold)
		}
	})

	t.Run("grace dolunca iptal edilir", func(t *testing.T) {
		obs := []Observation{absent("x", long())}
		plan := BuildPlan(now, obs, limits)

		if len(plan.Apply) != 1 || !plan.Apply[0].Revoking {
			t.Errorf("grace dolduğu hâlde iptal edilmedi: %+v", plan)
		}
	})
}

// Elle verilmiş roller iptalden SONRA da duruyor ve rapor bunu ayrıca
// söylemeli — yoksa operatör "iptal edildi" okuyup erişimin tamamen
// bittiğini sanar.
func TestManualRolesAreReportedSeparately(t *testing.T) {
	obs := []Observation{
		{Username: "x", Presence: ldap.PresenceAbsent, MissingSince: long(), ManualRoles: 2},
	}
	plan := BuildPlan(now, obs, DefaultLimits())

	if len(plan.Apply) != 1 {
		t.Fatalf("Apply = %+v", plan.Apply)
	}
	if plan.Apply[0].ManualRoles != 2 {
		t.Errorf("ManualRoles = %d, 2 bekleniyordu — rapor elle verilen "+
			"rollerin durduğunu söylemezse erişim bitti sanılır",
			plan.Apply[0].ManualRoles)
	}
}

// Tek koşuda çok fazla iptal, sebebi ne olursa olsun durdurulmalı.
func TestMaxRevokePerRunCaps(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxRevokePerRun = 3
	// Oran tavanını devre dışı bırak ki SADECE sayı tavanı sınansın.
	limits.MaxZeroFraction = 1.0

	var obs []Observation
	for i := 0; i < 5; i++ {
		obs = append(obs, absent("gitti"+string(rune('a'+i)), long()))
	}
	for i := 0; i < 100; i++ {
		obs = append(obs, present("kalan"+string(rune('a'+i%26)), "ops"))
	}

	plan := BuildPlan(now, obs, limits)

	if plan.Abort == "" {
		t.Fatal("5 iptal, sınır 3 — koşu durdurulmadı")
	}
	if !strings.Contains(plan.Abort, "max_revoke_per_run") {
		t.Errorf("sebep = %q, sınırı adıyla söylemeliydi", plan.Abort)
	}
}

// Normal koşu: roller değişen kullanıcılar uygulanır, cevaplanamayanlara
// DOKUNULMAZ.
func TestNormalRunAppliesAndSkipsUnknown(t *testing.T) {
	// Cevaplanamayan oran tavanın ALTINDA olmalı, yoksa koşu (doğru
	// biçimde) iptal edilir; sınanmak istenen normal akış.
	obs := []Observation{unknown("c")}
	for i := 0; i < 9; i++ {
		obs = append(obs, present("k"+string(rune('a'+i)), "ops"))
	}

	plan := BuildPlan(now, obs, DefaultLimits())

	if plan.Abort != "" {
		t.Fatalf("beklenmeyen iptal: %s", plan.Abort)
	}
	if len(plan.Apply) != 9 {
		t.Errorf("%d uygulama, 9 bekleniyordu", len(plan.Apply))
	}
	if len(plan.Unknown) != 1 || plan.Unknown[0] != "c" {
		t.Errorf("Unknown = %v, [c] bekleniyordu", plan.Unknown)
	}
	for _, a := range plan.Apply {
		if a.Username == "c" {
			t.Error("cevaplanamayan kullanıcıya dokunuldu")
		}
	}
}

// Boş gözlem listesi hiçbir şey yapmamalı — ve iptal de etmemeli.
func TestEmptyObservationsIsNoop(t *testing.T) {
	plan := BuildPlan(now, nil, DefaultLimits())

	if plan.Abort != "" || len(plan.Apply) != 0 {
		t.Errorf("boş liste = %+v, sessiz no-op bekleniyordu", plan)
	}
}

// MinZeroFloor: küçük kurumda tek ayrılma oranı aşar ama TABAN
// aşılmadığı için durmamalı.
func TestSmallOrgSingleDepartureNotBlockedByFraction(t *testing.T) {
	// 3 kullanıcı, 1'i ayrılmış = %33, oran tavanı %10 — ama taban 3
	// olduğu için (1 < 3) durdurulmamalı.
	obs := []Observation{
		absent("gitti", long()),
		present("a", "ops"),
		present("b", "ops"),
	}

	plan := BuildPlan(now, obs, DefaultLimits())

	if plan.Abort != "" {
		t.Errorf("3 kişilik kurumda tek ayrılma durduruldu: %s\n"+
			"MinZeroFloor'un amacı tam olarak bunu önlemek", plan.Abort)
	}
}

// Cevaplanamayan oran tavanının TABANI YOK — ve bu bilinçli.
//
// Sıfırlanan-oran tavanının aksine, buradaki iptal GÜVENLİ yöne düşüyor:
// koşu atlanır, kimsenin yetkisi değişmez, bir sonraki tik yeniden
// dener. Küçük bir kurulumda tek bir geçici hata koşuyu durdurabilir;
// bunun sessiz kalmaması sync_runs tablosunun ve "son başarılı koşu"
// alanının işi.
func TestUnknownCeilingHasNoFloorOnPurpose(t *testing.T) {
	obs := []Observation{unknown("a"), present("b", "ops"), present("c", "ops")}

	plan := BuildPlan(now, obs, DefaultLimits())

	if plan.Abort == "" {
		t.Error("3 kullanıcının 1'i cevaplanamazken koşu sürdü; " +
			"iptal güvenli yön ve görünürlüğü sync_runs sağlıyor")
	}
	if len(plan.Apply) != 0 {
		t.Errorf("iptal edilen koşuda %d uygulama var", len(plan.Apply))
	}
}
