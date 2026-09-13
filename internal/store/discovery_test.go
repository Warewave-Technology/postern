package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/secret"
)

func aSource(name string) DiscoverySource {
	return DiscoverySource{
		Name: name, Kind: "proxmox", URL: "https://pve.example:8006", Username: "postern@pve!keşif",
		TagKey: "role", Port: 22, IntervalSeconds: 3600, Enabled: true, CreatedBy: "ops",
	}
}

func withBox(t *testing.T, s *Store) {
	t.Helper()
	box, err := secret.Init(filepath.Join(t.TempDir(), "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	s.UseSecretBox(box)
}

/*
 * ⚠️ SIR MÜHÜRLÜ YAZILIYOR, YAPIDAN HİÇ ÇIKMIYOR ve anahtar yokken kaynak
 * hiç yazılmıyor. Boş sırla güncelleme kayıtlı sırrı KORUYOR: panel sırrı
 * hiç görmediği için "değiştirmedim" demenin başka yolu yok.
 */
func TestDiscoverySourceKeepsItsSecretSealed(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.CreateDiscoverySource(ctx, aSource("lab"), "gizli"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("anahtarsız store kaynağı kabul etti: %v", err)
	}
	withBox(t, s)

	id, err := s.CreateDiscoverySource(ctx, aSource("lab"), "gizli")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.DiscoverySource(ctx, id)
	if err != nil || !got.SecretSet || got.Name != "lab" || got.Port != 22 || !got.Enabled ||
		got.IntervalSeconds != 3600 || got.CreatedBy != "ops" || got.CreatedAt.IsZero() {
		t.Fatalf("kaynak geri okunmadı: %+v (%v)", got, err)
	}
	var raw string
	if err := s.db.QueryRowContext(ctx, `SELECT secret FROM discovery_sources WHERE id = $1`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if raw == "gizli" || raw == "" {
		t.Fatalf("sır düz metin yazılmış: %q", raw)
	}
	if plain, err := s.DiscoverySourceSecret(ctx, id); err != nil || plain != "gizli" {
		t.Fatalf("sır açılmadı: %q (%v)", plain, err)
	}

	got.Name, got.IntervalSeconds = "lab2", 0
	if err := s.UpdateDiscoverySource(ctx, got, ""); err != nil {
		t.Fatal(err)
	}
	if plain, _ := s.DiscoverySourceSecret(ctx, id); plain != "gizli" {
		t.Errorf("boş sırla güncelleme kayıtlı sırrı sildi: %q", plain)
	}
	if again, _ := s.DiscoverySource(ctx, id); again.Name != "lab2" || again.IntervalSeconds != 0 {
		t.Errorf("güncelleme yazılmadı: %+v", again)
	}
	if err := s.UpdateDiscoverySource(ctx, got, "yeni"); err != nil {
		t.Fatal(err)
	}
	if plain, _ := s.DiscoverySourceSecret(ctx, id); plain != "yeni" {
		t.Errorf("yeni sır yazılmadı: %q", plain)
	}

	// Ad harf duyarsız tekil; silme adı döndürüyor ve kaynak gidiyor.
	if _, err := s.CreateDiscoverySource(ctx, aSource("LAB2"), "x"); !errors.Is(err, ErrConflict) {
		t.Errorf("aynı adla ikinci kaynak: %v", err)
	}
	if err := s.UpdateDiscoverySource(ctx, DiscoverySource{ID: "yok", Port: 22}, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("olmayan kaynağın güncellemesi: %v", err)
	}
	if name, err := s.DeleteDiscoverySource(ctx, id); err != nil || name != "lab2" {
		t.Fatalf("silme: %q (%v)", name, err)
	}
	if _, err := s.DiscoverySource(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("silinen kaynak hâlâ okunuyor: %v", err)
	}
	if list, _ := s.DiscoverySources(ctx); len(list) != 0 {
		t.Errorf("liste boş değil: %+v", list)
	}
}

/*
 * ⚠️ KOŞU YAZARKEN İNSANIN KARARINA DOKUNMUYOR: ignored ve target_id koşu
 * satırında yenilenmiyor. Satır kimliği (kaynak, ref); ad değişince aynı
 * satır güncelleniyor, first_seen duruyor.
 */
func TestDiscoveredMachinesKeepHumanDecisionsAcrossRuns(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	withBox(t, s)
	ctx := context.Background()

	sid, err := s.CreateDiscoverySource(ctx, aSource("lab"), "gizli")
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	m := DiscoveredMachine{
		SourceID: sid, Ref: "qemu/101", Name: "web-01", Host: "10.0.0.5", Tags: []string{"role_ops"},
		Running: true, Role: "ops", Tagged: true, HostKey: "ssh-ed25519 AAAA test", LastSeen: t0,
	}
	if err := s.SaveDiscoveredMachine(ctx, m); err != nil {
		t.Fatal(err)
	}
	got, err := s.DiscoveredMachine(ctx, sid, "qemu/101")
	if err != nil || got.Name != "web-01" || got.Source != "lab" || len(got.Tags) != 1 ||
		!got.FirstSeen.Equal(t0) || !got.LastSeen.Equal(t0) || !got.MissingSince.IsZero() {
		t.Fatalf("makine geri okunmadı: %+v (%v)", got, err)
	}

	// Yeniden adlandırılmış ve kayıp işaretlenmiş makine: aynı satır.
	if err := s.MarkDiscoveredMachineMissing(ctx, sid, "qemu/101", t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.DiscoveredMachine(ctx, sid, "qemu/101"); got.MissingSince.IsZero() {
		t.Fatal("kayıp işareti yazılmadı")
	}
	m.Name, m.LastSeen = "web-01-renamed", t0.Add(2*time.Minute)
	if err := s.SaveDiscoveredMachine(ctx, m); err != nil {
		t.Fatal(err)
	}
	all, _ := s.DiscoveredMachines(ctx, "")
	if len(all) != 1 || all[0].Name != "web-01-renamed" || !all[0].FirstSeen.Equal(t0) ||
		!all[0].MissingSince.IsZero() {
		t.Fatalf("yeniden görülen makine yeni satır açtı ya da ilk görülme kaydı: %+v", all)
	}

	// İnsanın kararları: hedefe bağ ve yok sayma, koşunun yazmasıyla silinmiyor.
	tid, err := s.CreateTarget(ctx, model.Target{Name: "web-01", Host: "10.0.0.5", Port: 22, HostKey: "ssh-ed25519 AAAA test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.LinkDiscoveredMachine(ctx, sid, "qemu/101", tid); err != nil {
		t.Fatal(err)
	}
	if name, changed, err := s.SetDiscoveredMachineIgnored(ctx, sid, "qemu/101", true); err != nil || !changed || name != "web-01-renamed" {
		t.Fatalf("yok sayma: %q %v (%v)", name, changed, err)
	}
	if _, changed, _ := s.SetDiscoveredMachineIgnored(ctx, sid, "qemu/101", true); changed {
		t.Error("ikinci yok sayma 'değişti' dedi")
	}
	if err := s.SaveDiscoveredMachine(ctx, m); err != nil {
		t.Fatal(err)
	}
	got, _ = s.DiscoveredMachine(ctx, sid, "qemu/101")
	if got.TargetID != tid || got.Target != "web-01" || got.TargetHostKey != "ssh-ed25519 AAAA test" || !got.Ignored {
		t.Errorf("koşu insanın kararını sildi: %+v", got)
	}
	if err := s.LinkDiscoveredMachine(ctx, sid, "yok", tid); !errors.Is(err, ErrNotFound) {
		t.Errorf("olmayan makineye bağ: %v", err)
	}

	// Kaynak silinince makineleri gidiyor, hedef kalıyor.
	if _, err := s.DeleteDiscoverySource(ctx, sid); err != nil {
		t.Fatal(err)
	}
	if left, _ := s.DiscoveredMachines(ctx, ""); len(left) != 0 {
		t.Errorf("kaynak silindi, makineleri kaldı: %+v", left)
	}
	if _, err := s.Target(ctx, "web-01"); err != nil {
		t.Errorf("kaynakla birlikte hedef de silindi: %v", err)
	}
}

// Koşu satırları ve zamanlayıcının sahiplenmesi.
func TestDiscoveryRunsAndClaims(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	withBox(t, s)
	ctx := context.Background()

	sid, err := s.CreateDiscoverySource(ctx, aSource("lab"), "gizli")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	id, err := s.StartDiscoveryRun(ctx, DiscoveryRun{SourceID: sid, Trigger: "web", Actor: "ops", StartedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	runs, _ := s.DiscoveryRuns(ctx, sid, 10)
	if len(runs) != 1 || runs[0].Outcome != DiscoveryRunning || runs[0].ID != id || runs[0].Actor != "ops" {
		t.Fatalf("açık koşu: %+v", runs)
	}
	if err := s.FinishDiscoveryRun(ctx, DiscoveryRun{
		ID: id, FinishedAt: now.Add(time.Second), Outcome: DiscoveryOK, Seen: 3, NewMachines: 1, Missing: 1, KeyChanged: 1, Unreachable: 2,
	}); err != nil {
		t.Fatal(err)
	}
	latest, _ := s.LatestDiscoveryRuns(ctx)
	if r := latest[sid]; r.Outcome != DiscoveryOK || r.Seen != 3 || r.NewMachines != 1 || r.Missing != 1 ||
		r.KeyChanged != 1 || r.Unreachable != 2 || r.FinishedAt.IsZero() {
		t.Errorf("kapanan koşu: %+v", r)
	}
	if err := s.FinishDiscoveryRun(ctx, DiscoveryRun{ID: 9999, FinishedAt: now, Outcome: DiscoveryFailed}); !errors.Is(err, ErrNotFound) {
		t.Errorf("olmayan koşuyu kapatma: %v", err)
	}

	/*
	 * ⚠️ SAHİPLENME TEK KAZANAN: aynı saniyede iki bastion aynı kaynağı
	 * sormasın diye last_run_at yalnızca hâlâ eskiyse ilerliyor. Zamanı
	 * gelmemiş kaynak, kapalı kaynak ve zamanlanmamış kaynak alınmıyor.
	 */
	if ok, _ := s.ClaimDiscoverySource(ctx, sid, now, now.Add(-time.Hour)); !ok {
		t.Fatal("hiç koşmamış kaynak sahiplenilmedi")
	}
	if ok, _ := s.ClaimDiscoverySource(ctx, sid, now, now.Add(-time.Hour)); ok {
		t.Error("az önce koşan kaynak yeniden sahiplenildi")
	}
	if ok, _ := s.ClaimDiscoverySource(ctx, sid, now.Add(2*time.Hour), now.Add(time.Hour)); !ok {
		t.Error("vadesi geçen kaynak sahiplenilmedi")
	}
	src, _ := s.DiscoverySource(ctx, sid)
	if !src.LastRunAt.Equal(now.Add(2 * time.Hour)) {
		t.Errorf("last_run_at ilerlemedi: %v", src.LastRunAt)
	}
	src.Enabled = false
	if err := s.UpdateDiscoverySource(ctx, src, ""); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.ClaimDiscoverySource(ctx, sid, now.Add(9*time.Hour), now.Add(8*time.Hour)); ok {
		t.Error("kapalı kaynak sahiplenildi")
	}
	src.Enabled, src.IntervalSeconds = true, 0
	if err := s.UpdateDiscoverySource(ctx, src, ""); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.ClaimDiscoverySource(ctx, sid, now.Add(9*time.Hour), now.Add(8*time.Hour)); ok {
		t.Error("zamanlanmamış kaynak sahiplenildi")
	}
	if err := s.TouchDiscoverySource(ctx, "yok", now); !errors.Is(err, ErrNotFound) {
		t.Errorf("olmayan kaynağa dokunma: %v", err)
	}
}
