package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Warewave-Technology/postern/internal/model"
)

func seedTarget(t *testing.T, s *Store, name string) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.CreateTarget(ctx, model.Target{
		Name: name, Host: "10.0.0.1", Port: 22, HostKey: testHostKey,
	}); err != nil {
		t.Fatalf("CreateTarget(%s): %v", name, err)
	}
}

func TestTargetLabelRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedTarget(t, s, "web01")

	if err := s.SetTargetLabel(ctx, "web01", "env", "prod", "yigit", "cli"); err != nil {
		t.Fatalf("SetTargetLabel: %v", err)
	}
	if err := s.SetTargetLabel(ctx, "web01", "team", "platform", "yigit", "cli"); err != nil {
		t.Fatalf("SetTargetLabel: %v", err)
	}

	got, err := s.TargetLabels(ctx, "web01")
	if err != nil {
		t.Fatalf("TargetLabels: %v", err)
	}
	if got["env"] != "prod" || got["team"] != "platform" || len(got) != 2 {
		t.Fatalf("etiketler = %v", got)
	}

	// Aynı anahtarı tekrar yazmak DEĞERİ GÜNCELLER. Çakışma hatası
	// dönseydi, "env=staging" yazmak isteyen operatör önce eskisini elle
	// silmek zorunda kalırdı.
	if err := s.SetTargetLabel(ctx, "web01", "env", "staging", "yigit", "cli"); err != nil {
		t.Fatalf("ikinci yazma: %v", err)
	}
	got, _ = s.TargetLabels(ctx, "web01")
	if got["env"] != "staging" || len(got) != 2 {
		t.Fatalf("güncelleme sonrası etiketler = %v", got)
	}
}

func TestTargetLabelDeleteMissingIsNotFound(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedTarget(t, s, "web01")

	// ⚠️ "Sildim" demek YANLIŞ olurdu: olmayan bir etiketi kaldırdığını
	// söyleyen bir API, yanlış hedefe bakan operatöre işini yaptığını
	// söyler.
	err := s.DeleteTargetLabel(ctx, "web01", "yok", "yigit", "cli")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("hata = %v, ErrNotFound bekleniyordu", err)
	}
}

func TestTargetsCarriesLabels(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedTarget(t, s, "web01")
	seedTarget(t, s, "db01")

	if err := s.SetTargetLabel(ctx, "db01", "env", "prod", "yigit", "cli"); err != nil {
		t.Fatal(err)
	}

	targets, err := s.Targets(ctx)
	if err != nil {
		t.Fatalf("Targets: %v", err)
	}
	byName := map[string]model.Target{}
	for _, tg := range targets {
		byName[tg.Name] = tg
	}
	if byName["db01"].Labels["env"] != "prod" {
		t.Errorf("db01 etiketi listeye girmemiş: %v", byName["db01"].Labels)
	}
	// Etiketi olmayan hedef, BAŞKASININ etiketini almamalı — birleştirme
	// hedef adına göre yapılıyor ve kayması sessizce yanlış bilgi verirdi.
	if len(byName["web01"].Labels) != 0 {
		t.Errorf("web01 etiketsiz olmalı: %v", byName["web01"].Labels)
	}
}

func TestValidateLabel(t *testing.T) {
	long := strings.Repeat("a", 64)

	bad := map[string][2]string{
		"boş anahtar":        {"", "v"},
		"boşluklu anahtar":   {"env prod", "v"},
		"eğik çizgi":         {"env/prod", "v"},
		"rakamla başlamıyor": {"-env", "v"},
		"çok uzun anahtar":   {long, "v"},
		"kontrol karakteri":  {"env", "pr\nod"},
		"çok uzun değer":     {"env", strings.Repeat("x", 256)},
	}
	for name, kv := range bad {
		if err := ValidateLabel(kv[0], kv[1]); err == nil {
			t.Errorf("%s: kabul edildi (%q=%q)", name, kv[0], kv[1])
		}
	}

	good := [][2]string{
		{"env", "prod"},
		{"team.name", "payments"},
		{"tier_1", ""},
		{"a", strings.Repeat("x", 255)},
		{"v2", "üretim"}, // ASCII dışı DEĞER serbest: yalnızca anahtar dar
	}
	for _, kv := range good {
		if err := ValidateLabel(kv[0], kv[1]); err != nil {
			t.Errorf("%q=%q reddedildi: %v", kv[0], kv[1], err)
		}
	}
}

// Etiket bir NOT, bir yetki değil: hedefi silmek etiketleri de
// götürmeli. RESTRICT olsaydı etiketlenmiş bir hedef silinemez hâle
// gelir ve operatör önce etiketleri tek tek kaldırmak zorunda kalırdı.
func TestDeletingTargetRemovesLabels(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedTarget(t, s, "web01")
	if err := s.SetTargetLabel(ctx, "web01", "env", "prod", "yigit", "cli"); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteTarget(ctx, "web01"); err != nil {
		t.Fatalf("DeleteTarget: %v", err)
	}

	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM target_labels;`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("hedef silindi ama %d etiket kaldı", n)
	}
}
