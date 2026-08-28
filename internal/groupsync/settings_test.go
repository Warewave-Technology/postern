package groupsync

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/warewave/postern/internal/store"
	"github.com/warewave/postern/internal/testdb"
)

func syncStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), testdb.DSN(t))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func fallback() Settings {
	return Settings{
		Enabled: false,
		Config: Config{
			Interval: 15 * time.Minute,
			Timeout:  5 * time.Minute,
			DryRun:   false,
			Limits: Limits{
				Grace:              time.Hour,
				MaxZeroFraction:    0.10,
				MinZeroFloor:       3,
				MaxUnknownFraction: 0.25,
				MaxRevokePerRun:    25,
			},
		},
	}
}

// Saklanan ayar yoksa YAML'daki değer geçerli: mevcut kurulumlar
// yükseltmeden sonra ayar kaybetmemeli.
func TestLoadSettingsFallsBackToTheFile(t *testing.T) {
	db := syncStore(t)

	got, err := LoadSettings(context.Background(), db, fallback())
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	if got.Config.Interval != 15*time.Minute || got.Config.Limits.MaxRevokePerRun != 25 {
		t.Errorf("dosya varsayılanları kaybedildi: %+v", got.Config)
	}
	if got.Enabled {
		t.Error("kapalıyken açık okundu")
	}
}

// Panelden yazılan değer dosyayı EZER — özelliğin bütün amacı bu.
func TestLoadSettingsPanelOverridesFile(t *testing.T) {
	ctx := context.Background()
	db := syncStore(t)

	for k, v := range map[string]string{
		KeyEnabled:         "true",
		KeyDryRun:          "true",
		KeyInterval:        "3m",
		KeyGrace:           "30m",
		KeyMaxRevokePerRun: "7",
		KeyMaxZeroFraction: "0.5",
	} {
		if err := db.SetSetting(ctx, k, v, false, "test"); err != nil {
			t.Fatalf("SetSetting %s: %v", k, err)
		}
	}

	got, err := LoadSettings(ctx, db, fallback())
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	if !got.Enabled || !got.Config.DryRun {
		t.Errorf("bayraklar okunmadı: %+v", got)
	}
	if got.Config.Interval != 3*time.Minute || got.Config.Limits.Grace != 30*time.Minute {
		t.Errorf("süreler okunmadı: %+v", got.Config)
	}
	if got.Config.Limits.MaxRevokePerRun != 7 || got.Config.Limits.MaxZeroFraction != 0.5 {
		t.Errorf("tavanlar okunmadı: %+v", got.Config.Limits)
	}
	// Yazılmayan anahtar dosyadan gelmeye devam etmeli.
	if got.Config.Limits.MinZeroFloor != 3 {
		t.Errorf("yazılmayan anahtar varsayılanı kaybetti: %d", got.Config.Limits.MinZeroFloor)
	}
}

/*
 * ⚠️ HATALI DEĞER VARSAYILANA DÜŞMEZ, HATA DÖNER.
 *
 * "2O" (rakam sıfır yerine harf O) yazan bir operatör sessizce
 * varsayılana dönseydi, patlama yarıçapı tavanı sandığından başka bir
 * değerde çalışırdı — ve YETKİ İPTAL EDEN bir döngüde fark edilmemesi
 * en pahalı şey bu.
 */
func TestLoadSettingsRefusesUnusableValues(t *testing.T) {
	ctx := context.Background()

	cases := map[string]string{
		KeyEnabled:            "evet",
		KeyInterval:           "15 dakika",
		KeyGrace:              "-1h",
		KeyMaxRevokePerRun:    "2O",
		KeyMaxZeroFraction:    "1.5",
		KeyMinZeroFloor:       "-1",
		KeyMaxUnknownFraction: "yuzde on",
		KeyDryRun:             "1 tabii",
	}

	for key, bad := range cases {
		t.Run(key, func(t *testing.T) {
			db := syncStore(t)
			if err := db.SetSetting(ctx, key, bad, false, "test"); err != nil {
				t.Fatalf("SetSetting: %v", err)
			}

			_, err := LoadSettings(ctx, db, fallback())
			if err == nil {
				t.Fatalf("%s = %q kabul edildi", key, bad)
			}
			var ise *InvalidSettingError
			if !errors.As(err, &ise) {
				t.Fatalf("hata tipi yanlış: %T %v", err, err)
			}
			// Mesaj SUÇLUYU söylemeli: hangi anahtar, ne yazıyor.
			if ise.Key != key {
				t.Errorf("hata yanlış anahtarı suçluyor: %s", ise.Key)
			}
			if ise.Got != bad {
				t.Errorf("hata değeri göstermiyor: %q", ise.Got)
			}
		})
	}
}

// Boşaltılan ayar "varsayılana dön" demek — silmekle aynı.
func TestLoadSettingsTreatsEmptyAsUnset(t *testing.T) {
	ctx := context.Background()
	db := syncStore(t)

	if err := db.SetSetting(ctx, KeyInterval, "", false, "test"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	got, err := LoadSettings(ctx, db, fallback())
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	if got.Config.Interval != 15*time.Minute {
		t.Errorf("boş değer varsayılana dönmedi: %v", got.Config.Interval)
	}
}
