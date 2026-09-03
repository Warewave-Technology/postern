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
	s, _ := syncStoreDSN(t)
	return s
}

// syncStoreDSN, aynısını DSN'i de vererek döner: bir testin tek bir
// yazmayı düşürmek için ikinci bir bağlantı açması gerekebiliyor.
func syncStoreDSN(t *testing.T) (*store.Store, string) {
	t.Helper()
	dsn := testdb.DSN(t)
	s, err := store.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dsn
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

// Ritim ayarları panelden ezilebiliyor — dry_run'ın orada olması
// özelliğin en çok işe yarayan yanı.
func TestLoadSettingsPanelOverridesTheRhythm(t *testing.T) {
	ctx := context.Background()
	db := syncStore(t)

	for k, v := range map[string]string{
		KeyEnabled:  "true",
		KeyDryRun:   "true",
		KeyInterval: "3m",
		KeyGrace:    "30m",
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
}

/*
 * ⚠️ PATLAMA YARIÇAPI TAVANLARI PANELDEN EZİLEMEZ.
 *
 * config.go'daki SyncConfig yorumu bunu bir güvenlik değişmezi olarak
 * ilan ediyordu — "tavanı yükseltebilmek için host'a erişmek gerekmeli,
 * admin bayrağının yalnızca CLI'dan verilebilmesiyle aynı gerekçe" —
 * ama kod dördünü de ayarlar tablosundan okuyup panele yazdırıyordu.
 * Yani yorum bir garanti veriyor, kod tutmuyordu.
 *
 * ⚠️ VE YOK SAYMAK SESSİZ DEĞİL. Panelden bir değer yazmış kurulumlar
 * olabilir; okumayı bırakıp susmak, operatörü yürürlükte sandığı bir
 * ayarla bırakırdı — bu deponun en tanıdık arızası.
 */
func TestCeilingsIgnoreTheSettingsTableAndSaySo(t *testing.T) {
	ctx := context.Background()
	db := syncStore(t)

	for k, v := range map[string]string{
		KeyMaxRevokePerRun:    "9999",
		KeyMaxZeroFraction:    "1",
		KeyMinZeroFloor:       "100000",
		KeyMaxUnknownFraction: "1",
	} {
		if err := db.SetSetting(ctx, k, v, false, "test"); err != nil {
			t.Fatalf("SetSetting %s: %v", k, err)
		}
	}

	got, err := LoadSettings(ctx, db, fallback())
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}

	want := fallback().Config.Limits
	if got.Config.Limits != want {
		t.Errorf("tavanlar ayarlar tablosundan ezildi:\n got %+v\nwant %+v",
			got.Config.Limits, want)
	}
	if len(got.IgnoredKeys) != 4 {
		t.Errorf("yok sayılan anahtarlar bildirilmedi: %v", got.IgnoredKeys)
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
		KeyEnabled:  "evet",
		KeyInterval: "15 dakika",
		KeyGrace:    "-1h",
		// ⚠️ Tavanlar burada YOK: artık ayarlar tablosundan hiç
		// okunmuyorlar (config dosyasından geliyorlar), dolayısıyla
		// oradaki bozuk bir değer bir ayrıştırma hatası değil, yok
		// sayılan bir satır. Onu TestCeilingsIgnoreTheSettingsTable
		// ölçüyor.
		KeyDryRun: "1 tabii",
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
