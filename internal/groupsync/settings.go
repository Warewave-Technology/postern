package groupsync

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/warewave/postern/internal/store"
)

/*
 * Senkronizasyon ayarları ARTIK VERİTABANINDA.
 *
 * NEDEN TAŞINDI: dizin senkronizasyonu bir LDAP özelliği ve LDAP'ın
 * kendisi zaten panelden yönetiliyor. Ayarların yalnızca YAML'da olması
 * iki şeyi bozuyordu: dizini panelden kuran operatör senkronizasyonu
 * göremiyordu, ve en çok ihtiyaç duyulan düğme — dry_run — bir dosya
 * düzenleyip süreci yeniden başlatmayı gerektiriyordu. Oysa dry_run'ın
 * varlık sebebi, YETKİ İPTAL EDEN bir döngüyü önce izlemek: onu açıp
 * kapatmak anlık olmalı.
 *
 * ⚠️ YAML BLOĞU HÂLÂ OKUNUYOR ve varsayılan olarak duruyor. Saklanan bir
 * anahtar yoksa dosyadaki değer geçerli — mevcut kurulumlar yükseltmeden
 * sonra ayar kaybetmiyor. Panelden yazılan değer dosyayı EZER.
 */

// Ayar anahtarları. Panelden yazılabilenler httpapi'deki beyaz listede.
const (
	KeyEnabled            = "sync.enabled"
	KeyInterval           = "sync.interval"
	KeyGrace              = "sync.grace"
	KeyDryRun             = "sync.dry_run"
	KeyMaxZeroFraction    = "sync.max_zero_fraction"
	KeyMinZeroFloor       = "sync.min_zero_floor"
	KeyMaxUnknownFraction = "sync.max_unknown_fraction"
	KeyMaxRevokePerRun    = "sync.max_revoke_per_run"
)

// Settings, bir koşunun ayarları ve açık olup olmadığı.
type Settings struct {
	Enabled bool
	Config  Config
}

/*
 * LoadSettings, saklanan ayarları okur; olmayanlar için fallback.
 *
 * ⚠️ HATALI DEĞER VARSAYILANA DÜŞMEZ, HATA DÖNER. Bir operatörün
 * "max_revoke_per_run: 2O" (harf O) yazması, sessizce varsayılana
 * dönmekle sonuçlansaydı, patlama yarıçapı tavanı sandığından başka bir
 * değerde çalışırdı — ve bu, yetki iptal eden bir döngüde tam olarak
 * fark edilmemesi en pahalı şey.
 */
func LoadSettings(ctx context.Context, db *store.Store, fallback Settings) (Settings, error) {
	out := fallback

	str := func(key string) (string, bool, error) {
		v, err := db.Setting(ctx, key)
		if errors.Is(err, store.ErrNotFound) {
			return "", false, nil
		}
		if err != nil {
			return "", false, err
		}
		if v == "" {
			// Boşaltılmış ayar "varsayılana dön" demek: silmekle aynı.
			return "", false, nil
		}
		return v, true, nil
	}

	if v, ok, err := str(KeyEnabled); err != nil {
		return out, err
	} else if ok {
		b, perr := strconv.ParseBool(v)
		if perr != nil {
			return out, invalid(KeyEnabled, v, "true or false")
		}
		out.Enabled = b
	}

	if v, ok, err := str(KeyDryRun); err != nil {
		return out, err
	} else if ok {
		b, perr := strconv.ParseBool(v)
		if perr != nil {
			return out, invalid(KeyDryRun, v, "true or false")
		}
		out.Config.DryRun = b
	}

	for _, d := range []struct {
		key string
		dst *time.Duration
	}{
		{KeyInterval, &out.Config.Interval},
		{KeyGrace, &out.Config.Limits.Grace},
	} {
		v, ok, err := str(d.key)
		if err != nil {
			return out, err
		}
		if !ok {
			continue
		}
		parsed, perr := time.ParseDuration(v)
		if perr != nil || parsed <= 0 {
			return out, invalid(d.key, v, "a positive duration like 15m or 1h")
		}
		*d.dst = parsed
	}

	for _, f := range []struct {
		key string
		dst *float64
	}{
		{KeyMaxZeroFraction, &out.Config.Limits.MaxZeroFraction},
		{KeyMaxUnknownFraction, &out.Config.Limits.MaxUnknownFraction},
	} {
		v, ok, err := str(f.key)
		if err != nil {
			return out, err
		}
		if !ok {
			continue
		}
		parsed, perr := strconv.ParseFloat(v, 64)
		if perr != nil || parsed < 0 || parsed > 1 {
			return out, invalid(f.key, v, "a fraction between 0 and 1")
		}
		*f.dst = parsed
	}

	for _, n := range []struct {
		key string
		dst *int
	}{
		{KeyMinZeroFloor, &out.Config.Limits.MinZeroFloor},
		{KeyMaxRevokePerRun, &out.Config.Limits.MaxRevokePerRun},
	} {
		v, ok, err := str(n.key)
		if err != nil {
			return out, err
		}
		if !ok {
			continue
		}
		parsed, perr := strconv.Atoi(v)
		if perr != nil || parsed < 0 {
			return out, invalid(n.key, v, "a whole number, zero or more")
		}
		*n.dst = parsed
	}

	return out, nil
}

func invalid(key, got, want string) error {
	return &InvalidSettingError{Key: key, Got: got, Want: want}
}

// InvalidSettingError, saklanan bir ayarın okunamaması.
type InvalidSettingError struct{ Key, Got, Want string }

func (e *InvalidSettingError) Error() string {
	return e.Key + " = " + strconv.Quote(e.Got) + " is not usable; expected " + e.Want
}
