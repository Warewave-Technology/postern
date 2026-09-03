package groupsync

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/Warewave-Technology/postern/internal/store"
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

	/*
	 * IgnoredKeys, ayarlar tablosunda duran ama ARTIK OKUNMAYAN
	 * anahtarlar (patlama yarıçapı tavanları; gerekçe LoadSettings'te).
	 *
	 * ⚠️ Çağıranın bunu bildirmesi ŞART. Bir değeri yok saymak ile
	 * yok saydığını söylemek arasındaki fark, operatörün yürürlükte
	 * sandığı bir ayarla çalışıp çalışmadığıdır.
	 */
	IgnoredKeys []string
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

	/*
	 * ⚠️ PATLAMA YARIÇAPI TAVANLARI BURADAN OKUNMUYOR — YALNIZCA
	 * CONFIG DOSYASINDAN.
	 *
	 * config.go'daki SyncConfig yorumu bunu bir güvenlik değişmezi
	 * olarak ilan ediyor: "tavanı yükseltebilmek için host'a erişmek
	 * gerekmeli — admin bayrağının yalnızca CLI'dan verilebilmesiyle
	 * aynı gerekçe." Kod ise dördünü de ayarlar tablosundan okuyup
	 * paneli üstüne yazdırıyordu. Yorum mu kod mu yanlış sorusunun
	 * cevabı yorum lehine verildi: otomatik toplu iptalin üst
	 * sınırını ele geçirilmiş bir panel oturumu yükseltebilmemeli.
	 *
	 * ⚠️ ESKİ SATIRLAR SESSİZCE YOK SAYILMIYOR. Panelden bir değer
	 * yazmış kurulumlar var olabilir; onu okumayı bırakıp susmak,
	 * yürürlükte sandığı bir ayarla çalışan operatör bırakırdı — bu
	 * deponun en tanıdık arızası. Kalan satır uyarıyla bildiriliyor.
	 */
	for _, key := range []string{
		KeyMaxZeroFraction, KeyMinZeroFloor,
		KeyMaxUnknownFraction, KeyMaxRevokePerRun,
	} {
		if _, ok, err := str(key); err != nil {
			return out, err
		} else if ok {
			out.IgnoredKeys = append(out.IgnoredKeys, key)
		}
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
