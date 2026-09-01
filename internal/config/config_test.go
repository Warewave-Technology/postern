package config

import (
	"testing"
	"time"
)

/*
 * ⚠️ İKİ AYARIN SIFIR DEĞERLERİ AYRI ANLAMLARA GELİYOR.
 *
 * retain boş = "hiç silme" (kanıt silmek varsayılan olamaz).
 * min_free boş = VARSAYILANI kullan; açıkça "0" = kapat. İkisi aynı
 * değere düşseydi, eşiği kapatmak isteyen operatörle hiçbir şey
 * yazmamış operatör ayırt edilemezdi.
 */
func TestRecordingRetentionDefaults(t *testing.T) {
	var r RecordingConfig

	// retain: boş ve "0" → hiçbir şey silinmiyor.
	for _, v := range []string{"", "0"} {
		r.Retain = v
		d, err := r.RetainDuration()
		if err != nil || d != 0 {
			t.Errorf("retain=%q -> %v %v; kanıt silmek varsayılan olamaz", v, d, err)
		}
	}
	r.Retain = "90d"
	if d, err := r.RetainDuration(); err != nil || d != 90*24*time.Hour {
		t.Errorf("retain=90d -> %v %v", d, err)
	}
	r.Retain = "2160h"
	if d, err := r.RetainDuration(); err != nil || d != 2160*time.Hour {
		t.Errorf("retain=2160h -> %v %v", d, err)
	}
	// ⚠️ Çözülemeyen değer HATA, sessizce varsayılana düşmüyor:
	// "90gun" yazan operatör diskinin neden dolduğunu anlamalı.
	for _, bad := range []string{"90gun", "doksan", "-5d", "abc"} {
		if _, err := (RecordingConfig{Retain: bad}).RetainDuration(); err == nil {
			t.Errorf("retain=%q kabul edildi", bad)
		}
	}

	// min_free: boş → VARSAYILAN, "0" → kapalı.
	if n, err := (RecordingConfig{}).MinFreeBytes(); err != nil || n != DefaultRecordingMinFree {
		t.Errorf("min_free boş -> %d %v, varsayılan bekleniyordu", n, err)
	}
	if n, err := (RecordingConfig{MinFree: "0"}).MinFreeBytes(); err != nil || n != 0 {
		t.Errorf("min_free=0 -> %d %v, kapalı bekleniyordu", n, err)
	}
	for in, want := range map[string]uint64{
		"2GiB":   2 << 30,
		"500MiB": 500 << 20,
		"1024":   1024,
	} {
		if n, err := (RecordingConfig{MinFree: in}).MinFreeBytes(); err != nil || n != want {
			t.Errorf("min_free=%q -> %d %v, %d bekleniyordu", in, n, err, want)
		}
	}
	for _, bad := range []string{"iki gib", "-1", "2GB!"} {
		if _, err := (RecordingConfig{MinFree: bad}).MinFreeBytes(); err == nil {
			t.Errorf("min_free=%q kabul edildi", bad)
		}
	}
}
