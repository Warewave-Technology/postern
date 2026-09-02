package groupsync

import (
	"fmt"
	"testing"
	"time"
)

/*
 * ⚠️ SIFIR TAVAN, TAVANSIZ DEMEK DEĞİL.
 *
 * Koşul `MaxRevokePerRun > 0 && revoking > MaxRevokePerRun` idi: sıfır
 * korumayı tamamen kapatıyordu. Aynı sıfır config dosyasında
 * "varsayılanı kullan" (25) anlamına geliyor
 * (config.MaxRevokePerRunOrDefault), ama panelden yazılan ayar olduğu
 * gibi saklanıyordu — aynı değer, iki kapıdan girildiğinde iki zıt
 * anlam, ve panelden gireni toplu iptali SINIRSIZ yapıyordu.
 *
 * ⚠️ VE YALNIZCA BU SINIR ÖYLEYDİ. Kardeşleri sıfırda fail-SAFE:
 * MaxUnknownFraction=0 herhangi bir bilinmeyende, MaxZeroFraction=0
 * herhangi bir sıfırlamada koşuyu durduruyor. En pahalı işlemin sınırı
 * en gevşek olanıydı.
 */
func TestZeroRevokeCeilingFallsBackToTheDefault(t *testing.T) {
	now := time.Now()
	long := now.Add(-48 * time.Hour)

	obs := make([]Observation, 0, 60)
	for i := range 60 {
		obs = append(obs, absent(fmt.Sprintf("ayrilan%02d", i), long))
	}

	limits := DefaultLimits()
	limits.MaxRevokePerRun = 0
	// Kardeş kapılar bu testin ölçtüğünü gölgelemesin: iptali
	// durduracak tek şey toplu iptal tavanı olmalı.
	limits.MaxZeroFraction = 1
	limits.MinZeroFloor = 1 << 30
	limits.MaxUnknownFraction = 1

	plan := BuildPlan(now, obs, limits)
	if plan.Abort == "" {
		t.Fatalf("sıfır tavanla %d iptal geçti: koruma kapanmış", len(plan.Apply))
	}
	t.Logf("durduruldu: %s", plan.Abort)
}
