package proxy

import (
	"context"
	"errors"
	"testing"
	"time"
)

/*
 * ⚠️ AKTÖR ADI, İÇİNDE ": " GEÇSE BİLE BOZULMAMALI.
 *
 * İlk hâl sebebi fmt.Errorf("%w: %s") ile kurup son ": "den bölerek
 * okuyordu; böyle bir ad sessizce kırpılır ve denetim satırına yanlış
 * kişi yazılırdı. "Kim kesti" sorusunun cevabı ayrıştırma kazasına
 * açık olmamalı.
 */
func TestTerminatedByKeepsAwkwardNames(t *testing.T) {
	for _, name := range []string{"admin", "ops: gece", "a: b: c", ""} {
		cause := error(&terminatedError{by: name})
		if !errors.Is(cause, ErrTerminated) {
			t.Fatalf("%q: errors.Is(ErrTerminated) bozuldu", name)
		}
		got, ok := TerminatedBy(cause)
		if !ok {
			t.Fatalf("%q: kesme tanınmadı", name)
		}
		if got != name {
			t.Errorf("aktör = %q, %q bekleniyordu", got, name)
		}
	}
}

// Kesme dışındaki sebepler aktör üretmemeli.
func TestTerminatedByIgnoresOtherCauses(t *testing.T) {
	if who, ok := TerminatedBy(ErrIdleTimeout); ok || who != "" {
		t.Errorf("boşta kalma kesme sayıldı: %q %v", who, ok)
	}
	if who, ok := TerminatedBy(nil); ok || who != "" {
		t.Errorf("nil sebep kesme sayıldı: %q %v", who, ok)
	}
}

/*
 * ⚠️ DEFTER GERÇEKTEN İPTAL ETMELİ ve sebebi TAŞIMALI.
 *
 * Terminate'in true dönmesi tek başına hiçbir şey kanıtlamaz: iptal
 * etmeden true dönen bir uygulama da uçtan 200 aldırırdı.
 */
func TestLiveTerminateCancelsWithReason(t *testing.T) {
	l := NewLive()
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	l.add("s1", cancel)

	if !l.Running("s1") {
		t.Fatal("eklenen oturum defterde görünmüyor")
	}
	if !l.Terminate("s1", "yigit") {
		t.Fatal("Terminate false döndü")
	}

	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("bağlam iptal edilmedi — kesme iş yapmıyor")
	}
	cause := context.Cause(ctx)
	if !errors.Is(cause, ErrTerminated) {
		t.Fatalf("sebep = %v", cause)
	}
	if who, _ := TerminatedBy(cause); who != "yigit" {
		t.Errorf("aktör = %q", who)
	}
}

// Bilinmeyen kimlik false dönmeli: çağıran bunu "kesildi" diye
// çevirmemeli ve uç de öyle yapmıyor.
func TestLiveTerminateUnknownIsFalse(t *testing.T) {
	l := NewLive()
	if l.Terminate("yok", "yigit") {
		t.Error("olmayan oturum için true döndü")
	}
	if l.Running("yok") {
		t.Error("olmayan oturum akıyor göründü")
	}
}

// remove sonrası kesilemez: bitmiş bir oturumu kesilebilir göstermek,
// "bastım ve hiçbir şey olmadı" demekti.
func TestLiveRemoveStopsTermination(t *testing.T) {
	l := NewLive()
	_, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	l.add("s1", cancel)
	l.remove("s1")
	if l.Terminate("s1", "yigit") {
		t.Error("düşürülen oturum kesilebildi")
	}
}

// nil defter her yerde güvenli olmalı: Deps.Live boş bırakılabiliyor.
func TestNilLiveIsSafe(t *testing.T) {
	var l *Live
	l.add("s1", func(error) {})
	l.remove("s1")
	if l.Running("s1") || l.Terminate("s1", "x") || len(l.RunningIDs()) != 0 {
		t.Error("nil defter beklenmedik davrandı")
	}
}
