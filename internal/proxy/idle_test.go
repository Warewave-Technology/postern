package proxy

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestIdleGuardFiresWhenNothingFlows(t *testing.T) {
	g := newIdleGuard(150 * time.Millisecond)

	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	go g.watch(ctx, cancel)

	select {
	case <-ctx.Done():
		if !errors.Is(context.Cause(ctx), ErrIdleTimeout) {
			t.Errorf("sebep = %v, ErrIdleTimeout bekleniyordu", context.Cause(ctx))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("boşta kalma sınırı hiç tetiklenmedi")
	}
}

// Sürekli çıktı akan bir oturum boşta SAYILMAMALI.
//
// Bu, korumanın en kolay yanlış yazılan yanı: "boşta" tuş vuruşu diye
// tanımlanırsa, bir saat süren `make -j` çıktı üretmesine rağmen
// ortasından kesilir. Bu testin geçmesi, tanımın bayt akışı olduğunu
// ispatlıyor.
func TestIdleGuardDoesNotFireDuringContinuousOutput(t *testing.T) {
	g := newIdleGuard(300 * time.Millisecond)

	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	go g.watch(ctx, cancel)

	w := g.wrap(io.Discard)

	// Sınırdan kısa aralıklarla, sınırın üç katı boyunca yaz.
	deadline := time.Now().Add(900 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, err := w.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)

		if ctx.Err() != nil {
			t.Fatalf("akış sürerken kapandı: %v", context.Cause(ctx))
		}
	}
}

// Yazma etkinliği sınırı ERTELEMELİ.
func TestIdleGuardWriteDefersTimeout(t *testing.T) {
	g := newIdleGuard(time.Hour)

	time.Sleep(50 * time.Millisecond)
	before := g.idleFor()

	if _, err := g.wrap(io.Discard).Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	after := g.idleFor()

	if after >= before {
		t.Errorf("yazmadan sonra boşta süre %v, öncesi %v — damga konmamış", after, before)
	}
}

// nil koruma sarmalayıcı eklemeden geçmeli: sınır kapalıyken maliyeti sıfır.
func TestNilIdleGuardWrapIsPassthrough(t *testing.T) {
	var g *idleGuard
	if got := g.wrap(io.Discard); got != io.Discard {
		t.Error("nil koruma yazıcıyı sarmalamış")
	}
}

func TestBoundAppliesMaxLifetime(t *testing.T) {
	ctx, _, stop := bound(context.Background(), 0, 150*time.Millisecond)
	defer stop()

	select {
	case <-ctx.Done():
		if !errors.Is(context.Cause(ctx), ErrMaxLifetime) {
			t.Errorf("sebep = %v, ErrMaxLifetime bekleniyordu", context.Cause(ctx))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ömür sınırı tetiklenmedi")
	}
}

// İkisi de kapalıysa bağlam DOKUNULMADAN geçmeli — varsayılan davranış
// değişmemeli.
func TestBoundWithNoLimitsDoesNotCancel(t *testing.T) {
	parent := context.Background()
	ctx, guard, stop := bound(parent, 0, 0)
	defer stop()

	if guard != nil {
		t.Error("sınır kapalıyken koruma kurulmuş")
	}
	if ctx.Done() != nil {
		t.Error("sınır kapalıyken iptal edilebilir bağlam üretilmiş")
	}
}

// Ömür sınırı, boşta kalma sınırıyla birlikte de çalışmalı: trafik akmaya
// devam etse bile mutlak ömür dolunca oturum kapanır.
//
// Gerekçesi somut: süreli rol atamaları oturum ORTASINDA yeniden
// denetlenmiyor. Aktif bir oturum, kendi yetkisinden uzun yaşamamalı.
func TestMaxLifetimeFiresDespiteActivity(t *testing.T) {
	ctx, guard, stop := bound(context.Background(), time.Hour, 200*time.Millisecond)
	defer stop()

	go func() {
		w := guard.wrap(io.Discard)
		for ctx.Err() == nil {
			w.Write([]byte("x"))
			time.Sleep(10 * time.Millisecond)
		}
	}()

	select {
	case <-ctx.Done():
		if !errors.Is(context.Cause(ctx), ErrMaxLifetime) {
			t.Errorf("sebep = %v, ErrMaxLifetime bekleniyordu", context.Cause(ctx))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("trafik akarken ömür sınırı tetiklenmedi")
	}
}
