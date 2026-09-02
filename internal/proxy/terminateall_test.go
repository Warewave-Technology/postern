package proxy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

/*
 * ⚠️ KAPANIŞ SEBEBİ, "YÖNETİCİ KESTİ" DEĞİL.
 *
 * İkisi de oturumu kapatıyor ama denetim kaydına ve kullanıcıya
 * bambaşka şeyler söylüyorlar. Aynı sebebi kullansaydık bir dağıtım
 * gecesi defter, kimsenin yapmadığı yüzlerce kesme satırıyla dolar ve
 * gerçek bir kesmeyi içinde bulmak imkânsızlaşırdı.
 */
func TestTerminateAllUsesTheShutdownReason(t *testing.T) {
	live := NewLive()

	got := make(chan error, 2)
	for _, id := range []string{"a", "b"} {
		live.add(id, func(cause error) { got <- cause })
	}

	if n := live.TerminateAll(ErrShuttingDown); n != 2 {
		t.Fatalf("kesilen oturum = %d, 2 bekleniyordu", n)
	}

	for range 2 {
		select {
		case cause := <-got:
			if !errors.Is(cause, ErrShuttingDown) {
				t.Errorf("sebep kapanış değil: %v", cause)
			}
			if errors.Is(cause, ErrTerminated) {
				t.Error("kapanış, yönetici kesmesi gibi raporlandı")
			}
		default:
			t.Fatal("oturum kesilmedi")
		}
	}
}

// Boş defterde çağrılmak güvenli olmalı: kapanış yolu her koşuda
// çalışıyor ve akan oturum olmayabilir.
func TestTerminateAllOnAnEmptyRegistry(t *testing.T) {
	if n := NewLive().TerminateAll(ErrShuttingDown); n != 0 {
		t.Fatalf("boş defterde %d oturum kesildi", n)
	}
	var nilLive *Live
	if n := nilLive.TerminateAll(ErrShuttingDown); n != 0 {
		t.Fatalf("nil defterde %d oturum kesildi", n)
	}
}

/*
 * ⚠️ VEDA CÜMLESİ KAPANIŞI DA ANLATIYOR.
 *
 * sayGoodbye'ın switch'i bilmediği sebepte sessizce dönüyor: yeni
 * sebep eklenip cümlesi eklenmezse, kullanıcı yine sessizce kopan bir
 * oturum görür — düzeltmenin amacı tam da oydu.
 */
func TestGoodbyeExplainsAShutdown(t *testing.T) {
	down, _, _ := newFakeChannel()
	up, _, _ := newFakeChannel()
	b := New(down, make(chan *ssh.Request), up, make(chan *ssh.Request),
		nil, false, RequestPolicy{}, testLogger())

	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(ErrShuttingDown)
	b.sayGoodbye(ctx)

	if got := down.dataW.String(); !strings.Contains(got, "shutting down") {
		t.Fatalf("kapanış sebebi kullanıcıya gitmedi: %q", got)
	}
}
