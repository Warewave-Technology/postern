package proxy

import (
	"context"
	"io"
	"sync/atomic"
	"time"
)

// Oturum ömür sınırları.
//
// BURADA olmalarının sebebi lifecycle.go'nun başındaki argümanın aynısı:
// iki kapı (SSH ve web terminali) tek oturum akışını paylaşıyor. Sınırı
// internal/sshd'ye koymak, WS /api/terminal/{target} yolunu sınırsız
// bırakırdı.

// idleGuard, iki yönde de bayt akmadığında oturumu kapatır.
//
// "Boşta" tanımı BAYT AKIŞIDIR, tuş vuruşu değil: çıktı üreten uzun bir
// derleme boşta sayılmamalı. Bu yüzden damga üç yazıcıya birden konuyor
// (kullanıcı→hedef, hedef→kullanıcı, stderr).
type idleGuard struct {
	// last, son etkinliğin monotonik nanosaniyesi.
	//
	// Mutex değil atomic: io.Copy bu yola her 32 KB'de bir uğruyor ve
	// kilit yolundan uzak durmalı.
	last atomic.Int64

	timeout time.Duration
	start   time.Time
}

func newIdleGuard(timeout time.Duration) *idleGuard {
	g := &idleGuard{timeout: timeout, start: time.Now()}
	g.touch()
	return g
}

func (g *idleGuard) touch() {
	g.last.Store(int64(time.Since(g.start)))
}

// idleFor, son etkinlikten bu yana geçen süre.
func (g *idleGuard) idleFor() time.Duration {
	return time.Since(g.start) - time.Duration(g.last.Load())
}

// wrap, yazıcıyı etkinlik damgalayan bir sarmalayıcıya alır.
func (g *idleGuard) wrap(w io.Writer) io.Writer {
	if g == nil {
		return w
	}
	return &touchWriter{w: w, g: g}
}

type touchWriter struct {
	w io.Writer
	g *idleGuard
}

func (t *touchWriter) Write(p []byte) (int, error) {
	t.g.touch()
	return t.w.Write(p)
}

// watch, boşta kalma süresi aşıldığında cancel çağırır.
//
// Tik aralığı timeout/4: sabit bir aralık uzun zaman aşımlarında boşuna
// uyanır, kısa olanlarda ise sınırı çeyrek periyottan fazla aşardı.
func (g *idleGuard) watch(ctx context.Context, cancel func(error)) {
	tick := g.timeout / 4
	if tick < time.Second {
		tick = time.Second
	}

	t := time.NewTicker(tick)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if g.idleFor() >= g.timeout {
				cancel(ErrIdleTimeout)
				return
			}
		}
	}
}

// bound, oturum bağlamını ömür ve boşta kalma sınırlarıyla sarar.
//
// Dönen cause fonksiyonu, oturumun HANGİ sınır yüzünden kapandığını
// söyler: denetim kaydında "boşta kaldı" ile "ömrü doldu" ayrı olaylar
// ve ikisi de "kullanıcı çıktı"dan farklı.
func bound(ctx context.Context, idle, lifetime time.Duration) (
	context.Context, *idleGuard, func()) {

	var stops []func()
	stop := func() {
		for i := len(stops) - 1; i >= 0; i-- {
			stops[i]()
		}
	}

	if lifetime > 0 {
		// WithTimeoutCause: Cause() sınırı ayırt edilebilir kılıyor,
		// düz DeadlineExceeded "ne oldu" sorusunu cevaplamıyor.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeoutCause(ctx, lifetime, ErrMaxLifetime)
		stops = append(stops, cancel)
	}

	var guard *idleGuard
	if idle > 0 {
		var cancel context.CancelCauseFunc
		ctx, cancel = context.WithCancelCause(ctx)
		stops = append(stops, func() { cancel(nil) })

		guard = newIdleGuard(idle)
		go guard.watch(ctx, cancel)
	}

	return ctx, guard, stop
}
