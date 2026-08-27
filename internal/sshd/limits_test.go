package sshd

import (
	"sync"
	"testing"
	"time"
)

func TestConnLimiterCounts(t *testing.T) {
	t.Run("kuresel sinir", func(t *testing.T) {
		l := newConnLimiter(2, 0)

		r1, reason := l.acquire("10.0.0.1")
		if r1 == nil {
			t.Fatalf("ilk bağlantı reddedildi: %s", reason)
		}
		r2, _ := l.acquire("10.0.0.2")
		if r2 == nil {
			t.Fatal("ikinci bağlantı reddedildi")
		}

		r3, reason := l.acquire("10.0.0.3")
		if r3 != nil {
			t.Error("üçüncü bağlantı kabul edildi, sınır 2")
		}
		if reason != "global" {
			t.Errorf("sebep = %q, \"global\" bekleniyordu", reason)
		}

		// Bırakma gerçekten yer açmalı. Bu ikinci yarı olmadan test,
		// sayacın artmasını doğrular ama azalmasını doğrulamaz — ve
		// azalmayan bir sayaç bastion'ı zamanla kilitler.
		r1()
		r4, reason := l.acquire("10.0.0.4")
		if r4 == nil {
			t.Errorf("bırakma sonrası hâlâ reddediyor: %s", reason)
		}
	})

	t.Run("IP basina sinir", func(t *testing.T) {
		l := newConnLimiter(0, 2)

		a, _ := l.acquire("10.0.0.1")
		b, _ := l.acquire("10.0.0.1")
		if a == nil || b == nil {
			t.Fatal("aynı IP'den ilk iki bağlantı reddedildi")
		}

		c, reason := l.acquire("10.0.0.1")
		if c != nil {
			t.Error("aynı IP'den üçüncü bağlantı kabul edildi")
		}
		if reason != "per-ip" {
			t.Errorf("sebep = %q, \"per-ip\" bekleniyordu", reason)
		}

		// BAŞKA bir IP etkilenmemeli: sınır kaynağa özel.
		d, _ := l.acquire("10.0.0.2")
		if d == nil {
			t.Error("farklı IP de reddedildi — sınır IP başına değil")
		}
	})

	t.Run("sifir sinir = sinirsiz", func(t *testing.T) {
		l := newConnLimiter(0, 0)
		for i := 0; i < 100; i++ {
			if r, _ := l.acquire("10.0.0.1"); r == nil {
				t.Fatalf("%d. bağlantı reddedildi, sınırsız olmalıydı", i)
			}
		}
	})
}

// Sıfırlanan IP kaydı SİLİNMELİ.
//
// Yalnızca büyüyen bir harita, sınırlayıcının önlemesi gereken bellek
// sızıntısının ta kendisi olurdu — üstelik sınırlayıcı "çalışıyor"
// görünürken.
func TestConnLimiterDoesNotLeakIPs(t *testing.T) {
	l := newConnLimiter(0, 4)

	for i := 0; i < 1000; i++ {
		ip := "10.0." + string(rune('0'+i%10)) + ".1"
		release, _ := l.acquire(ip)
		if release == nil {
			t.Fatalf("%d. bağlantı reddedildi", i)
		}
		release()
	}

	total, ips := l.stats()
	if total != 0 {
		t.Errorf("total = %d, 0 bekleniyordu", total)
	}
	if ips != 0 {
		t.Errorf("perIP haritasında %d anahtar kaldı, 0 bekleniyordu", ips)
	}
}

// release iki kez çağrılırsa sayaç bozulmamalı.
func TestConnLimiterReleaseIsIdempotent(t *testing.T) {
	l := newConnLimiter(2, 0)

	release, _ := l.acquire("10.0.0.1")
	release()
	release()

	total, ips := l.stats()
	if total != 0 {
		t.Errorf("total = %d, çifte release sayacı bozmuş", total)
	}
	if ips != 0 {
		t.Errorf("ips = %d", ips)
	}

	// Ve sınır hâlâ 2 olmalı, 3 değil.
	a, _ := l.acquire("a")
	b, _ := l.acquire("b")
	c, _ := l.acquire("c")
	if a == nil || b == nil {
		t.Fatal("iki bağlantı alınamadı")
	}
	if c != nil {
		t.Error("çifte release sınırı gevşetmiş")
	}
}

func TestConnLimiterIsRaceFree(t *testing.T) {
	l := newConnLimiter(50, 5)

	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := "10.0.0." + string(rune('0'+i%8))
			if release, _ := l.acquire(ip); release != nil {
				release()
			}
		}(i)
	}
	wg.Wait()

	total, ips := l.stats()
	if total != 0 || ips != 0 {
		t.Errorf("eşzamanlı koşu sonrası total=%d ips=%d, ikisi de 0 olmalıydı", total, ips)
	}
}

// recordingDeadline, kendisine verilen son tarihleri kaydeder.
type recordingDeadline struct {
	mu    sync.Mutex
	times []time.Time
}

func (r *recordingDeadline) SetDeadline(t time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.times = append(r.times, t)
	return nil
}

// OOB süre uzatması, onayı kapsayacak kadar ileri olmalı.
//
// Bu, canlı bir kimlik sağlayıcı olmadan sınanabilen tek yer: politikanın
// kendisi burada, ağ çağrısı değil.
func TestExtendDeadlineCoversOOBWait(t *testing.T) {
	var rec recordingDeadline

	before := time.Now()
	extendDeadline(&rec, oobTimeout+oobDeadlineSlack, testLogger())

	if len(rec.times) != 1 {
		t.Fatalf("%d son tarih ayarlandı, 1 bekleniyordu", len(rec.times))
	}

	got := rec.times[0].Sub(before)
	if got < oobTimeout {
		t.Errorf("uzatma %v, en az oobTimeout (%v) olmalıydı — tarayıcı girişi kesilir",
			got, oobTimeout)
	}
}
