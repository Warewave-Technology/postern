package events

import (
	"sync"
	"testing"
	"time"
)

func TestSubscribeReceives(t *testing.T) {
	b := New(4, 8)
	ch, cancel, ok := b.Subscribe()
	if !ok {
		t.Fatal("abonelik açılmadı")
	}
	defer cancel()

	b.Publish(Event{Kind: SessionStarted, User: "yigit", Target: "web-01"})

	select {
	case e := <-ch:
		if e.Kind != SessionStarted || e.User != "yigit" {
			t.Fatalf("beklenmeyen olay: %+v", e)
		}
		if e.At.IsZero() {
			t.Error("At doldurulmamış")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("olay gelmedi")
	}
}

// TestPublishNeverBlocks bu paketin ASIL iddiasını ölçer.
//
// Publish çağıranlar bir SSH oturumunun açılış/kapanış yolunda. Burada
// bloklamak, tarayıcısını açık unutmuş bir yöneticinin yavaş
// bağlantısının bir SSH oturumunu kilitlemesi demek olurdu: izleme
// aracı, izlediği şeyi durduramaz.
//
// Abone HİÇ okumuyor ve tampon iki olay alıyor; yüzlerce yayın yine de
// dönmek zorunda.
func TestPublishNeverBlocks(t *testing.T) {
	b := New(4, 2)
	_, cancel, ok := b.Subscribe()
	if !ok {
		t.Fatal("abonelik açılmadı")
	}
	defer cancel()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 500; i++ {
			b.Publish(Event{Kind: AuthOK, User: "yigit"})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Publish bloklandı: yavaş bir abone üretici tarafı durduruyor")
	}

	// Düşen olaylar SAYILMALI: eksik bir akışa "tam" diye bakmak,
	// olmamış saymaktır.
	if got := b.Stats().Dropped; got == 0 {
		t.Error("tampon dolmasına rağmen düşen olay sayılmamış")
	}
}

func TestCancelStopsDeliveryAndIsIdempotent(t *testing.T) {
	b := New(4, 8)
	ch, cancel, _ := b.Subscribe()

	cancel()
	cancel() // ikinci çağrı panik etmemeli

	b.Publish(Event{Kind: AuthDenied})

	select {
	case e, open := <-ch:
		if open {
			t.Fatalf("abonelik kapatıldıktan sonra olay geldi: %+v", e)
		}
	default:
	}

	if got := b.Stats().Subscribers; got != 0 {
		t.Errorf("abone sayısı = %d, 0 bekleniyordu", got)
	}
}

func TestSubscribeRefusesBeyondCap(t *testing.T) {
	b := New(2, 4)
	_, c1, ok1 := b.Subscribe()
	_, c2, ok2 := b.Subscribe()
	defer c1()
	defer c2()
	if !ok1 || !ok2 {
		t.Fatal("ilk iki abonelik açılmalıydı")
	}

	// ⚠️ Sessizce boş bir kanal vermek YANLIŞ olurdu: panel "bağlıyım
	// ama hiç olay gelmiyor" derdi ve bu, "hiçbir şey olmuyor" ile
	// ayırt edilemezdi.
	if _, _, ok := b.Subscribe(); ok {
		t.Error("kapasite dolmuşken abonelik kabul edildi")
	}
}

// Yarış dedektörü altında koşacak: Publish ile Subscribe/cancel aynı
// anda çağrılıyor.
func TestConcurrentPublishAndSubscribe(t *testing.T) {
	b := New(16, 4)
	var wg sync.WaitGroup

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch, cancel, ok := b.Subscribe()
			if !ok {
				return
			}
			go func() {
				for range ch {
				}
			}()
			time.Sleep(time.Millisecond)
			cancel()
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				b.Publish(Event{Kind: SessionEnded})
			}
		}()
	}
	wg.Wait()
}
