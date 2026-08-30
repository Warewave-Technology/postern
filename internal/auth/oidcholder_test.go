package auth

import (
	"sync"
	"testing"
)

/*
 * ⚠️ AKIŞI BAŞLATAN KUŞAK, TAMAMLAYAN KUŞAKLA AYNI OLMAK ZORUNDA.
 *
 * Ayarlar akışın ortasında değişirse, A sağlayıcısının ürettiği code
 * B'nin token ucuna gönderilirdi — code VE istemci sırrı, operatörün az
 * önce yazdığı adrese giderdi. Kuşak numarası o akışı reddetmek için
 * var ve bu test onun gerçekten ilerlediğini gösteriyor.
 */
func TestHolderGenerationAdvancesOnEveryChange(t *testing.T) {
	h := NewOIDCHolder()

	if c, _ := h.Current(); c != nil {
		t.Fatal("boş tutucu istemci verdi")
	}
	if h.Live() || h.Configured() {
		t.Fatal("boş tutucu canlı ya da ayarlı göründü")
	}

	a := &OIDC{}
	h.Install(a)
	got, gen1 := h.Current()
	if got != a || !h.Live() || !h.Configured() {
		t.Fatalf("Install sonrası: %v %v %v", got == a, h.Live(), h.Configured())
	}

	// ⚠️ Clear KUŞAĞI İLERLETİYOR: ilerletmeseydi, düşürülmüş bir
	// sağlayıcıda başlamış akış yeni sağlayıcıda tamamlanabilirdi.
	h.Clear()
	if c, gen2 := h.Current(); c != nil || gen2 == gen1 {
		t.Fatalf("Clear sonrası istemci=%v kuşak=%d (önce %d)", c != nil, gen2, gen1)
	}

	// ⚠️ Ve VARLIK bilgisi Clear'dan ETKİLENMİYOR: "ayarlı ama
	// çalışmıyor", "hiç ayarlanmamış"tan farklı bir ekran hak ediyor.
	if !h.Configured() {
		t.Fatal("Clear, yapılandırmanın varlığını da sildi")
	}

	b := &OIDC{}
	h.Install(b)
	got, gen3 := h.Current()
	if got != b {
		t.Fatal("ikinci Install yerleşmedi")
	}
	if gen3 <= gen1 {
		t.Fatalf("kuşak geri gitti ya da durdu: %d → %d", gen1, gen3)
	}
}

// Eşzamanlı okuma/yazma yarışsız olmalı: -race altında koşuyor.
func TestHolderIsSafeUnderConcurrency(t *testing.T) {
	h := NewOIDCHolder()
	h.Install(&OIDC{})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				h.Current()
				h.Live()
				h.Configured()
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				h.Clear()
				h.Install(&OIDC{})
			}
		}()
	}
	wg.Wait()
}
