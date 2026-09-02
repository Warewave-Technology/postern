package store

import (
	"context"
	"errors"
	"testing"
)

/*
 * ⚠️ İKİ SAYACIN DA AYNI CÜMLEYE ÇIKTIĞI.
 *
 * Sunucu tarafı sınır 57014 üretiyor (TestSearchStopsAtTheServerSideTimeout
 * onu gerçek bir sorguyla ölçüyor). İstemci tarafı süre ise ölçüldü:
 * SQLSTATE'siz, düz "context deadline exceeded". İkincisi elenmezse
 * veritabanına giden bağlantı takıldığında operatör "internal error"
 * görür — oysa olan şey aynı: arama bitmedi.
 */
func TestBothTimeoutsReadAsTooSlow(t *testing.T) {
	if err := translateSearchErr("x", context.DeadlineExceeded); !errors.Is(err, ErrTooSlow) {
		t.Errorf("istemci tarafı süre ErrTooSlow'a çevrilmedi: %v", err)
	}
	// ⚠️ İSTEMCİNİN GİTMESİ AYRI: sekmesini kapatana "aramanız fazla
	// uzun sürdü" demek yanlış olurdu ve kimse de okumuyor.
	if err := translateSearchErr("x", context.Canceled); errors.Is(err, ErrTooSlow) {
		t.Error("istemcinin bağlantıyı kesmesi 'çok yavaş' diye raporlandı")
	}
}
