package store

import (
	"testing"
	"time"
)

/*
 * ⚠️ DAMGA YALNIZCA İLERİ GİDİYOR.
 *
 * İki sekme açık bir yöneticide eski bir istek sonra varabiliyor;
 * damgayı geri almak, o kişinin çoktan gördüğü işleri yeniden "yeni"
 * göstermek olurdu ve rozet güvenilirliğini kaybederdi.
 */
func TestTheReadStampOnlyMovesForward(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	if _, err := s.CreateUser(ctx, "ayse", "", "ayse"); err != nil {
		t.Fatal(err)
	}

	later := time.Unix(1_700_000_000, 0)
	if err := s.MarkNotificationsRead(ctx, "ayse", later); err != nil {
		t.Fatal(err)
	}
	// Geciken eski istek.
	if err := s.MarkNotificationsRead(ctx, "ayse", later.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	got, err := s.NotificationsReadAt(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(later) {
		t.Fatalf("damga geri alındı: %v, %v bekleniyordu", got, later)
	}
}

/*
 * ⚠️ "HİÇ BAKMADIM" HATA DEĞİL, SIFIR ZAMAN. ErrNotFound döndürmek her
 * çağıranı aynı dalı yazmaya zorlardı — ve unutan çağıran, yeni bir
 * yöneticinin rozetini hiç göstermezdi.
 */
func TestNeverHavingLookedIsNotAnError(t *testing.T) {
	s := newTestStore(t)
	got, err := s.NotificationsReadAt(t.Context(), "kimse")
	if err != nil {
		t.Fatalf("hiç bakmamış kişi hata verdi: %v", err)
	}
	if !got.IsZero() {
		t.Fatalf("damga = %v, sıfır bekleniyordu", got)
	}
}
