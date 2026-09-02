package store

import (
	"context"
	"testing"
	"time"
)

// queuedSession, arşiv kuyruğunda bekleyen bitmiş bir oturum kurar.
func queuedSession(t *testing.T, s *Store, id string) {
	t.Helper()
	ctx := context.Background()
	startFileSession(t, s, id)
	if err := s.SetRecordingPathForTest(ctx, id, "2026-09-03/"+id+".cast"); err != nil {
		t.Fatal(err)
	}
	if err := s.EndSession(ctx, id, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.QueueArchive(ctx, id); err != nil {
		t.Fatal(err)
	}
}

/*
 * ⚠️ BAŞARISIZ SATIR HER TURDA YENİDEN ALINMAMALI.
 *
 * Geri çekilme SABİTTİ: retryAfter geçtiği anda satır yeniden
 * üstleniliyordu. Arşivleyici hatanın kalıcı mı geçici mi olduğunu
 * zaten hesaplıyor (objstore.ErrTransient) ama sonucu yalnızca log
 * cümlesini seçmek için kullanıyordu — yanlış yazılmış bir kova adı,
 * düzeltilene kadar her turda yeniden denenip log'u dolduruyor ve
 * içindeki gerçek geçici arızayı görünmez yapıyordu.
 */
func TestArchiveRetryBacksOffWithAttempts(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	queuedSession(t, s, "sess-backoff")

	now := time.Now()
	const retryAfter = time.Minute

	// İlk deneme: hemen alınabilir.
	got, err := s.ClaimArchives(ctx, 10, now, time.Hour, retryAfter)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("ilk turda üstlenilen = %d, 1 bekleniyordu", len(got))
	}

	// Üç kez başarısız ol: attempts = 3, yani geri çekilme 8 dakika.
	for range 3 {
		if err := s.MarkArchiveFailed(ctx, "sess-backoff", "no such bucket", now); err != nil {
			t.Fatal(err)
		}
	}

	// retryAfter geçti ama üstel pencere geçmedi: alınmamalı.
	if got, err = s.ClaimArchives(ctx, 10, now.Add(2*time.Minute), time.Hour, retryAfter); err != nil {
		t.Fatal(err)
	} else if len(got) != 0 {
		t.Errorf("2 dakika sonra yeniden alındı: geri çekilme sabit kalmış (%d satır)", len(got))
	}

	// Pencere geçince yeniden alınabilmeli — kalıcı olarak
	// vazgeçmiyoruz, operatör kovayı düzeltince sıra ilerlesin.
	if got, err = s.ClaimArchives(ctx, 10, now.Add(20*time.Minute), time.Hour, retryAfter); err != nil {
		t.Fatal(err)
	} else if len(got) != 1 {
		t.Errorf("pencere geçtiği hâlde alınmadı: sıra kalıcı olarak tıkanmış (%d satır)", len(got))
	}
}
