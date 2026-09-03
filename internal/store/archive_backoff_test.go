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
		if err := s.MarkArchiveFailed(ctx, "sess-backoff", "no such bucket", false, now); err != nil {
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

/*
 * ⚠️ KALICI HATA, SATIRI KUYRUKTAN ÇIKARMALI.
 *
 * ÖLÇÜLEN ARIZA: kaydı diskte olmayan bir satır (dosyası budanmış ya da
 * elle silinmiş) her turda yeniden claim ediliyordu. attempts sonsuza
 * kadar artıyor, ArchiveBacklog onu "bekliyor" sayıyor ve bir gün sonra
 * "disk dolacak" alarmı KALICI olarak yanıyordu — oysa o kayıt için
 * yapılabilecek bir şey yok.
 *
 * Arşivleyici geçici/kalıcı ayrımını zaten hesaplıyordu; artık satıra
 * da yazılıyor (permanent). Bu test kalıcı işaretlenen satırın bir daha
 * claim edilmediğini ve "bekliyor" değil "kayıp" sayıldığını ölçüyor.
 */
func TestPermanentFailureLeavesTheQueue(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	queuedSession(t, s, "sess-gone")

	now := time.Now()
	const retryAfter = time.Minute

	got, err := s.ClaimArchives(ctx, 10, now, time.Hour, retryAfter)
	if err != nil || len(got) != 1 {
		t.Fatalf("ilk claim = %d, %v", len(got), err)
	}

	// Dosya kayıp: KALICI hata.
	if err := s.MarkArchiveFailed(ctx, "sess-gone", "recording file is gone", true, now); err != nil {
		t.Fatal(err)
	}

	// ⚠️ ASIL İDDİA: geri çekilme süresi geçse bile bir daha
	// üstlenilmemeli.
	later := now.Add(24 * time.Hour)
	if again, err := s.ClaimArchives(ctx, 10, later, time.Hour, retryAfter); err != nil {
		t.Fatal(err)
	} else if len(again) != 0 {
		t.Errorf("kalıcı hatalı satır yeniden üstlenildi (%d) — kuyruk hiç "+
			"bitmez ve 'disk dolacak' alarmı sönmez", len(again))
	}

	// Ve "bekliyor" değil "kayıp" sayılmalı.
	b, err := s.ArchiveBacklog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if b.Pending != 0 {
		t.Errorf("Pending = %d, 0 bekleniyordu — kayıp kayıt hâlâ 'bekliyor' sayılıyor", b.Pending)
	}
	if b.Lost != 1 {
		t.Errorf("Lost = %d, 1 bekleniyordu", b.Lost)
	}
	if !b.Oldest.IsZero() {
		t.Errorf("Oldest kayıp satırdan hesaplandı: %v — 'disk dolacak' yaşı bundan çıkıyordu", b.Oldest)
	}
}

/*
 * ⚠️ DÜZELTİLEBİLİR BİR HATA KUYRUKTAN ÇIKARILMAMALI.
 *
 * `permanent`, "hiçbir koşulda yüklenemez" demek — dosyanın kaybolması
 * gibi. Yapılandırma ve yetki hataları (403 yanlış kimlik, 404 yanlış
 * kova adı) BUNA GİRMİYOR: operatör onları düzeltiyor ve düzeltince
 * kuyruk kendiliğinden boşalmalı. CHANGELOG'un sözü de bu: "hiçbir şey
 * kalıcı ölü işaretlenmiyor, kovayı düzeltmek kuyruğu boşaltıyor".
 *
 * Bu test o sözü koruyor: kalıcı OLMAYAN bir hatadan sonra satır, geri
 * çekilme süresi geçince yeniden üstlenilebilmeli.
 */
func TestRecoverableFailureStaysInTheQueue(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	queuedSession(t, s, "sess-403")

	now := time.Now()
	const retryAfter = time.Minute

	if got, err := s.ClaimArchives(ctx, 10, now, time.Hour, retryAfter); err != nil || len(got) != 1 {
		t.Fatalf("ilk claim = %d, %v", len(got), err)
	}

	// Yanlış kimlik / yanlış kova: kalıcı DEĞİL, düzeltilebilir.
	if err := s.MarkArchiveFailed(ctx, "sess-403",
		"AccessDenied (403)", false, now); err != nil {
		t.Fatal(err)
	}

	// Geri çekilme geçtikten sonra YENİDEN üstlenilmeli.
	later := now.Add(24 * time.Hour)
	again, err := s.ClaimArchives(ctx, 10, later, time.Hour, retryAfter)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 1 {
		t.Errorf("düzeltilebilir hatadan sonra satır yeniden üstlenilmedi (%d) — "+
			"operatör kimliği düzeltse bile kuyruk boşalmaz", len(again))
	}

	b, err := s.ArchiveBacklog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if b.Lost != 0 {
		t.Errorf("Lost = %d, 0 bekleniyordu — düzeltilebilir hata 'kayıp' sayıldı", b.Lost)
	}
	if b.Pending != 1 {
		t.Errorf("Pending = %d, 1 bekleniyordu", b.Pending)
	}
}
