package store

/*
 * Bildirimlerin "en son ne zaman bakıldı" damgası.
 *
 * ⚠️ BİLDİRİM TABLOSU DEĞİL. Liste hâlâ her çağrıda durumdan türetiliyor
 * (httpapi/notifications.go): işi yapılan satır kayboluyor, dolayısıyla
 * bayatlayacak bir kayıt yok. Burada duran tek şey kişinin son bakış anı;
 * ondan SONRA beklemeye başlayan her şey o kişi için yeni.
 */

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

/*
 * NotificationsReadAt, kişinin bildirimlere en son baktığı an. Hiç
 * bakmamışsa sıfır zaman.
 *
 * ⚠️ "HİÇ BAKMADIM" HATA DEĞİL. Yokluğu ErrNotFound olarak döndürmek,
 * her çağıranı aynı dalı yazmaya zorlardı — ve unutan çağıran, yeni bir
 * yöneticinin rozetini hiç göstermezdi.
 */
func (s *Store) NotificationsReadAt(ctx context.Context, username string) (time.Time, error) {
	var at int64
	err := s.db.QueryRowContext(ctx,
		`SELECT read_at FROM notification_reads WHERE username = $1;`, username).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, translateErr("store.NotificationsReadAt", err)
	}

	return time.Unix(at, 0), nil
}

/*
 * MarkNotificationsRead, kişinin bakış damgasını ileri alır.
 *
 * ⚠️ YALNIZCA İLERİ. İki sekme açık bir yöneticide eski bir istek sonra
 * varabiliyor; damgayı geri almak, o kişinin çoktan gördüğü işleri
 * yeniden "yeni" göstermek olurdu ve rozet güvenilirliğini kaybederdi.
 */
func (s *Store) MarkNotificationsRead(ctx context.Context, username string, at time.Time) error {
	const op = "store.MarkNotificationsRead"
	if err := refuseBadUsername(op, username); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO notification_reads (username, read_at)
		VALUES ($1, $2)
		ON CONFLICT (username) DO UPDATE SET read_at = GREATEST(notification_reads.read_at, EXCLUDED.read_at);`,
		username, at.Unix())

	return translateErr(op, err)
}
