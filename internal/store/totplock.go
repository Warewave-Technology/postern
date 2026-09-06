package store

// TOTP deneme sayacı ve kilit.

import (
	"context"
	"fmt"
	"time"
)

/*
 * TOTPLock, bir hesabın kod denemelerinin durumu.
 *
 * ⚠️ Failures, SON BAŞARILI GİRİŞTEN BU YANAKİ hatalar. Kümülatif değil:
 * kullanıcıya "son girişinizden beri N deneme" diye gösterilebilmesi için
 * başarıda sıfırlanıyor. Kümülatif bir sayı zamanla anlamsız büyür ve
 * "bugün bir şey oldu mu" sorusunu cevaplayamaz.
 */
type TOTPLock struct {
	Failures    int
	LockedUntil time.Time
}

// Locked, kilidin verilen anda geçerli olup olmadığı.
func (l TOTPLock) Locked(now time.Time) bool {
	return !l.LockedUntil.IsZero() && l.LockedUntil.After(now)
}

/*
 * TOTPLockState, sayaç ve kilidi okur.
 *
 * Doğrulayıcısı olmayan hesap ErrNotFound veriyor: kilit, doğrulayıcıya
 * ait bir şey.
 */
func (s *Store) TOTPLockState(ctx context.Context, username string) (TOTPLock, error) {
	var failures int
	var until int64
	err := s.db.QueryRowContext(ctx, `
		SELECT t.failures, t.locked_until
		FROM totp_credentials t
		JOIN users u ON u.id = t.user_id
		WHERE `+ciEq("u.username", "$1")+`;`, username).Scan(&failures, &until)
	if err != nil {
		return TOTPLock{}, translateErr("store.TOTPLockState", err)
	}

	return TOTPLock{Failures: failures, LockedUntil: unixOrZero(until)}, nil
}

/*
 * TOTPFailure, bir başarısız denemeyi sayar ve gerekiyorsa kilitler.
 *
 * ⚠️ SAYMA VE KİLİTLEME TEK İFADEDE. İki adıma bölseydik (oku, sonra yaz)
 * aynı anda gelen denemeler aynı sayıyı okuyup aynı değeri yazardı: eşik
 * hiç geçilmeyebilir ve kilit hiç kurulmayabilirdi. Saldırganın
 * yapabileceği en kolay şey paralel denemek.
 *
 * max <= 0 ise kilit kurulmuyor, yalnızca sayılıyor: operatör kilidi
 * kapatabilmeli ve kapattığında sayacı da kaybetmemeli.
 */
func (s *Store) TOTPFailure(ctx context.Context, username string, max int, lockFor time.Duration) (TOTPLock, error) {
	now := time.Now().Unix()
	lockAt := int64(0)
	if max > 0 {
		lockAt = now + int64(lockFor/time.Second)
	}

	var failures int
	var until int64
	err := s.db.QueryRowContext(ctx, `
		UPDATE totp_credentials
		SET failures = failures + 1,
		    locked_until = CASE
		      WHEN $2 > 0 AND failures + 1 >= $2 THEN $3
		      ELSE locked_until
		    END
		WHERE user_id = (SELECT id FROM users WHERE `+ciEq("username", "$1")+`)
		RETURNING failures, locked_until;`,
		username, max, lockAt).Scan(&failures, &until)
	if err != nil {
		return TOTPLock{}, translateErr("store.TOTPFailure", err)
	}

	return TOTPLock{Failures: failures, LockedUntil: unixOrZero(until)}, nil
}

/*
 * ClearTOTPFailures, sayacı sıfırlar ve ÖNCEKİ değeri döndürür.
 *
 * ⚠️ ÖNCEKİ DEĞER DÖNMEK ZORUNDA. Kullanıcıya "son girişinizden bu yana N
 * başarısız deneme oldu" diyebilmemizin tek yolu bu; ayrı bir okuma
 * yapsaydık araya giren bir deneme sayıyı değiştirebilirdi ve kullanıcıya
 * yanlış bir sayı gösterirdik.
 */
func (s *Store) ClearTOTPFailures(ctx context.Context, username string) (int, error) {
	/*
	 * ⚠️ ESKİ DEĞER CTE'DEN OKUNUYOR, RETURNING'DEN DEĞİL. RETURNING
	 * güncellenmiş satırı görüyor; oradan okunan sayı her zaman 0
	 * olurdu ve kullanıcıya hiçbir zaman "N deneme oldu" diyemezdik.
	 * FOR UPDATE, okuma ile yazma arasına başka bir denemenin
	 * girmesini engelliyor.
	 */
	var previous int
	err := s.db.QueryRowContext(ctx, `
		WITH before AS (
		  SELECT user_id, failures
		  FROM totp_credentials
		  WHERE user_id = (SELECT id FROM users WHERE `+ciEq("username", "$1")+`)
		  FOR UPDATE
		)
		UPDATE totp_credentials t
		SET failures = 0, locked_until = 0
		FROM before
		WHERE t.user_id = before.user_id
		RETURNING before.failures;`,
		username).Scan(&previous)
	if err != nil {
		return 0, translateErr("store.ClearTOTPFailures", err)
	}

	return previous, nil
}

/*
 * UnlockTOTP, kilidi yönetici eliyle kaldırır ve sayacı sıfırlar.
 *
 * ⚠️ SAYAÇ DA SIFIRLANIYOR. Yalnızca kilidi açmak, kullanıcının bir sonraki
 * hatasında anında yeniden kilitlenmesi demekti — yönetici müdahalesi
 * neredeyse hiçbir şey değiştirmezdi.
 */
func (s *Store) UnlockTOTP(ctx context.Context, username string) error {
	// #nosec G202 -- birleştirilen parça sabit (dialect.go); değer $1 ile gidiyor
	res, err := s.db.ExecContext(ctx, `
		UPDATE totp_credentials
		SET failures = 0, locked_until = 0
		WHERE user_id = (SELECT id FROM users WHERE `+ciEq("username", "$1")+`);`,
		username)
	if err != nil {
		return translateErr("store.UnlockTOTP", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store.UnlockTOTP: %w", ErrNotFound)
	}

	return nil
}

// unixOrZero, 0'ı "kilit yok" olarak sıfır zamana çeviriyor.
func unixOrZero(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}

	return time.Unix(v, 0)
}
