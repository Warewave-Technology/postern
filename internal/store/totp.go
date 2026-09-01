package store

// TOTP ikinci faktörünün saklanması (göç 028).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// TOTPCredential, bir hesabın ikinci faktörü.
type TOTPCredential struct {
	// ⚠️ Secret JSON'a ÇIKMIYOR. Bu değer kod üretmeye yeter; bir
	// listeleme ucundan sızması, ikinci faktörü ikinci faktör olmaktan
	// çıkarır. Yalnızca kayıt akışında, bir kez gösteriliyor.
	Secret string `json:"-"`

	Confirmed   bool      `json:"confirmed"`
	ConfirmedAt time.Time `json:"confirmed_at,omitzero"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsedAt  time.Time `json:"last_used_at,omitzero"`
}

/*
 * BeginTOTP, kayıt başlatır (ya da BAŞTAN başlatır).
 *
 * ⚠️ Doğrulanmış bir kaydın üzerine YAZMIYOR. Yazsaydı, oturumu çalınan
 * bir hesapta saldırgan kaydı sıfırlayıp kendi telefonunu bağlar ve
 * ikinci faktör sessizce el değiştirirdi. Doğrulanmış kaydı değiştirmek
 * ancak önce onu kapatmakla (DisableTOTP, kod ister) mümkün.
 */
func (s *Store) BeginTOTP(ctx context.Context, username, secret string) error {
	userID, err := s.userID(ctx, username)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO totp_credentials (user_id, secret, created_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id) DO UPDATE SET
		    secret     = EXCLUDED.secret,
		    created_at = EXCLUDED.created_at,
		    last_step  = -1
		WHERE totp_credentials.confirmed_at IS NULL;`,
		userID, secret, now)
	if err != nil {
		return translateErr("store.BeginTOTP", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store.BeginTOTP[%s]: already enrolled: %w", username, ErrConflict)
	}
	return nil
}

/*
 * ConfirmTOTP, kaydı DOĞRULANMIŞ işaretler.
 *
 * Yalnızca doğrulanmamış bir kayıt onaylanabilir: ikinci bir onay
 * çağrısı, kullanılmış bir adımı geri açmamalı.
 */
func (s *Store) ConfirmTOTP(ctx context.Context, username string, step int64) error {
	userID, err := s.userID(ctx, username)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	res, err := s.db.ExecContext(ctx, `
		UPDATE totp_credentials
		SET confirmed_at = $2, last_step = $3, last_used_at = $2
		WHERE user_id = $1 AND confirmed_at IS NULL;`, userID, now, step)
	if err != nil {
		return translateErr("store.ConfirmTOTP", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store.ConfirmTOTP[%s]: %w", username, ErrNotFound)
	}
	return nil
}

// TOTP, hesabın ikinci faktörünü döner. Yoksa ErrNotFound.
func (s *Store) TOTP(ctx context.Context, username string) (TOTPCredential, error) {
	var c TOTPCredential
	var confirmed, lastUsed sql.NullInt64
	var created int64
	err := s.db.QueryRowContext(ctx, `
		SELECT t.secret, t.confirmed_at, t.created_at, t.last_used_at
		FROM totp_credentials t
		JOIN users u ON u.id = t.user_id
		WHERE u.username = $1;`, username).
		Scan(&c.Secret, &confirmed, &created, &lastUsed)
	if err != nil {
		return TOTPCredential{}, translateErr("store.TOTP", err)
	}
	c.CreatedAt = time.Unix(created, 0).UTC()
	if confirmed.Valid {
		c.Confirmed = true
		c.ConfirmedAt = time.Unix(confirmed.Int64, 0).UTC()
	}
	if lastUsed.Valid {
		c.LastUsedAt = time.Unix(lastUsed.Int64, 0).UTC()
	}
	return c, nil
}

/*
 * UseTOTPStep, bir adımı TÜKETİR ve daha önce kullanılmışsa reddeder.
 *
 * ⚠️ TEK BİR İFADEDE KARŞILAŞTIR-VE-YAZ. Önce okuyup sonra yazan bir
 * uygulama, aynı kodla gönderilen İKİ eşzamanlı isteğin ikisini de
 * geçirirdi: her ikisi de eski değeri okur, her ikisi de kabul eder.
 * Tekrar korumasının bütün anlamı tam olarak o yarışı kapatmak.
 *
 * `last_step < $2` aynı zamanda pencere içindeki DAHA ESKİ adımları da
 * kapatıyor: adım N kullanıldıysa, hâlâ geçerli olan N-1 kodu da ölür.
 */
func (s *Store) UseTOTPStep(ctx context.Context, username string, step int64) error {
	userID, err := s.userID(ctx, username)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE totp_credentials
		SET last_step = $2, last_used_at = $3
		WHERE user_id = $1
		  AND confirmed_at IS NOT NULL
		  AND last_step < $2;`, userID, step, time.Now().Unix())
	if err != nil {
		return translateErr("store.UseTOTPStep", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store.UseTOTPStep[%s]: code already used: %w",
			username, ErrConflict)
	}
	return nil
}

// DisableTOTP, ikinci faktörü kaldırır.
func (s *Store) DisableTOTP(ctx context.Context, username string) error {
	userID, err := s.userID(ctx, username)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM totp_credentials WHERE user_id = $1;`, userID)
	if err != nil {
		return translateErr("store.DisableTOTP", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store.DisableTOTP[%s]: %w", username, ErrNotFound)
	}
	return nil
}

// userID, kullanıcı adını kimliğe çevirir.
func (s *Store) userID(ctx context.Context, username string) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM users WHERE username = $1;`, username).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("store: no such user %q: %w", username, ErrNotFound)
		}
		return "", translateErr("store.userID", err)
	}
	return id, nil
}
