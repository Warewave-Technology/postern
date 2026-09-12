package store

// Donanım güvenlik anahtarlarının saklanması (göç 039).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"
)

/*
 * WebAuthnCredential, bir hesaba kayıtlı tek bir güvenlik anahtarı.
 *
 * ⚠️ TOTPCredential'DAN FARKI TEK CÜMLEDE: burada gizli bir şey yok.
 * TOTP sırrı paylaşılan bir sır ve JSON'a çıkmıyor (bkz. totp.go);
 * PublicKey ise çalınsa bile imza üretmiyor. Bu yüzden mühürlenmiyor,
 * ve mühürlenmemesi bir eksiklik değil — gereksiz yere mühürlemek
 * okuyana "bu değer gizli" diye yanlış bir şey öğretirdi.
 */
type WebAuthnCredential struct {
	// ID, ham kimlik bilgisi kimliğinin base64url hâli.
	ID string `json:"id"`

	PublicKey []byte `json:"-"`
	AAGUID    []byte `json:"-"`

	// SignCount, doğrulayıcının bildirdiği son sayaç.
	SignCount uint32 `json:"-"`

	// Name, kişinin verdiği ad: kayıp anahtarı silecek olan buna bakıyor.
	Name string `json:"name"`

	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at,omitzero"`
}

/*
 * UserIdentity, hesabın KARARLI kimliği.
 *
 * ⚠️ WebAuthn kaydı bu değere bağlanıyor, kullanıcı adına DEĞİL. Ad
 * yeniden kullanılabiliyor (user purge); anahtarın bağlandığı şey ad
 * olsaydı, silinip yeniden açılan bir hesap eski sahibinin
 * doğrulayıcısındaki kaydı devralırdı.
 */
func (s *Store) UserIdentity(ctx context.Context, username string) (string, error) {
	return s.userID(ctx, username)
}

// AddWebAuthnCredential, doğrulanmış bir anahtarı hesaba bağlar.
func (s *Store) AddWebAuthnCredential(ctx context.Context, username string, c WebAuthnCredential) error {
	userID, err := s.userID(ctx, username)
	if err != nil {
		return err
	}

	/*
	 * ⚠️ AYNI ANAHTAR İKİ HESABA BAĞLANAMAZ. id birincil anahtar;
	 * çakışma ErrConflict'e çevriliyor. Bir kimlik bilgisi kimliğinin
	 * iki kişiye ait olması, "bu imzayı kim attı" sorusunu
	 * cevapsız bırakırdı.
	 */
	/*
	 * ⚠️ nil DİLİM NULL YAZIYOR, VARSAYILANI KULLANMIYOR — ÖLÇÜLDÜ.
	 *
	 * Sütun NOT NULL ve varsayılanı boş; ama Go'nun nil []byte'ı
	 * sürücüye NULL olarak gidiyor ve varsayılan yalnızca sütun HİÇ
	 * verilmediğinde devreye giriyor. AAGUID bildirmeyen bir
	 * doğrulayıcı (platform anahtarlarının çoğu sıfır gönderiyor)
	 * kaydolurken 500 alıyordu. Boş dilim doğru gösterim: "üretici
	 * modeli bildirilmedi", "bilinmiyor" değil.
	 */
	if c.AAGUID == nil {
		c.AAGUID = []byte{}
	}
	if c.PublicKey == nil {
		c.PublicKey = []byte{}
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO webauthn_credentials
		       (id, user_id, public_key, aaguid, sign_count, name, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7);`,
		c.ID, userID, c.PublicKey, c.AAGUID, int64(c.SignCount), c.Name,
		time.Now().Unix())
	if err != nil {
		return translateErr("store.AddWebAuthnCredential", err)
	}

	return nil
}

// WebAuthnCredentials, hesabın anahtarlarını en eskiden yeniye döner.
func (s *Store) WebAuthnCredentials(ctx context.Context, username string) ([]WebAuthnCredential, error) {
	userID, err := s.userID(ctx, username)
	if err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, public_key, aaguid, sign_count, name, created_at, last_used_at
		FROM webauthn_credentials
		WHERE user_id = $1
		ORDER BY created_at, id;`, userID)
	if err != nil {
		return nil, translateErr("store.WebAuthnCredentials", err)
	}
	defer rows.Close()

	out := make([]WebAuthnCredential, 0)
	for rows.Next() {
		var c WebAuthnCredential
		var signCount, createdAt int64
		var lastUsed sql.NullInt64

		if err := rows.Scan(&c.ID, &c.PublicKey, &c.AAGUID, &signCount,
			&c.Name, &createdAt, &lastUsed); err != nil {
			return nil, translateErr("store.WebAuthnCredentials", err)
		}

		/*
		 * ⚠️ SÜTUN BIGINT, SAYAÇ uint32 — VE SARMA YÖNÜ KÖTÜ.
		 *
		 * Doğrulayıcı uint32 bildiriyor, dolayısıyla normal yoldan
		 * sınır aşılamıyor. Ama elle yazılmış ya da bozulmuş bir satır
		 * aşarsa, dönüştürme sessizce sarar ve saklanan sayı KÜÇÜLÜR:
		 * klon sezgisi tam da kurcalanmış bir satırda körelirdi.
		 * Sınıra sabitlemek her zaman güvenli yön — büyük bir sayı
		 * hiçbir imzayı kabul ettirmiyor, küçük bir sayı ettiriyor.
		 */
		switch {
		case signCount < 0:
			signCount = 0
		case signCount > math.MaxUint32:
			signCount = math.MaxUint32
		}
		c.SignCount = uint32(signCount)
		c.CreatedAt = time.Unix(createdAt, 0)
		// ⚠️ NULL "hiç kullanılmadı" demek, "1970'te kullanıldı" değil.
		if lastUsed.Valid {
			c.LastUsedAt = time.Unix(lastUsed.Int64, 0)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, translateErr("store.WebAuthnCredentials", err)
	}

	return out, nil
}

/*
 * TouchWebAuthnCredential, başarılı bir girişten sonra sayacı ve son
 * kullanım anını yazar.
 *
 * ⚠️ SAYAÇ GERİ GİTMİYOR. Doğrulayıcı sayacı artırmıyorsa (bazı platform
 * anahtarları hep 0 gönderiyor) yazdığımız değer 0 kalıyor; kontrolü
 * yapan taraf bunu bilerek atlıyor (bkz. httpapi/webauthn.go). Burada
 * küçülen bir sayıyı yazmak, klon sezgisini sessizce kapatırdı.
 */
func (s *Store) TouchWebAuthnCredential(ctx context.Context, id string, signCount uint32) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE webauthn_credentials
		SET sign_count = GREATEST(sign_count, $2), last_used_at = $3
		WHERE id = $1;`, id, int64(signCount), time.Now().Unix())
	if err != nil {
		return translateErr("store.TouchWebAuthnCredential", err)
	}

	n, err := res.RowsAffected()
	if err != nil {
		return translateErr("store.TouchWebAuthnCredential", err)
	}
	if n == 0 {
		return fmt.Errorf("store.TouchWebAuthnCredential: %w", ErrNotFound)
	}

	return nil
}

/*
 * DeleteWebAuthnCredential, bir anahtarı hesaptan kaldırır.
 *
 * ⚠️ SON ANAHTAR SİLİNİRKEN "yalnızca anahtar" KİLİDİ DE AÇILIYOR.
 * Aksi hâlde hesap, kabul edeceği hiçbir faktörü olmayan bir duruma
 * düşerdi: kod kapalı, anahtar yok. O durumdan çıkmanın tek yolu
 * yönetici olurdu ve kullanıcı bunu kendi eliyle, tek tıkla yapardı.
 */
func (s *Store) DeleteWebAuthnCredential(ctx context.Context, username, id string) error {
	userID, err := s.userID(ctx, username)
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return translateErr("store.DeleteWebAuthnCredential", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2;`, id, userID)
	if err != nil {
		return translateErr("store.DeleteWebAuthnCredential", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return translateErr("store.DeleteWebAuthnCredential", err)
	}
	if n == 0 {
		return fmt.Errorf("store.DeleteWebAuthnCredential: %w", ErrNotFound)
	}

	var left int
	if err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM webauthn_credentials WHERE user_id = $1;`,
		userID).Scan(&left); err != nil {
		return translateErr("store.DeleteWebAuthnCredential", err)
	}
	if left == 0 {
		if _, err := tx.ExecContext(ctx,
			`UPDATE users SET webauthn_only = FALSE WHERE id = $1;`, userID); err != nil {
			return translateErr("store.DeleteWebAuthnCredential", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return translateErr("store.DeleteWebAuthnCredential", err)
	}

	return nil
}

/*
 * SetWebAuthnOnly, hesabın kodu kabul edip etmeyeceğini belirler.
 *
 * ⚠️ ANAHTARSIZ AÇILAMIYOR. Açılsaydı hesabın kabul ettiği hiçbir ikinci
 * faktör kalmazdı ve kullanıcı kendini kilitlerdi — bu projede kurtarma
 * kodu bilerek yok, yani çıkış yolu yalnızca yönetici olurdu.
 */
func (s *Store) SetWebAuthnOnly(ctx context.Context, username string, only bool) error {
	userID, err := s.userID(ctx, username)
	if err != nil {
		return err
	}

	if only {
		var n int
		if err := s.db.QueryRowContext(ctx,
			`SELECT count(*) FROM webauthn_credentials WHERE user_id = $1;`,
			userID).Scan(&n); err != nil {
			return translateErr("store.SetWebAuthnOnly", err)
		}
		if n == 0 {
			return fmt.Errorf("store.SetWebAuthnOnly: %w: register a security key first",
				ErrConflict)
		}
	}

	if _, err := s.db.ExecContext(ctx,
		`UPDATE users SET webauthn_only = $2 WHERE id = $1;`, userID, only); err != nil {
		return translateErr("store.SetWebAuthnOnly", err)
	}

	return nil
}

// WebAuthnOnly, hesabın kodu reddedip reddetmediğini söyler.
func (s *Store) WebAuthnOnly(ctx context.Context, username string) (bool, error) {
	var only bool
	err := s.db.QueryRowContext(ctx,
		`SELECT webauthn_only FROM users WHERE username = $1;`, username).Scan(&only)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, fmt.Errorf("store.WebAuthnOnly: %w", ErrNotFound)
	case err != nil:
		return false, translateErr("store.WebAuthnOnly", err)
	}

	return only, nil
}

/*
 * ResetWebAuthn, hesabın bütün anahtarlarını siler ve kodu yeniden
 * kabul eder hâle getirir — yöneticinin acil çıkış yolu.
 *
 * ⚠️ TEK İŞLEMDE. İkisi ayrı olsaydı, aradaki bir hata hesabı tam da
 * kurtarmaya çalıştığımız duruma sokardı: anahtar yok, kod kapalı.
 */
func (s *Store) ResetWebAuthn(ctx context.Context, username string) (int, error) {
	userID, err := s.userID(ctx, username)
	if err != nil {
		return 0, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, translateErr("store.ResetWebAuthn", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`DELETE FROM webauthn_credentials WHERE user_id = $1;`, userID)
	if err != nil {
		return 0, translateErr("store.ResetWebAuthn", err)
	}
	removed, err := res.RowsAffected()
	if err != nil {
		return 0, translateErr("store.ResetWebAuthn", err)
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET webauthn_only = FALSE WHERE id = $1;`, userID); err != nil {
		return 0, translateErr("store.ResetWebAuthn", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, translateErr("store.ResetWebAuthn", err)
	}

	return int(removed), nil
}
