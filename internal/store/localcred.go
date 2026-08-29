package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

/*
 * Yerel kimlik bilgisi kayıtları.
 *
 * ⚠️ SAKLANAN ŞEY DOĞRULAYICI, sırrın kendisi değil ve geri okunamaz.
 * Bu paket sırrı hiç görmez: üretimi ve doğrulaması internal/auth'ta.
 */

// ErrCredentialExists, hesabın zaten bir yerel kimlik bilgisi olduğunu
// söyler.
var ErrCredentialExists = errors.New("store: account already has a local credential")

/*
 * AddLocalCredential, hesaba yerel kimlik bilgisi bağlar.
 *
 * ⚠️ ÜSTÜNE YAZMAZ. Var olan bir kimlik bilgisini sessizce
 * değiştirmek, komutu ikinci kez çalıştıran operatörün ELİNDEKİ sırrı
 * geçersiz kılardı — üstelik o an ekranda yeni bir sır gördüğü için
 * bunu fark etmeden. Daha kötüsü: kurulumun tek yöneticisinin kimlik
 * bilgisini, yazma yetkisi olan herkes böylece döndürebilirdi.
 * Değiştirmek istiyorsa açık bir komut kullanır.
 */
func (s *Store) AddLocalCredential(ctx context.Context, username, verifier, by string) error {
	userID, err := s.rowID(ctx, "store.AddLocalCredential", "users", "username", username)
	if err != nil {
		return err
	}

	res, err := s.db.ExecContext(ctx, `
		INSERT INTO local_credentials (user_id, verifier, created_at, created_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id) DO NOTHING;`,
		userID, verifier, time.Now().Unix(), by)
	if err != nil {
		return translateErr("store.AddLocalCredential", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return translateErr("store.AddLocalCredential", err)
	}
	if n == 0 {
		return fmt.Errorf("store.AddLocalCredential[%s]: %w", username, ErrCredentialExists)
	}
	return nil
}

/*
 * UserByNameFold, adı HARF DUYARSIZ arar ve bulunan gerçek adı döner.
 *
 * ⚠️ postern'de kullanıcı adları harf DUYARLI ve bu doğru: "Ops" ile
 * "ops" meşru biçimde iki ayrı hesap olabilir. Bu sorgu o modeli
 * değiştirmiyor; yalnızca BOOTSTRAP'ın sorduğu farklı bir soruya cevap
 * veriyor.
 *
 * Oradaki tehlike somut: adı bir harf farkıyla yeniden yazan operatör,
 * ikinci bir yönetici ve İKİNCİ BİR CANLI SIR yaratır. İkisi de
 * çalışır, biri unutulur. Fark edilmesi zor, düzeltilmesi zor.
 *
 * İndeks yok — users.username ciColumns'ta değil. Sorun değil: bu
 * yalnızca kurulum anında, tek satır için çalışıyor.
 */
func (s *Store) UserByNameFold(ctx context.Context, name string) (string, error) {
	var found string
	err := s.db.QueryRowContext(ctx,
		`SELECT username FROM users WHERE lower(username) = lower($1);`, name).Scan(&found)
	if err != nil {
		return "", translateErr("store.UserByNameFold", err)
	}
	return found, nil
}

// LocalCredential, hesabın doğrulayıcısını döner. Yoksa ErrNotFound.
func (s *Store) LocalCredential(ctx context.Context, username string) (string, error) {
	var verifier string
	err := s.db.QueryRowContext(ctx, `
		SELECT c.verifier FROM local_credentials c
		JOIN users u ON u.id = c.user_id
		WHERE u.username = $1;`, username).Scan(&verifier)
	if err != nil {
		return "", translateErr("store.LocalCredential", err)
	}
	return verifier, nil
}

// TouchLocalCredential, son kullanım anını damgalar.
//
// Hatası girişi DÜŞÜRMEZ: çağıran loglar. Kullanım damgası bir teşhis
// bilgisi ve onun yazılamaması, kimliği doğrulanmış bir kullanıcıyı
// dışarıda bırakmak için sebep değil.
func (s *Store) TouchLocalCredential(ctx context.Context, username string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE local_credentials SET last_used_at = $1
		WHERE user_id = (SELECT id FROM users WHERE username = $2);`, at.Unix(), username)
	if err != nil {
		return translateErr("store.TouchLocalCredential", err)
	}
	return nil
}

// RemoveLocalCredential, kimlik bilgisini siler. Hesap kalır.
func (s *Store) RemoveLocalCredential(ctx context.Context, username string) error {
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM local_credentials
		WHERE user_id = (SELECT id FROM users WHERE username = $1);`, username)
	if err != nil {
		return translateErr("store.RemoveLocalCredential", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return translateErr("store.RemoveLocalCredential", err)
	}
	if n == 0 {
		return fmt.Errorf("store.RemoveLocalCredential[%s]: %w", username, ErrNotFound)
	}
	return nil
}

/*
 * FirstKeyAdded, hesabın ilk anahtarını EKLEMİŞ olup olmadığı.
 *
 * ⚠️ SAYIYA DEĞİL DAMGAYA BAKIYOR. "Şu an anahtarı var mı" diye sorsaydık
 * sil-ve-ekle kuralı tamamen atlardı: oturumu ele geçiren kişi mevcut
 * anahtarı siler, sayaç sıfırlanır, yeni anahtarı bedavaya ekler. Damga
 * bir kez konuyor ve bir daha kalkmıyor.
 */
func (s *Store) FirstKeyAdded(ctx context.Context, username string) (bool, error) {
	var at sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT first_key_added_at FROM users WHERE username = $1;`, username).Scan(&at)
	if err != nil {
		return false, translateErr("store.FirstKeyAdded", err)
	}
	return at.Valid, nil
}

// MarkFirstKeyAdded, damgayı koyar. Zaten varsa DOKUNMAZ — ilk anahtarın
// anı, sonradan eklenenlerle kaymamalı.
func (s *Store) MarkFirstKeyAdded(ctx context.Context, username string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users SET first_key_added_at = COALESCE(first_key_added_at, $1)
		WHERE username = $2;`, at.Unix(), username)
	if err != nil {
		return translateErr("store.MarkFirstKeyAdded", err)
	}
	return nil
}

// LocalCredentialHolder, yerel kimlik bilgisi olan bir hesabın özeti.
type LocalCredentialHolder struct {
	Username   string
	IsAdmin    bool
	CreatedAt  time.Time
	CreatedBy  string
	LastUsedAt time.Time
}

/*
 * LocalCredentialHolders, yerel kimlik bilgisi olan hesapları döner.
 *
 * ⚠️ GÖRÜNÜRLÜK BİR GÜVENLİK ÖZELLİĞİ. Bu hesaplar bir acil durum
 * kapısı ve kullanılmayan bir acil durum kapısı unutulmuş bir kapıdır.
 * Operatörün "kimlerde var, en son ne zaman kullanıldı" sorusunu
 * veritabanına girmeden cevaplayabilmesi gerekiyor.
 */
func (s *Store) LocalCredentialHolders(ctx context.Context) ([]LocalCredentialHolder, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT u.username, u.is_admin, c.created_at, c.created_by, c.last_used_at
		FROM local_credentials c
		JOIN users u ON u.id = c.user_id
		ORDER BY u.username;`)
	if err != nil {
		return nil, translateErr("store.LocalCredentialHolders", err)
	}
	defer rows.Close()

	var out []LocalCredentialHolder
	for rows.Next() {
		var h LocalCredentialHolder
		var created int64
		var last sql.NullInt64
		if err := rows.Scan(&h.Username, &h.IsAdmin, &created, &h.CreatedBy, &last); err != nil {
			return nil, translateErr("store.LocalCredentialHolders", err)
		}
		h.CreatedAt = time.Unix(created, 0).UTC()
		if last.Valid {
			h.LastUsedAt = time.Unix(last.Int64, 0).UTC()
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, translateErr("store.LocalCredentialHolders", err)
	}
	return out, nil
}
