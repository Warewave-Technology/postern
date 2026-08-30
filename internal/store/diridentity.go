package store

// Dizin kimliğinin postern hesabına bağlanması.
//
// ⚠️ Eşleştirmenin anahtarı KULLANICI ADI DEĞİL, dizinin verdiği
// kararlı ve opak değer (AD objectGUID / RFC 4530 entryUUID). Gerekçe
// göç 021'de ve ölçümü orada.

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/warewave/postern/internal/model"
)

// UserByDirSubject, dizin kimliğine bağlı kullanıcıyı döner.
// Bağlı hesap yoksa ErrNotFound.
func (s *Store) UserByDirSubject(ctx context.Context, subject string) (model.User, error) {
	if subject == "" {
		return model.User{}, fmt.Errorf("store.UserByDirSubject: %w", ErrNotFound)
	}
	var username string
	err := s.db.QueryRowContext(ctx,
		`SELECT username FROM users WHERE dir_subject = $1;`, subject).Scan(&username)
	if err != nil {
		return model.User{}, translateErr("store.UserByDirSubject", err)
	}
	return s.User(ctx, username)
}

/*
 * BindDirIdentity, bir postern hesabını bir dizin kimliğine bağlar.
 *
 * ⚠️ YALNIZCA HENÜZ BAĞLI DEĞİLSE (`dir_subject IS NULL`). Var olan bir
 * bağı sessizce değiştirmek, tam olarak önlenmeye çalışılan devralmayı
 * geri getirirdi — 011'in BindIdPSubject'teki aynı kuralı.
 *
 * Zaten başka bir kimliğe bağlıysa ErrConflict; başka bir HESAP o
 * kimliği tutuyorsa benzersiz indeks ihlali yine ErrConflict'e çevrilir.
 * İki durum da "buradan devam etme" demek.
 */
func (s *Store) BindDirIdentity(ctx context.Context, username, subject string) error {
	if subject == "" {
		return fmt.Errorf("store.BindDirIdentity[%s]: empty subject", username)
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE users SET dir_subject = $1
		WHERE username = $2 AND dir_subject IS NULL;`, subject, username)
	if err != nil {
		return translateErr("store.BindDirIdentity", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return translateErr("store.BindDirIdentity", err)
	}
	if n == 0 {
		return fmt.Errorf("store.BindDirIdentity[%s]: %w", username, ErrConflict)
	}
	return nil
}

// UnbindDirIdentity, bağı koparır.
//
// ⚠️ Kurtarma yolu ve var olması ŞART: dizinde silinip yeniden açılan
// bir kişi YENİ bir kimlik alır (ölçüldü) ve eski bağ onu kendi
// hesabından kilitler. Bunu çözecek bir komut olmazsa tek çıkış
// veritabanına elle girmek olurdu.
func (s *Store) UnbindDirIdentity(ctx context.Context, username string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET dir_subject = NULL WHERE username = $1;`, username)
	if err != nil {
		return translateErr("store.UnbindDirIdentity", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store.UnbindDirIdentity[%s]: %w", username, ErrNotFound)
	}
	return nil
}

// DirSubjectOf, hesabın bağlı olduğu dizin kimliğini döner; bağlı
// değilse boş dize.
func (s *Store) DirSubjectOf(ctx context.Context, username string) (string, error) {
	var subject sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT dir_subject FROM users WHERE username = $1;`, username).Scan(&subject)
	if err != nil {
		return "", translateErr("store.DirSubjectOf", err)
	}
	return subject.String, nil
}

/*
 * HasDirectoryIdentity, hesabın dizine BAĞLI olup olmadığı.
 *
 * ⚠️ freshen'ın doğru koşulu bu — `sso_only` DEĞİL. Ölçüldü: yetkisi
 * dizinden gelen bir yönetici (admin_via='group') demo veritabanında
 * sso_only=false ile duruyordu, yani dizine karşı hiç yeniden
 * sorulmuyordu. Dizinde kapatılsa bile anahtarıyla oturum açardı.
 */
func (s *Store) HasDirectoryIdentity(ctx context.Context, username string) (bool, error) {
	subject, err := s.DirSubjectOf(ctx, username)
	if err != nil {
		return false, err
	}
	return subject != "", nil
}
