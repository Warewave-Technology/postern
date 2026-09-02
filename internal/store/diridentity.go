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
	"time"

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

// DirectoryAccount, dizinden kendiliğinden açılacak hesabın girdisi.
type DirectoryAccount struct {
	Username string
	Subject  string
	Groups   []string
}

/*
 * CreateFromDirectory, dizin kimliğinden hesap açar ve BAĞLAR.
 *
 * ⚠️ ROL EŞLEMESİ KAPIDA. Hiçbir grup bir role eşleşmiyorsa hesap
 * AÇILMIYOR (ErrAccessDenied). Bu, OIDC yolundaki ProvisionUser'ın
 * aynı sözleşmesi: "IdP'de hesabın olması postern'de hesabın olması
 * demek değil" kuralının otomatik açılıştaki karşılığı. Onsuz users
 * tablosu, hiçbir yere erişemeyen kayıtlarla dizinin kopyasına
 * dönüşürdü.
 *
 * ⚠️ Hesap ve bağ AYNI transaction'da: bağlanmamış bir hesap, adla
 * devralınabilir bir hesaptır.
 */
func (s *Store) CreateFromDirectory(ctx context.Context, acc DirectoryAccount) (model.User, error) {
	if acc.Subject == "" {
		return model.User{}, fmt.Errorf("store.CreateFromDirectory: empty subject")
	}
	if reservedOSUsers[acc.Username] {
		return model.User{}, fmt.Errorf(
			"store.CreateFromDirectory[%s]: refusing to auto-provision a reserved "+
				"system account name: %w", acc.Username, ErrAccessDenied)
	}

	roles, unmapped, err := s.RolesForGroups(ctx, model.ResolvedGroups(acc.Groups))
	if err != nil {
		return model.User{}, err
	}
	if len(unmapped) > 0 {
		if rerr := s.RecordUnmappedGroups(ctx, unmapped); rerr != nil {
			return model.User{}, rerr
		}
	}
	if len(roles) == 0 {
		return model.User{}, fmt.Errorf(
			"store.CreateFromDirectory[%s]: no group maps to a role: %w",
			acc.Username, ErrAccessDenied)
	}

	userID, err := newID()
	if err != nil {
		return model.User{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.User{}, translateErr("store.CreateFromDirectory", err)
	}
	defer tx.Rollback() //nolint:errcheck // commit sonrası no-op

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO users (id, username, os_user, created_at, dir_subject)
		VALUES ($1, $2, $2, $3, $4);`,
		userID, acc.Username, time.Now().Unix(), acc.Subject); err != nil {
		return model.User{}, translateErr("store.CreateFromDirectory", err)
	}
	if err := tx.Commit(); err != nil {
		return model.User{}, translateErr("store.CreateFromDirectory", err)
	}

	if serr := s.SyncRoles(ctx, acc.Username, roles); serr != nil {
		return model.User{}, serr
	}
	if lerr := s.LogAdmin(ctx, AdminLogEntry{
		Actor: "system", Via: "dir", Action: "user.auto_create", Entity: acc.Username,
		Details: "created from directory identity " + acc.Subject,
	}); lerr != nil {
		return model.User{}, lerr
	}
	return s.User(ctx, acc.Username)
}
