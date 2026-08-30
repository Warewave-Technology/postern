package store

// Onay kuyruğu: hesap açılışı otomatik değilken, kimliği doğrulanan
// ama postern hesabı olmayan kişiler.
//
// ⚠️ Anahtar KARARLI KİMLİK, kullanıcı adı değil — gerekçesi göç 022'de.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Pending durumları.
const (
	PendingWaiting  = "waiting"
	PendingRejected = "rejected"
)

// PendingUser, onay bekleyen (ya da reddedilmiş) bir kimlik.
type PendingUser struct {
	ID      string `json:"id"`
	Subject string `json:"subject"`
	Source  string `json:"source"`

	// ⚠️ Username, Email ve SeenGroups YALNIZCA GÖSTERİM. Hiçbir karar
	// bunlara bakmıyor: üçü de kaynakta değişebiliyor.
	Username   string   `json:"username"`
	Email      string   `json:"email"`
	SeenGroups []string `json:"seen_groups"`

	State     string    `json:"state"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	DecidedBy string    `json:"decided_by,omitempty"`
	DecidedAt time.Time `json:"decided_at,omitzero"`
	Reason    string    `json:"reason,omitempty"`
}

/*
 * RecordPending, bir başvuruyu kaydeder ve GÜNCEL durumu döner.
 *
 * ⚠️ RED YAPIŞKAN. Reddedilmiş bir kimlik yeniden giriş denediğinde
 * satır 'waiting'e DÖNMÜYOR; yalnızca last_seen ilerliyor. Dönseydi,
 * reddedilen kişi tekrar tekrar deneyerek kuyruğu doldurur ve
 * yöneticiyi aynı kararı vermeye zorlardı.
 *
 * ⚠️ Ad DEĞİŞSE de aynı satır: anahtar kimlik. Adla anahtarlanan bir
 * kuyrukta reddedilen kişi dizinde adını değiştirip yeniden
 * başvurabilirdi.
 */
func (s *Store) RecordPending(ctx context.Context, p PendingUser) (string, error) {
	if strings.TrimSpace(p.Subject) == "" {
		return "", fmt.Errorf("store.RecordPending: empty subject")
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	now := time.Now().Unix()

	var state string
	err = s.db.QueryRowContext(ctx, `
		INSERT INTO pending_users
		    (id, subject, source, username, email, seen_groups, state, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, 'waiting', $7, $7)
		ON CONFLICT (subject) DO UPDATE SET
		    username    = EXCLUDED.username,
		    email       = EXCLUDED.email,
		    seen_groups = EXCLUDED.seen_groups,
		    last_seen   = EXCLUDED.last_seen
		RETURNING state;`,
		id, p.Subject, p.Source, p.Username, p.Email,
		strings.Join(p.SeenGroups, ","), now).Scan(&state)
	if err != nil {
		return "", translateErr("store.RecordPending", err)
	}
	return state, nil
}

// ListPending, kuyruğu döner (bekleyenler önce, en yeni başta).
func (s *Store) ListPending(ctx context.Context) ([]PendingUser, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, subject, source, username, email, seen_groups, state,
		       first_seen, last_seen, decided_by, decided_at, reason
		FROM pending_users
		ORDER BY (state = 'waiting') DESC, last_seen DESC;`)
	if err != nil {
		return nil, translateErr("store.ListPending", err)
	}
	defer rows.Close()

	out := make([]PendingUser, 0)
	for rows.Next() {
		var p PendingUser
		var groups string
		var first, last int64
		var decided sql.NullInt64
		if err := rows.Scan(&p.ID, &p.Subject, &p.Source, &p.Username, &p.Email,
			&groups, &p.State, &first, &last, &p.DecidedBy, &decided, &p.Reason); err != nil {
			return nil, translateErr("store.ListPending", err)
		}
		if groups != "" {
			p.SeenGroups = strings.Split(groups, ",")
		} else {
			p.SeenGroups = []string{}
		}
		p.FirstSeen = time.Unix(first, 0).UTC()
		p.LastSeen = time.Unix(last, 0).UTC()
		if decided.Valid {
			p.DecidedAt = time.Unix(decided.Int64, 0).UTC()
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, translateErr("store.ListPending", err)
	}
	return out, nil
}

// PendingByID, tek satır.
func (s *Store) PendingByID(ctx context.Context, id string) (PendingUser, error) {
	all, err := s.ListPending(ctx)
	if err != nil {
		return PendingUser{}, err
	}
	for _, p := range all {
		if p.ID == id {
			return p, nil
		}
	}
	return PendingUser{}, fmt.Errorf("store.PendingByID[%s]: %w", id, ErrNotFound)
}

/*
 * ApprovePending, hesabı AÇAR ve kimliği bağlar.
 *
 * ⚠️ ROL VERMİYOR. Roller kişinin bir sonraki girişinde CANLI kaynaktan
 * çözülüyor; kuyruktaki grup listesi onay ekranında ne görüldüğünü
 * gösteriyor, bir yetki kaydı değil. Bayat bir fotoğrafa göre rol
 * yazmak, yetkiyi geçmişe bağlamak olurdu.
 *
 * Hesap ve bağ AYNI transaction'da: arada kalan bir hata, kimliği
 * bağlanmamış bir hesap bırakır ve o hesap sonra ADLA devralınabilir
 * hâle gelirdi.
 */
func (s *Store) ApprovePending(ctx context.Context, id, osUser, by string) (PendingUser, error) {
	p, err := s.PendingByID(ctx, id)
	if err != nil {
		return PendingUser{}, err
	}
	if p.State == PendingRejected {
		return PendingUser{}, fmt.Errorf("store.ApprovePending[%s]: already rejected: %w", id, ErrConflict)
	}
	if reservedOSUsers[p.Username] {
		return PendingUser{}, fmt.Errorf(
			"store.ApprovePending[%s]: %q is a reserved system account name: %w",
			id, p.Username, ErrAccessDenied)
	}
	if osUser == "" {
		osUser = p.Username
	}

	userID, err := newID()
	if err != nil {
		return PendingUser{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PendingUser{}, translateErr("store.ApprovePending", err)
	}
	defer tx.Rollback() //nolint:errcheck // commit sonrası no-op

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO users (id, username, email, os_user, created_at)
		VALUES ($1, $2, $3, $4, $5);`,
		userID, p.Username, sql.NullString{String: p.Email, Valid: p.Email != ""},
		osUser, time.Now().Unix()); err != nil {
		return PendingUser{}, translateErr("store.ApprovePending", err)
	}

	// Kimlik AYNI işlemde bağlanıyor: bağlanmamış bir hesap, adla
	// devralınabilir bir hesaptır.
	col := "dir_subject"
	if p.Source == "oidc" {
		col = "idp_subject"
	}
	// #nosec G202 -- col sabit bir kümeden geliyor (yukarıdaki iki değer)
	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET `+col+` = $1 WHERE id = $2;`, p.Subject, userID); err != nil {
		return PendingUser{}, translateErr("store.ApprovePending", err)
	}

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM pending_users WHERE id = $1;`, id); err != nil {
		return PendingUser{}, translateErr("store.ApprovePending", err)
	}

	if err := tx.Commit(); err != nil {
		return PendingUser{}, translateErr("store.ApprovePending", err)
	}
	return p, nil
}

/*
 * RejectPending, başvuruyu reddeder ve SATIRI BIRAKIR.
 *
 * ⚠️ Silinmiyor: silinseydi aynı kişi bir sonraki girişinde yeniden
 * 'waiting' olarak belirir ve red hiçbir şey ifade etmezdi. Sebep de
 * saklanıyor — aynı kararı ikinci kez veren yönetici, ilkinin niye
 * verildiğini görmeli.
 */
func (s *Store) RejectPending(ctx context.Context, id, reason, by string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE pending_users
		SET state = 'rejected', reason = $1, decided_by = $2, decided_at = $3
		WHERE id = $4;`, reason, by, time.Now().Unix(), id)
	if err != nil {
		return translateErr("store.RejectPending", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store.RejectPending[%s]: %w", id, ErrNotFound)
	}
	return nil
}

// ForgetPending, satırı tamamen siler — reddi geri almanın yolu.
//
// Var olması şart: yanlışlıkla reddedilen biri, aksi hâlde bir daha
// hiç başvuramazdı.
func (s *Store) ForgetPending(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM pending_users WHERE id = $1;`, id)
	if err != nil {
		return translateErr("store.ForgetPending", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store.ForgetPending[%s]: %w", id, ErrNotFound)
	}
	return nil
}

// PendingWaitingCount, bekleyen başvuru sayısı — panelde rozet için.
func (s *Store) PendingWaitingCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM pending_users WHERE state = 'waiting';`).Scan(&n)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, translateErr("store.PendingWaitingCount", err)
	}
	return n, nil
}
