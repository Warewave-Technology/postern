package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Dizin senkronizasyonunun veritabanı tarafı (göç 010).

// SyncCandidate, senkronizasyonun bakacağı bir kullanıcı.
type SyncCandidate struct {
	Username string
	Email    string

	// MissingSince sıfırsa kullanıcı en son bakıldığında dizinde vardı.
	MissingSince time.Time

	SSORoles    int
	ManualRoles int
}

// SyncCandidates, senkronizasyona TABİ kullanıcıları döner.
//
// ⚠️ YALNIZCA sso_only = TRUE. Bu kapsam daraltması özelliğin servis
// hesapları (otomasyon, CI) için güvenli olmasının tek sebebi: onların
// IdP'de karşılığı yok ve dizinde "bulunamamaları" normal. Göç 008 tam
// olarak bu ayrımı yapmak için var.
func (s *Store) SyncCandidates(ctx context.Context) ([]SyncCandidate, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT u.username,
		       COALESCE(u.email, ''),
		       u.dir_missing_since,
		       COUNT(*) FILTER (WHERE ur.source = 'sso')    AS sso_roles,
		       COUNT(*) FILTER (WHERE ur.source = 'manual') AS manual_roles
		FROM users u
		LEFT JOIN user_roles ur ON ur.user_id = u.id
		WHERE u.sso_only = TRUE
		GROUP BY u.username, u.email, u.dir_missing_since
		ORDER BY u.username;`)
	if err != nil {
		return nil, translateErr("store.SyncCandidates", err)
	}
	defer rows.Close()

	var out []SyncCandidate
	for rows.Next() {
		var c SyncCandidate
		var missing sql.NullInt64
		if err := rows.Scan(&c.Username, &c.Email, &missing, &c.SSORoles, &c.ManualRoles); err != nil {
			return nil, translateErr("store.SyncCandidates", err)
		}
		if missing.Valid {
			c.MissingSince = time.Unix(missing.Int64, 0)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, translateErr("store.SyncCandidates", err)
	}
	return out, nil
}

// MarkDirectorySeen, kullanıcının dizinde bulunduğunu kaydeder ve
// kayıp saatini SIFIRLAR.
func (s *Store) MarkDirectorySeen(ctx context.Context, username string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users SET dir_last_seen_at = $1, dir_missing_since = NULL
		WHERE username = $2;`, at.Unix(), username)
	if err != nil {
		return translateErr("store.MarkDirectorySeen", err)
	}
	return nil
}

// MarkDirectoryMissing, kullanıcının bulunamadığını kaydeder.
//
// COALESCE: kayıp saati YALNIZCA henüz kurulmamışsa kuruluyor. Her
// koşuda üzerine yazmak, grace penceresini gerçek bir saat olmaktan
// çıkarıp hiç dolmayan bir sayaca çevirirdi.
func (s *Store) MarkDirectoryMissing(ctx context.Context, username string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users SET dir_missing_since = COALESCE(dir_missing_since, $1)
		WHERE username = $2;`, at.Unix(), username)
	if err != nil {
		return translateErr("store.MarkDirectoryMissing", err)
	}
	return nil
}

// SyncRun, bir senkronizasyon koşusunun kaydı.
type SyncRun struct {
	ID         int64
	StartedAt  time.Time
	FinishedAt time.Time
	Source     string
	Trigger    string
	Outcome    string
	Reason     string

	Considered   int
	Present      int
	Absent       int
	Unknown      int
	Revoked      int
	RolesChanged int

	DryRun bool
}

// StartSyncRun, koşuyu açar ve id'sini döner.
func (s *Store) StartSyncRun(ctx context.Context, source, trigger string, dryRun bool) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO sync_runs (started_at, source, trigger, outcome, dry_run)
		VALUES ($1, $2, $3, 'failed', $4)
		RETURNING id;`, time.Now().Unix(), source, trigger, dryRun).Scan(&id)
	if err != nil {
		return 0, translateErr("store.StartSyncRun", err)
	}
	return id, nil
}

// FinishSyncRun, koşuyu sonuçlandırır.
//
// Satır 'failed' olarak AÇILIYOR ve burada güncelleniyor: süreç
// ortasında ölürse kayıt "başarılı" değil "başarısız" kalır — sessizce
// başarılı görünen bir yarım koşu, olmayan bir senkronizasyona
// güvenilmesi demek olurdu.
func (s *Store) FinishSyncRun(ctx context.Context, run SyncRun) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE sync_runs SET
			finished_at = $1, outcome = $2, reason = $3,
			users_considered = $4, users_present = $5, users_absent = $6,
			users_unknown = $7, users_revoked = $8, roles_changed = $9
		WHERE id = $10;`,
		time.Now().Unix(), run.Outcome, run.Reason,
		run.Considered, run.Present, run.Absent,
		run.Unknown, run.Revoked, run.RolesChanged, run.ID)
	if err != nil {
		return translateErr("store.FinishSyncRun", err)
	}
	return nil
}

// SyncRuns, son koşuları yeniden eskiye döner.
func (s *Store) SyncRuns(ctx context.Context, limit int) ([]SyncRun, error) {
	// #nosec G202 -- birleştirilen parça sabit (dialect.go); değerler $N ile gidiyor
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, started_at, finished_at, source, trigger, outcome, reason,
		       users_considered, users_present, users_absent,
		       users_unknown, users_revoked, roles_changed, dry_run
		FROM sync_runs
		ORDER BY started_at DESC, id DESC`+limitClause(limit, "$1")+`;`,
		limitArgs(limit)...)
	if err != nil {
		return nil, translateErr("store.SyncRuns", err)
	}
	defer rows.Close()

	out := make([]SyncRun, 0)
	for rows.Next() {
		var r SyncRun
		var started int64
		var finished sql.NullInt64
		if err := rows.Scan(&r.ID, &started, &finished, &r.Source, &r.Trigger,
			&r.Outcome, &r.Reason, &r.Considered, &r.Present, &r.Absent,
			&r.Unknown, &r.Revoked, &r.RolesChanged, &r.DryRun); err != nil {
			return nil, translateErr("store.SyncRuns", err)
		}
		r.StartedAt = time.Unix(started, 0)
		if finished.Valid {
			r.FinishedAt = time.Unix(finished.Int64, 0)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, translateErr("store.SyncRuns", err)
	}
	return out, nil
}

// TryLockSync, senkronizasyon kilidini DENEYEREK alır.
//
// İki postern süreci aynı veritabanına bakıyorsa ikisi de
// senkronize eder ve patlama yarıçapı sayaçlarını BAĞIMSIZ hesaplar —
// yani tavanlar ikiye bölünmüş olur ve ikisi birden geçebilir.
//
// pg_try_advisory_lock BEKLEMEZ: alamadıysa bu koşu atlanır. Beklemek,
// zamanlayıcı tikleri kuyruğa dizmek demek olurdu.
//
// ⚠️ Kilit SABİTLENMİŞ bir bağlantıda tutuluyor: havuzdan alınan bir
// bağlantı koşunun ortasında geri verilebilir ve kilit sessizce
// düşerdi.
func (s *Store) TryLockSync(ctx context.Context) (release func(), acquired bool, err error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("store.TryLockSync: %w", err)
	}

	var got bool
	if err := conn.QueryRowContext(ctx,
		`SELECT pg_try_advisory_lock($1);`, syncLockID).Scan(&got); err != nil {
		conn.Close()
		return nil, false, fmt.Errorf("store.TryLockSync: %w", err)
	}
	if !got {
		conn.Close()
		return nil, false, nil
	}

	return func() {
		unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()

		conn.ExecContext(unlockCtx, `SELECT pg_advisory_unlock($1);`, syncLockID)
		conn.Close()
	}, true, nil
}
