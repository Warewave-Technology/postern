package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

/*
 * Kayıt arşivinin defteri.
 *
 * ⚠️ TEK BİR SORU İÇİN VAR: "bu oturumun kaydı başka bir yerde
 * güvende mi?" Budayıcı silmeden önce bunu soruyor ve cevap kesin
 * olarak EVET değilse dosyaya dokunmuyor.
 */

// ArchivePending, yüklenmeyi bekleyen bir kayıt.
type ArchivePending struct {
	SessionID     string
	RecordingPath string
	StartedAt     time.Time
	Attempts      int
}

// ArchiveState, bir oturumun arşiv durumu.
type ArchiveState struct {
	Archived   bool
	ArchivedAt time.Time
	Bucket     string
	ObjectKey  string
	SHA256     string
	SizeBytes  int64
	Attempts   int
	LastError  string
}

/*
 * QueueArchive, oturum için bekleyen bir arşiv satırı açar.
 *
 * Oturum kapanışında çağrılıyor. İkinci çağrı zararsız: satır zaten
 * varsa dokunulmuyor — özellikle archived_at'e, çünkü onu silmek
 * yüklenmiş bir kaydı yeniden bekleyene çevirirdi.
 */
func (s *Store) QueueArchive(ctx context.Context, sessionID string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO session_archives (session_id) VALUES ($1)
		ON CONFLICT (session_id) DO NOTHING;`, sessionID)
	if err != nil {
		return translateErr("store.QueueArchive", err)
	}
	return nil
}

/*
 * ClaimArchives, yüklenecek işleri üstlenir.
 *
 * ⚠️ ÜSTLENME ZAMAN AŞIMIYLA SERBEST KALIYOR, temizlikle değil.
 * Öldürülen bir süreç hiçbir şey temizleyemez; claimed_at'i eski olan
 * satırı yeniden üstlenilebilir saymak, yeniden başlatmadan sonra işin
 * kendiliğinden devam etmesinin tek yolu.
 *
 * ⚠️ GERİ ÇEKİLME last_attempt_at ÜZERİNDEN: az önce denenmiş ve
 * başarısız olmuş bir satırı hemen yeniden almak, kesinti sırasında
 * depoyu ve log'u boğardı.
 */
func (s *Store) ClaimArchives(ctx context.Context, limit int, now time.Time,
	claimTimeout, retryAfter time.Duration) ([]ArchivePending, error) {

	staleClaim := now.Add(-claimTimeout).Unix()
	retryBefore := now.Add(-retryAfter).Unix()

	rows, err := s.db.QueryContext(ctx, `
		UPDATE session_archives SET claimed_at = $1
		WHERE session_id IN (
			SELECT a.session_id
			FROM session_archives a
			JOIN sessions s ON s.id = a.session_id
			WHERE a.archived_at IS NULL
			  AND (a.claimed_at IS NULL OR a.claimed_at < $2)
			  AND (a.last_attempt_at IS NULL OR a.last_attempt_at < $3)
			ORDER BY s.started_at
			LIMIT $4
		)
		RETURNING session_id,
		          (SELECT recording_path FROM sessions WHERE id = session_id),
		          (SELECT started_at     FROM sessions WHERE id = session_id),
		          attempts;`,
		now.Unix(), staleClaim, retryBefore, limit)
	if err != nil {
		return nil, translateErr("store.ClaimArchives", err)
	}
	defer rows.Close()

	var out []ArchivePending
	for rows.Next() {
		var p ArchivePending
		var startedAt int64
		if err := rows.Scan(&p.SessionID, &p.RecordingPath, &startedAt, &p.Attempts); err != nil {
			return nil, translateErr("store.ClaimArchives", err)
		}
		p.StartedAt = time.Unix(startedAt, 0)
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, translateErr("store.ClaimArchives", err)
	}
	return out, nil
}

/*
 * MarkArchived, yüklemenin DOĞRULANDIĞINI kaydeder.
 *
 * ⚠️ SIRA: yükle → deponun kendisine sor → BURAYA yaz → budayıcıya
 * silme izni doğ. Bu satır atıldığı andan itibaren kayıt yerelden
 * silinebilir hâle geliyor, dolayısıyla "gönderdim" ile "orada"
 * arasındaki farkı burada kapatmak zorundayız.
 */
func (s *Store) MarkArchived(ctx context.Context, sessionID, bucket, key, sha string,
	size int64, at time.Time) error {

	res, err := s.db.ExecContext(ctx, `
		UPDATE session_archives
		SET archived_at = $1, bucket = $2, object_key = $3, sha256 = $4,
		    size_bytes = $5, last_error = '', claimed_at = NULL
		WHERE session_id = $6;`,
		at.Unix(), bucket, key, sha, size, sessionID)
	if err != nil {
		return translateErr("store.MarkArchived", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return translateErr("store.MarkArchived", err)
	}
	if n == 0 {
		return fmt.Errorf("store.MarkArchived[%s]: %w", sessionID, ErrNotFound)
	}
	return nil
}

// MarkArchiveFailed, denemeyi ve sebebini kaydeder.
//
// archived_at'e DOKUNMUYOR: bir kez doğrulanmış kayıt, sonradan gelen
// bir hata yüzünden "güvende değil"e dönmemeli.
func (s *Store) MarkArchiveFailed(ctx context.Context, sessionID, reason string, at time.Time) error {
	// Sebep uzun olabilir (S3 XML gövdesi); tabloyu şişirmesin.
	if len(reason) > 500 {
		reason = reason[:500]
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE session_archives
		SET attempts = attempts + 1, last_error = $1, last_attempt_at = $2, claimed_at = NULL
		WHERE session_id = $3 AND archived_at IS NULL;`,
		reason, at.Unix(), sessionID)
	if err != nil {
		return translateErr("store.MarkArchiveFailed", err)
	}
	return nil
}

/*
 * ArchivedIDs, verilen oturumlardan HANGİLERİNİN doğrulanmış şekilde
 * arşivlendiğini döner.
 *
 * ⚠️ BUDAYICININ KAPISI BU ve varsayılan REDDETME: dönen kümede
 * OLMAYAN her kimlik "silme" demek. Sorgu hata verirse çağıran koşuyu
 * iptal ediyor — hiçbir şey silmeden. "Çözemedim" ile "güvende" aynı
 * şey değil ve burada karıştırmanın bedeli kanıtın yok olması.
 */
func (s *Store) ArchivedIDs(ctx context.Context, ids []string) (map[string]bool, error) {
	out := make(map[string]bool, len(ids))
	if len(ids) == 0 {
		return out, nil
	}

	// Numaralı yer tutucular: lehçe farkı olmadan çalışıyor.
	args := make([]any, len(ids))
	placeholders := make([]byte, 0, len(ids)*4)
	for i, id := range ids {
		args[i] = id
		if i > 0 {
			placeholders = append(placeholders, ',')
		}
		placeholders = append(placeholders, fmt.Sprintf("$%d", i+1)...)
	}

	// #nosec G202 -- birleştirilen parça yalnızca $N yer tutucuları
	q := `SELECT session_id FROM session_archives
	      WHERE archived_at IS NOT NULL AND session_id IN (` + string(placeholders) + `);`

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, translateErr("store.ArchivedIDs", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, translateErr("store.ArchivedIDs", err)
		}
		out[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, translateErr("store.ArchivedIDs", err)
	}
	return out, nil
}

// ArchiveStateOf, panelin gösterdiği durum.
func (s *Store) ArchiveStateOf(ctx context.Context, sessionID string) (ArchiveState, bool, error) {
	var st ArchiveState
	var archivedAt sql.NullInt64

	err := s.db.QueryRowContext(ctx, `
		SELECT archived_at, bucket, object_key, sha256, size_bytes, attempts, last_error
		FROM session_archives WHERE session_id = $1;`, sessionID).
		Scan(&archivedAt, &st.Bucket, &st.ObjectKey, &st.SHA256, &st.SizeBytes,
			&st.Attempts, &st.LastError)
	if err == sql.ErrNoRows {
		return ArchiveState{}, false, nil
	}
	if err != nil {
		return ArchiveState{}, false, translateErr("store.ArchiveStateOf", err)
	}
	if archivedAt.Valid {
		st.Archived = true
		st.ArchivedAt = time.Unix(archivedAt.Int64, 0)
	}
	return st, true, nil
}

// ArchiveBacklog, bekleyen kayıt sayısı ve EN ESKİSİNİN yaşı.
//
// ⚠️ YAŞ, SAYIDAN DAHA ÖNEMLİ. Ölmüş bir yükleyicinin belirtisi
// "sayı artıyor" değil, "en eskisi yaşlanıyor": sabit bir sayı da
// hiçbir şeyin ilerlemediği anlamına gelebilir.
func (s *Store) ArchiveBacklog(ctx context.Context) (pending int, oldest time.Time, err error) {
	var oldestUnix sql.NullInt64
	qerr := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*), MIN(s.started_at)
		FROM session_archives a
		JOIN sessions s ON s.id = a.session_id
		WHERE a.archived_at IS NULL;`).Scan(&pending, &oldestUnix)
	if qerr != nil {
		return 0, time.Time{}, translateErr("store.ArchiveBacklog", qerr)
	}
	if oldestUnix.Valid {
		oldest = time.Unix(oldestUnix.Int64, 0)
	}
	return pending, oldest, nil
}

/*
 * SetRecordingPathForTest, kayıt yolunu doğrudan değiştirir.
 *
 * ⚠️ YALNIZCA TESTLER İÇİN. Üretimde bu sütunu yazan tek yer
 * StartSession; keyfi bir yol yazabilen bir API, veritabanına
 * ulaşan birine dosya okuma/yükleme yetkisi vermek olurdu. Test,
 * arşivleyicinin tam da o saldırıyı reddettiğini ölçüyor.
 */
func (s *Store) SetRecordingPathForTest(ctx context.Context, sessionID, path string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET recording_path = $1 WHERE id = $2;`, path, sessionID)
	if err != nil {
		return translateErr("store.SetRecordingPathForTest", err)
	}
	return nil
}
