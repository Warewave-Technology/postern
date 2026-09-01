package store

// SFTP dosya olaylarının saklanması (göç 027).
//
// Bu tablo, `subsystem sftp` kanalının açılabilmesinin ÖN KOŞULU: kanal
// dosya seviyesinde denetlenemediği sürece reddediliyordu.

import (
	"context"
	"fmt"
	"time"
)

// SessionFile, bir oturumda gerçekleşen tek bir dosya olayı.
type SessionFile struct {
	ID        string    `json:"id"`
	SessionID string    `json:"session_id"`
	At        time.Time `json:"at"`
	Op        string    `json:"op"`
	Path      string    `json:"path"`
	NewPath   string    `json:"new_path,omitempty"`
	Flags     string    `json:"flags,omitempty"`
	Read      int64     `json:"read"`
	Wrote     int64     `json:"wrote"`
	OK        bool      `json:"ok"`
	Detail    string    `json:"detail,omitempty"`
}

/*
 * AddSessionFiles, bir grup olayı TEK transaction'da yazar.
 *
 * ⚠️ Toplu yazım şart: rsync gibi bir istemci binlerce küçük dosyaya
 * dokunur ve olay başına ayrı gidiş-dönüş, denetimi transferin hız
 * sınırı hâline getirirdi. Denetimi yavaşlatmak, onu kapatma isteği
 * doğurur.
 *
 * Ya hepsi yazılır ya hiçbiri: yarım yazılmış bir grup, "dosya açıldı
 * ama hiç kapanmadı" gibi görünen uydurma bir denetim satırı bırakırdı.
 */
func (s *Store) AddSessionFiles(ctx context.Context, sessionID string, files []SessionFile) error {
	if len(files) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return translateErr("store.AddSessionFiles", err)
	}
	defer tx.Rollback() //nolint:errcheck // commit sonrası no-op

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO session_files
		    (id, session_id, at, op, path, new_path, flags,
		     bytes_read, bytes_wrote, ok, detail)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);`)
	if err != nil {
		return translateErr("store.AddSessionFiles", err)
	}
	defer stmt.Close() //nolint:errcheck

	for _, f := range files {
		id, err := newID()
		if err != nil {
			return err
		}
		if _, err := stmt.ExecContext(ctx, id, sessionID, f.At.Unix(), f.Op,
			f.Path, f.NewPath, f.Flags, f.Read, f.Wrote, f.OK, f.Detail); err != nil {
			return translateErr("store.AddSessionFiles", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return translateErr("store.AddSessionFiles", err)
	}
	return nil
}

// SessionFiles, bir oturumun dosya olaylarını zaman sırasıyla döner.
func (s *Store) SessionFiles(ctx context.Context, sessionID string) ([]SessionFile, error) {
	return s.queryFiles(ctx, "store.SessionFiles", `
		SELECT id, session_id, at, op, path, new_path, flags,
		       bytes_read, bytes_wrote, ok, detail
		FROM session_files
		WHERE session_id = $1
		ORDER BY at, id;`, sessionID)
}

/*
 * FileHistory, bir yola dokunan TÜM oturumları döner.
 *
 * Soruşturmanın sorusu bu: "/etc/shadow'u kim aldı". Oturumdan dosyaya
 * bakan bir arayüz bu soruyu cevaplayamaz — soruşturma dosyayı bilir,
 * oturumu bilmez.
 */
func (s *Store) FileHistory(ctx context.Context, path string, limit int) ([]SessionFile, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	return s.queryFiles(ctx, "store.FileHistory", fmt.Sprintf(`
		SELECT id, session_id, at, op, path, new_path, flags,
		       bytes_read, bytes_wrote, ok, detail
		FROM session_files
		WHERE path = $1
		ORDER BY at DESC
		LIMIT %d;`, limit), path)
}

func (s *Store) queryFiles(ctx context.Context, what, query string, args ...any) ([]SessionFile, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, translateErr(what, err)
	}
	defer rows.Close()

	out := make([]SessionFile, 0)
	for rows.Next() {
		var f SessionFile
		var at int64
		if err := rows.Scan(&f.ID, &f.SessionID, &at, &f.Op, &f.Path,
			&f.NewPath, &f.Flags, &f.Read, &f.Wrote, &f.OK, &f.Detail); err != nil {
			return nil, translateErr(what, err)
		}
		f.At = time.Unix(at, 0).UTC()
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, translateErr(what, err)
	}
	return out, nil
}
