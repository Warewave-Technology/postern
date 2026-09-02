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

// FileHistoryDefaultLimit / FileHistoryMaxLimit, geçmiş sorgusunun sınırları.
//
// ⚠️ DIŞARI AÇIKLAR çünkü kesilmiş bir listeyi "hepsi bu" diye
// göstermemek çağıranın işi: HTTP ucu, kaç satır istediğini bilmeden
// sonucun kırpılıp kırpılmadığını söyleyemez. Sınırı burada tutup
// orada bir kez daha yazsaydık, ikisi sessizce ayrışabilirdi.
const (
	FileHistoryDefaultLimit = 200
	FileHistoryMaxLimit     = 1000
)

/*
 * FileTouch, bir dosya olayı ve onu YAPAN oturumun kimliği.
 *
 * ⚠️ OTURUM KİMLİĞİ TEK BAŞINA CEVAP DEĞİL. "/etc/shadow'u kim aldı"
 * sorusunun cevabı bir UUID değil, bir kişidir; olayları çıplak
 * session_id'lerle döndürmek, denetçiyi her satır için ayrı bir
 * sorguya mecbur bırakırdı.
 */
type FileTouch struct {
	SessionFile
	/*
	 * Birleştirme LEFT JOIN, dolayısıyla bu alanlar boş kalabilir.
	 *
	 * ⚠️ BUGÜN BOŞ KALAMIYORLAR: 027'deki yabancı anahtar
	 * (ON DELETE RESTRICT) oturum satırının silinmesini engelliyor,
	 * yani her dosya olayının oturumu yerinde. LEFT JOIN yine de
	 * seçildi çünkü bedeli sıfır ve kısıt bir gün gevşetilirse doğru
	 * davranışı zaten yapıyor: olayın kendisi kanıt, yanındaki
	 * üstveriyi okuyamamak onu gizlemenin gerekçesi değil. Panel de
	 * bu ihtimale göre çiziyor (boş kullanıcıyı satırı yutarak değil,
	 * işaretleyerek gösteriyor).
	 */
	User   string `json:"user"`
	Target string `json:"target"`
	OSUser string `json:"os_user"`
	SrcIP  string `json:"src_ip"`
}

/*
 * FileHistory, bir yola dokunan TÜM oturumları döner.
 *
 * Soruşturmanın sorusu bu: "/etc/shadow'u kim aldı". Oturumdan dosyaya
 * bakan bir arayüz bu soruyu cevaplayamaz — soruşturma dosyayı bilir,
 * oturumu bilmez.
 *
 * ⚠️ HEDEF YOLA DA BAKIYOR. Bir dosya bir yere rename ile gelmiş
 * olabilir ve o satırda aranan yol `path`te değil `new_path`te durur.
 * Yalnızca `path`e bakan bir arama, "/tmp/exfil buraya nereden geldi"
 * sorusuna "hiç dokunulmamış" cevabını verirdi — dosyayı oraya taşıyan
 * satır elimizdeyken.
 *
 * ⚠️ BOŞ YOL REDDEDİLİYOR — VE SEBEBİ ÖLÇÜLDÜ. Korumayı kaldırıp
 * denedik: sorgu boş bir yol için BOŞ LİSTE dönüyor (aşağıdaki
 * `new_path <> ''` koşulu, satırların çoğundaki boş new_path'in
 * eşleşmesini engelliyor). Yani tehlike rastgele bir liste değil, boş
 * bir liste: hiç sorulmamış bir soru "bu dosyaya dokunulmamış" diye
 * cevaplanmış görünürdü. Bu ekranda verilebilecek en pahalı yanlış
 * cevap o.
 */
func (s *Store) FileHistory(ctx context.Context, path string, limit int) ([]FileTouch, error) {
	if path == "" {
		return nil, fmt.Errorf("store.FileHistory: empty path: %w", ErrInvalid)
	}
	if limit <= 0 || limit > FileHistoryMaxLimit {
		limit = FileHistoryDefaultLimit
	}

	/*
	 * ⚠️ `new_path <> ''` KOŞULU SORGUDA GÖRÜNÜYOR. Yalnızca doğruluk
	 * için değil: 030'daki indeks kısmi ve planlayıcı onu ancak aynı
	 * koşulu sorguda görürse kullanabiliyor. Koşulu sadeleştirmek,
	 * aramayı sessizce tam tarama hâline getirir.
	 */
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT f.id, f.session_id, f.at, f.op, f.path, f.new_path, f.flags,
		       f.bytes_read, f.bytes_wrote, f.ok, f.detail,
		       COALESCE(u.username, ''), COALESCE(t.name, ''),
		       COALESCE(s.os_user, ''), COALESCE(s.src_ip, '')
		FROM session_files f
		LEFT JOIN sessions s ON s.id = f.session_id
		LEFT JOIN users    u ON u.id = s.user_id
		LEFT JOIN targets  t ON t.id = s.target_id
		WHERE f.path = $1 OR (f.new_path <> '' AND f.new_path = $1)
		ORDER BY f.at DESC, f.id
		LIMIT %d;`, limit), path)
	if err != nil {
		return nil, translateErr("store.FileHistory", err)
	}
	defer rows.Close()

	out := make([]FileTouch, 0)
	for rows.Next() {
		var t FileTouch
		var at int64
		if err := rows.Scan(&t.ID, &t.SessionID, &at, &t.Op, &t.Path,
			&t.NewPath, &t.Flags, &t.Read, &t.Wrote, &t.OK, &t.Detail,
			&t.User, &t.Target, &t.OSUser, &t.SrcIP); err != nil {
			return nil, translateErr("store.FileHistory", err)
		}
		t.At = time.Unix(at, 0).UTC()
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, translateErr("store.FileHistory", err)
	}
	return out, nil
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
