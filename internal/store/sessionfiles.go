package store

// SFTP dosya olaylarının saklanması (göç 027).
//
// Bu tablo, `subsystem sftp` kanalının açılabilmesinin ÖN KOŞULU: kanal
// dosya seviyesinde denetlenemediği sürece reddediliyordu.

import (
	"cmp"
	"context"
	"database/sql"
	"fmt"
	"strings"
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
 * FileQuery, dosya geçmişi aramasının ölçütleri.
 *
 * ⚠️ EN AZ BİRİ DOLU OLMALI. Üçü birden boşken "her şeyi göster"
 * demek, sorulmamış bir soruya dolu bir ekranla cevap vermek olurdu —
 * bu ekranın kaçındığı şeyin ta kendisi.
 */
type FileQuery struct {
	// Path, aranan yol. Under false ise TAM eşleşme.
	Path string

	/*
	 * Under: Path bir DİZİN, altındaki her şey aransın.
	 *
	 * ⚠️ SORUŞTURMANIN EN SIK SORDUĞU BU. "/etc altında ne oldu"
	 * sorusunu tam eşleşmeyle sormak imkânsız; her dosyayı tek tek
	 * bilmek gerekirdi.
	 */
	Under bool

	// User / Target, olayın oturumundan süzme.
	//
	// ⚠️ Path'siz de anlamlılar: "ayse ne aldı" ve "web01'de ne oldu"
	// soruşturmanın ikinci ve üçüncü sorusu.
	User   string
	Target string

	Limit int
}

/*
 * FileHistory, ölçütlere uyan dosya olaylarını en yeniden eskiye döner.
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
 * ⚠️ BOŞ ÖLÇÜT REDDEDİLİYOR — VE SEBEBİ ÖLÇÜLDÜ. Yalnızca yol
 * korumasını kaldırıp denedik: sorgu boş bir yol için BOŞ LİSTE
 * dönüyor (`new_path <> ''` koşulu, satırların çoğundaki boş
 * new_path'in eşleşmesini engelliyor). Yani tehlike rastgele bir liste
 * değil, boş bir liste: hiç sorulmamış bir soru "bu dosyaya
 * dokunulmamış" diye cevaplanmış görünürdü.
 *
 * ⚠️ ZAMAN SINIRLI ÇALIŞIYOR (searchtimeout.go). Ölçütler dışarıdan
 * geliyor ve havuzu SSH girişleri paylaşıyor.
 */
func (s *Store) FileHistory(ctx context.Context, q FileQuery) ([]FileTouch, error) {
	const op = "store.FileHistory"

	if q.Path == "" && q.User == "" && q.Target == "" {
		return nil, fmt.Errorf("%s: no criteria: %w", op, ErrInvalid)
	}
	// Under, Path olmadan anlamsız: çağıran karışmış demektir ve
	// sessizce "her şey"e düşmek en kötü yorum olurdu.
	if q.Under && q.Path == "" {
		return nil, fmt.Errorf("%s: under without a path: %w", op, ErrInvalid)
	}
	if q.Limit <= 0 || q.Limit > FileHistoryMaxLimit {
		q.Limit = FileHistoryDefaultLimit
	}

	var (
		conds []string
		args  []any
	)
	// ph, bir argümanı ekleyip yer tutucusunu döner ($1, $2, ...).
	ph := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}

	if q.Path != "" {
		if q.Under {
			/*
			 * ⚠️ SONDAKİ EĞİK ÇİZGİ TEMİZLENİYOR — VE SEBEBİ ÖLÇÜLDÜ.
			 *
			 * Önek düz birleştirmeyle kuruluyordu ve "/etc/" yazan biri
			 * "/etc//%" desenini alıyordu; PostgreSQL'de o desen
			 * "/etc/shadow" ile EŞLEŞMİYOR. Demo veritabanında ölçtük:
			 *
			 *   /home/sidinak   → 29 satır
			 *   /home/sidinak/  →  0 satır
			 *
			 * Sıfır satır sessizce dönüyordu: sorgu "başarıyla" bitiyor,
			 * ekran "Nothing found" yazıyor ve denetçi bunu "bu ağaca
			 * dokunulmamış" diye okuyordu. Kabuk tamamlaması dizin
			 * adlarının sonuna eğik çizgi ekliyor — yani bu, egzotik
			 * değil OLAĞAN girdi.
			 *
			 * Kök dizin de aynı kusurdaydı: "/" için desen "//%" oluyor
			 * ve hiçbir şeyle eşleşmiyordu.
			 */
			/*
			 * ⚠️ DİZİNİN KENDİSİ DE DAHİL. `opendir /etc` satırının
			 * path'i tam olarak "/etc"; yalnızca "/etc/%" arayan bir
			 * sorgu, dizinin açıldığını gösteren satırı atlardı.
			 *
			 * ⚠️ ÖNEK "/etc/" — "/etc" DEĞİL. İkincisi "/etcetera"yı
			 * da yakalardı: soruşturmaya ilgisiz bir ağacı aradığı
			 * ağaç diye gösteren sessiz bir yanlış.
			 */
			base := strings.TrimRight(q.Path, "/")
			exact := ph(cmp.Or(base, "/"))
			prefix := ph(likePrefix(base) + `/%`)
			conds = append(conds, fmt.Sprintf(
				`(f.path = %[1]s OR f.path LIKE %[2]s ESCAPE '\'
				  OR (f.new_path <> '' AND (f.new_path = %[1]s
				      OR f.new_path LIKE %[2]s ESCAPE '\')))`, exact, prefix))
		} else {
			/*
			 * ⚠️ `new_path <> ''` KOŞULU SORGUDA GÖRÜNÜYOR. Yalnızca
			 * doğruluk için değil: 030'daki indeks kısmi ve planlayıcı
			 * onu ancak aynı koşulu sorguda görürse kullanabiliyor.
			 */
			p := ph(q.Path)
			conds = append(conds, fmt.Sprintf(
				`(f.path = %[1]s OR (f.new_path <> '' AND f.new_path = %[1]s))`, p))
		}
	}
	/*
	 * ⚠️ ciEq: users.username ve targets.name harf duyarsız eşleşiyor
	 * (dialect.go'daki ciColumns ve 009'daki lower() indeksleri).
	 * Düz "=" kullanmak, "Ayse" yazan denetçiye "ayse"nin satırlarını
	 * göstermezdi.
	 *
	 * ⚠️ BU SÜZGEÇLER LEFT JOIN'İ FİİLEN INNER YAPIYOR ve doğrusu bu:
	 * oturum üstverisi okunamayan bir satır "ayse yaptı" diye
	 * gösterilemez. Süzgeç YOKKEN satır yine geliyor (kullanıcı boş),
	 * çünkü o hâlde iddia da yok.
	 */
	if q.User != "" {
		conds = append(conds, ciEq("u.username", ph(q.User)))
	}
	if q.Target != "" {
		conds = append(conds, ciEq("t.name", ph(q.Target)))
	}

	query := fmt.Sprintf(`
		SELECT f.id, f.session_id, f.at, f.op, f.path, f.new_path, f.flags,
		       f.bytes_read, f.bytes_wrote, f.ok, f.detail,
		       COALESCE(u.username, ''), COALESCE(t.name, ''),
		       COALESCE(s.os_user, ''), COALESCE(s.src_ip, '')
		FROM session_files f
		LEFT JOIN sessions s ON s.id = f.session_id
		LEFT JOIN users    u ON u.id = s.user_id
		LEFT JOIN targets  t ON t.id = s.target_id
		WHERE %s
		ORDER BY f.at DESC, f.id
		LIMIT %d;`, strings.Join(conds, "\n\t\t  AND "), q.Limit)

	out := make([]FileTouch, 0)
	err := s.searchRows(ctx, op, query, args, func(rows *sql.Rows) error {
		var t FileTouch
		var at int64
		if err := rows.Scan(&t.ID, &t.SessionID, &at, &t.Op, &t.Path,
			&t.NewPath, &t.Flags, &t.Read, &t.Wrote, &t.OK, &t.Detail,
			&t.User, &t.Target, &t.OSUser, &t.SrcIP); err != nil {
			return err
		}
		t.At = time.Unix(at, 0).UTC()
		out = append(out, t)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

/*
 * likePrefix, bir yolu LIKE deseninde GÜVENLE kullanılacak hâle getirir.
 *
 * ⚠️ KAÇIŞ ŞART. LIKE'ta `%` ve `_` joker; kaçırılmazsa "/var/log_1"
 * arayan biri "/var/logX1" ağacını da alırdı — ve `%` içeren bir yol
 * (nadir ama geçerli) aramayı bambaşka bir şeye çevirirdi. Sorgu
 * parametreli olduğu için bu bir enjeksiyon değil; sessizce YANLIŞ
 * SONUÇ üretme meselesi, ki denetimde farkı yok.
 *
 * Ters bölü ÖNCE kaçırılıyor: sonra yapılsaydı kendi eklediğimiz
 * kaçışları bir kez daha kaçırırdık.
 */
func likePrefix(p string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(p)
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

/*
 * CleanSearchPath, ağaç aramasında kullanılacak yolu normalleştirir.
 *
 * ⚠️ DIŞARI AÇIK ÇÜNKÜ UÇ, ARANANI YANKILIYOR. Panel sonuçta
 * "under /etc/" yazıp sorgunun "/etc" ile çalıştığını gizleseydi,
 * denetçi neyin arandığını yanlış bilirdi — ve "moved here" rozetini
 * çizen istemci karşılaştırması da normalleştirilmemiş yola bakıp
 * kayardı.
 *
 * Sondaki eğik çizgiler atılıyor; hepsi eğik çizgiyse kök dizin.
 */
func CleanSearchPath(p string) string {
	if t := strings.TrimRight(p, "/"); t != "" {
		return t
	}
	if strings.HasPrefix(p, "/") {
		return "/"
	}
	return p
}
