package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
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

/*
 * SetGroupAdmin, dizin GRUBUNDAN gelen yönetici yetkisini uygular.
 *
 * ⚠️ CLI'IN VERDİĞİNE DOKUNMAZ. WHERE koşulundaki
 * `admin_via IS DISTINCT FROM 'cli'` bunun için: acil durum diye elle
 * açılmış bir yöneticinin, dizinde o grubu görülmediği için sessizce
 * yetkisini kaybetmesi, tam olarak kaçınılması gereken şey — ve
 * kaybettiği an, onu geri verecek kişinin de kapısı kapanmış olurdu.
 *
 * Rol modelindeki source='sso' / 'manual' ayrımının aynısı: her
 * mekanizma yalnızca KENDİ verdiğini geri alabiliyor.
 */
func (s *Store) SetGroupAdmin(ctx context.Context, username string, admin bool) error {
	var (
		via any = nil
		val     = admin
	)
	if admin {
		via = "group"
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE users SET is_admin = $1, admin_via = $2
		WHERE username = $3 AND admin_via IS DISTINCT FROM 'cli';`,
		val, via, username)
	if err != nil {
		return translateErr("store.SetGroupAdmin", err)
	}
	// Satır güncellenmemiş olabilir (CLI yöneticisi) — bu bir hata
	// değil, kuralın kendisi.
	return nil
}

// AdminVia, yönetici yetkisinin kaynağını döner: "cli", "group" ya da
// boş (yönetici değil).
func (s *Store) AdminVia(ctx context.Context, username string) (string, error) {
	var via sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT admin_via FROM users WHERE username = $1;`, username).Scan(&via)
	if err != nil {
		return "", translateErr("store.AdminVia", err)
	}
	return via.String, nil
}

// AdminHolder, yönetici bayrağını taşıyan kişi ve bayrağın KAYNAĞI.
//
// Kaynağı da taşıması şart: panel "kim yönetici" sorusuna cevap
// verirken "bunu kim verdi" sorusunu da cevaplamak zorunda. Aksi hâlde
// grup üzerinden gelen yetki ile acil durum için elle açılmış hesap
// ekranda ayırt edilemez ve operatör, kaldıramayacağı bir yetkiyi
// kaldırabileceğini sanır.
type AdminHolder struct {
	Username string `json:"username"`
	// Via: "cli", "group" ya da boş. Boş olan, admin_via sütunu
	// eklenmeden önce yönetici yapılmış eski bir kayıttır (017 göçü
	// mevcutları 'cli' sayıyor, yani pratikte boş kalmaması gerekir).
	Via string `json:"via"`
}

// Admins, yönetici bayrağı taşıyan herkesi kaynağıyla döner.
func (s *Store) Admins(ctx context.Context) ([]AdminHolder, error) {
	// #nosec G202 -- birleştirilen parça sabit (dialect.go)
	rows, err := s.db.QueryContext(ctx, `
		SELECT username, admin_via FROM users
		WHERE is_admin = TRUE
		ORDER BY `+ciOrder("username")+`;`)
	if err != nil {
		return nil, translateErr("store.Admins", err)
	}
	defer rows.Close()

	out := make([]AdminHolder, 0)
	for rows.Next() {
		var h AdminHolder
		var via sql.NullString
		if err := rows.Scan(&h.Username, &via); err != nil {
			return nil, translateErr("store.Admins", err)
		}
		h.Via = via.String
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, translateErr("store.Admins", err)
	}
	return out, nil
}

/*
 * ApplyAdminGroup, grup üzerinden yönetici kümesini TEK İŞLEMDE eşitler.
 *
 * ⚠️ NEDEN "bir sonraki girişte" DEĞİL, ŞİMDİ:
 *
 * Yetki eskiden yalnızca kişi giriş yaptığında güncelleniyordu. Bu,
 * yönetici grubu DEĞİŞTİĞİNDE sessiz bir sızıntı bırakıyor: eski gruptan
 * gelen kişi bir daha hiç giriş yapmasa da yönetici KALIYOR. "Grubu
 * değiştirdim" ile "yetki değişti" arasındaki fark, kimsenin bakmadığı
 * bir yerde süresiz açık duruyordu.
 *
 * Ayrıca onay ekranını dürüst yapan şey bu: ekran "bu kişiler yönetici
 * oluyor" diyorsa, kaydettikten sonra gerçekten öyle olmalı — "herkes
 * bir dahaki girişinde" değil.
 *
 * members'ın DB'de karşılığı olmayanları ATLANIR (hata değil): dizinde
 * var ama postern'e hiç girmemiş kişinin hesabı yok. İlk girişinde
 * applyGroupAdmin onu zaten yakalar.
 *
 * CLI'ın verdiği yöneticiliğe DOKUNMAZ — ne verirken ne alırken.
 */
func (s *Store) ApplyAdminGroup(ctx context.Context, members []string) (granted, revoked []string, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, translateErr("store.ApplyAdminGroup", err)
	}
	defer tx.Rollback() //nolint:errcheck // commit sonrası no-op

	// Bütün kullanıcı adları TEK sorguda: ad eşleştirmesi harf duyarsız
	// olmak zorunda (dizin "Ayse" derken DB'de "ayse" olabilir) ve bunu
	// kişi başına lower() sorgusuyla yapmak, 200 üyelik bir grup için
	// 200 tarama demekti.
	rows, err := tx.QueryContext(ctx,
		`SELECT username, admin_via FROM users;`)
	if err != nil {
		return nil, nil, translateErr("store.ApplyAdminGroup", err)
	}
	type row struct{ name, via string }
	all := make([]row, 0)
	for rows.Next() {
		var r row
		var via sql.NullString
		if err := rows.Scan(&r.name, &via); err != nil {
			rows.Close()
			return nil, nil, translateErr("store.ApplyAdminGroup", err)
		}
		r.via = via.String
		all = append(all, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, nil, translateErr("store.ApplyAdminGroup", err)
	}
	rows.Close()

	// Hedef küme: dizin üyelerinin DB'deki gerçek yazımları.
	want := make(map[string]bool, len(members))
	for _, m := range members {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		for _, u := range all {
			if strings.EqualFold(u.name, m) {
				want[u.name] = true
				break
			}
		}
	}

	granted = make([]string, 0)
	revoked = make([]string, 0)

	for _, u := range all {
		switch {
		case want[u.name] && u.via != "group":
			// ⚠️ CLI koşulu burada da: elle açılmış yöneticinin kaynağı
			// 'group'a düşerse, gruptan çıkarıldığı gün acil durum
			// hesabı da kapanır.
			res, err := tx.ExecContext(ctx, `
				UPDATE users SET is_admin = TRUE, admin_via = 'group'
				WHERE username = $1 AND admin_via IS DISTINCT FROM 'cli';`, u.name)
			if err != nil {
				return nil, nil, translateErr("store.ApplyAdminGroup", err)
			}
			if n, _ := res.RowsAffected(); n > 0 {
				granted = append(granted, u.name)
			}
		case !want[u.name] && u.via == "group":
			if _, err := tx.ExecContext(ctx, `
				UPDATE users SET is_admin = FALSE, admin_via = NULL
				WHERE username = $1 AND admin_via = 'group';`, u.name); err != nil {
				return nil, nil, translateErr("store.ApplyAdminGroup", err)
			}
			revoked = append(revoked, u.name)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, nil, translateErr("store.ApplyAdminGroup", err)
	}
	return granted, revoked, nil
}
