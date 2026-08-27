package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"modernc.org/sqlite"
	sqlitelib "modernc.org/sqlite/lib"

	"github.com/warewave/postern/internal/model"
	"github.com/warewave/postern/internal/secret"
)

var (
	// ErrNotFound, aranan kaydın olmadığını söyler.
	ErrNotFound = errors.New("store: not found")

	// ErrConflict, benzersizlik kısıtının ihlal edildiğini söyler
	// (aynı adla ikinci bir kullanıcı, rol, hedef...).
	ErrConflict = errors.New("store: already exists")

	// errNotImplementedS51, S5.1 iskeletinin bekleyen fonksiyonları.
	errNotImplementedS51 = errors.New("store: not implemented")

	// errNotImplementedS33, S3.3 iskeletinin bekleyen fonksiyonları.
	errNotImplementedS33 = errors.New("store: not implemented")
)

type Store struct {
	db *sql.DB

	// box, şifreli ayarları açan anahtar. nil olabilir — bkz. UseSecretBox.
	box *secret.Box
}

func Open(ctx context.Context, path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("store.Open: %w", err)
	}

	dsn := fmt.Sprintf("%s?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store.Open: %w", err)
	}

	err = db.PingContext(ctx)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("store.Open: %w", err)
	}

	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("store.newID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func (s *Store) CreateUser(ctx context.Context, username, email, osUser string) (string, error) {
	userID, err := newID()
	if err != nil {
		return "", fmt.Errorf("store.CreateUser: %w", err)
	}

	userEmail := sql.NullString{String: email, Valid: email != ""}

	queryStr := `
		INSERT INTO users (id, username, email, os_user, created_at)
		VALUES (?, ?, ?, ?, ?);
	`

	if _, err = s.db.ExecContext(ctx, queryStr, userID, username, userEmail, osUser, time.Now().Unix()); err != nil {
		return "", translateErr("store.CreateUser", err)
	}

	return userID, nil
}

func (s *Store) User(ctx context.Context, username string) (model.User, error) {
	var user model.User
	queryStr := `
		SELECT u.username,
	       u.os_user,
	       u.is_admin,
	       r.name AS role_name,
	       t.name AS target_name
		FROM users u
		LEFT JOIN user_roles   ur ON ur.user_id = u.id
		LEFT JOIN roles        r  ON r.id       = ur.role_id
		LEFT JOIN role_targets rt ON rt.role_id = r.id
		LEFT JOIN targets      t  ON t.id       = rt.target_id
		WHERE u.username = ?
		ORDER BY r.name, t.name;
	`

	rows, err := s.db.QueryContext(ctx, queryStr, username)
	if err != nil {
		return model.User{}, translateErr("store.User", err)
	}
	defer rows.Close()

	roleIndexMap := make(map[string]int)

	var found bool

	for rows.Next() {
		var scannedName, scannedOSUser string
		var scannedAdmin bool
		var rawRole, rawTarget sql.NullString

		if err := rows.Scan(&scannedName, &scannedOSUser, &scannedAdmin, &rawRole, &rawTarget); err != nil {
			return model.User{}, translateErr("store.User", err)
		}

		if !found {
			found = true
			user.Name = scannedName
			user.OSUser = scannedOSUser
			user.Admin = scannedAdmin
			user.Roles = make([]model.Role, 0)
		}

		if !rawRole.Valid {
			continue
		}
		roleName := rawRole.String

		idx, alreadyExists := roleIndexMap[roleName]
		if !alreadyExists {
			newGroup := model.Role{
				Name:    roleName,
				Targets: make([]string, 0),
			}
			user.Roles = append(user.Roles, newGroup)
			idx = len(user.Roles) - 1
			roleIndexMap[roleName] = idx
		}

		if rawTarget.Valid {
			user.Roles[idx].Targets = append(user.Roles[idx].Targets, rawTarget.String)
		}

	}

	if err = rows.Err(); err != nil {
		return model.User{}, translateErr("store.User", err)
	}

	if !found {
		return model.User{}, fmt.Errorf("store.User: %w", ErrNotFound)
	}

	return user, nil
}

func (s *Store) CreateRole(ctx context.Context, name string) (string, error) {
	roleID, err := newID()
	if err != nil {
		return "", fmt.Errorf("store.CreateRole: %w", err)
	}

	queryStr := `
		INSERT INTO roles (id, name)
		VALUES (?, ?);
	`

	if _, err = s.db.ExecContext(ctx, queryStr, roleID, name); err != nil {
		return "", translateErr("store.CreateRole", err)
	}

	return roleID, nil
}

func (s *Store) CreateTarget(ctx context.Context, t model.Target) (string, error) {
	targetID, err := newID()
	if err != nil {
		return "", fmt.Errorf("store.CreateTarget: %w", err)
	}

	queryStr := `
		INSERT INTO targets (id, name, host, port, host_key)
		VALUES (?, ?, ?, ?, ?);
	`

	if _, err = s.db.ExecContext(ctx, queryStr, targetID, t.Name, t.Host, t.Port, t.HostKey); err != nil {
		return "", translateErr("store.CreateTarget", err)
	}

	return targetID, nil
}

func (s *Store) Target(ctx context.Context, name string) (model.Target, error) {
	queryStr := `
		SELECT id, name, host, port, host_key
		FROM targets
		WHERE name=?;
	`

	var target model.Target
	var targetID string

	err := s.db.QueryRowContext(ctx, queryStr, name).Scan(&targetID, &target.Name, &target.Host, &target.Port, &target.HostKey)
	if err != nil {
		return target, translateErr("store.Target", err)
	}

	return target, nil
}

func (s *Store) Targets(ctx context.Context) ([]model.Target, error) {
	var targets []model.Target

	queryStr := `
		SELECT name, host, port, host_key
		FROM targets
		ORDER BY name;
	`

	rows, err := s.db.QueryContext(ctx, queryStr)
	if err != nil {
		return nil, translateErr("store.Targets", err)
	}
	defer rows.Close()

	for rows.Next() {
		var target model.Target

		if err := rows.Scan(&target.Name, &target.Host, &target.Port, &target.HostKey); err != nil {
			return nil, translateErr("store.Targets", err)
		}

		targets = append(targets, target)
	}

	if err = rows.Err(); err != nil {
		return nil, translateErr("store.Targets", err)
	}

	return targets, nil
}

// AssignRole, kullanıcıya ELLE rol verir (source='manual').
//
// expiresAt sıfır ise süresiz. Zaten verilmiş bir rolü tekrar vermek hata
// değil — ama artık tam olarak no-op da değil: expires_at GÜNCELLENİR,
// çünkü "bu yetkiyi uzat" doğal bir istek ve ayrı bir komut gerektirmesi
// için sebep yok.
//
// Kullanıcı ya da rol yoksa ErrNotFound.
//
// TODO(yigit): expiresAt ve source='manual' ekle.
//
// İpucu: ON CONFLICT hedefi aynı kalıyor ((user_id, role_id)) ama artık
// DO NOTHING değil DO UPDATE gerekiyor — expires_at ve source alanlarını
// yaz. source'u güncellemek önemli: SSO'dan gelmiş bir rolü yönetici elle
// onaylıyorsa artık ona ait olmalı ve sonraki senkronizasyonda silinmemeli.
//
// ⚠️ Sıfır time.Time'ı doğrudan Unix()'e verme: 1970 öncesi bir sayı
// üretir ve "süresiz" yerine "çoktan doldu" anlamına gelir. NULL yazman
// gerekiyor (sql.NullInt64).
func (s *Store) AssignRole(ctx context.Context, username, roleName string, expiresAt time.Time) error {
	var userID string
	queryUserStr := `
		SELECT id
		FROM users
		WHERE username=?;
	`

	var roleID string
	queryRoleStr := `
		SELECT id
		FROM roles
		WHERE name=?;
	`

	err := s.db.QueryRowContext(ctx, queryUserStr, username).Scan(&userID)
	if err != nil {
		return translateErr("store.AssignRole", err)
	}

	err = s.db.QueryRowContext(ctx, queryRoleStr, roleName).Scan(&roleID)
	if err != nil {
		return translateErr("store.AssignRole", err)
	}

	if _, err = s.db.ExecContext(ctx, `INSERT INTO user_roles (user_id, role_id) VALUES (?, ?) ON CONFLICT(user_id, role_id) DO NOTHING;`, userID, roleID); err != nil {
		return translateErr("store.AssignRole", err)
	}

	return nil
}

func (s *Store) GrantTarget(ctx context.Context, roleName, targetName string) error {
	var targetID string
	queryTargetStr := `
		SELECT id
		FROM targets
		WHERE name=?;
	`

	var roleID string
	queryRoleStr := `
		SELECT id
		FROM roles
		WHERE name=?;
	`

	err := s.db.QueryRowContext(ctx, queryTargetStr, targetName).Scan(&targetID)
	if err != nil {
		return translateErr("store.GrantTarget", err)
	}

	err = s.db.QueryRowContext(ctx, queryRoleStr, roleName).Scan(&roleID)
	if err != nil {
		return translateErr("store.GrantTarget", err)
	}

	if _, err = s.db.ExecContext(ctx, `INSERT INTO role_targets (role_id, target_id) VALUES (?, ?) ON CONFLICT(role_id, target_id) DO NOTHING;`, roleID, targetID); err != nil {
		return translateErr("store.GrantTarget", err)
	}

	return nil
}

// ---------------------------------------------------------------------
// Yönetim: silme, geri alma, yönetici denetim kaydı (S4.2)
// ---------------------------------------------------------------------

// AdminLogEntry, tek bir yönetici işleminin kaydı.
type AdminLogEntry struct {
	At      time.Time
	Actor   string // web: oturum sahibi; cli: işletim sistemi kullanıcısı
	Via     string // "web" | "cli"
	Action  string // makine-okur: "user.create", "role.grant" ...
	Entity  string // etkilenen varlık adı
	Details string
}

// LogAdmin, bir yönetici işlemini deftere yazar (sıfır At damgalanır).
//
// Çağıran, işlemi BAŞARIYLA bitirdikten sonra çağırır — başarısız
// denemeler HTTP log'unda zaten var; defter, "ne değişti"nin kaydı.
func (s *Store) LogAdmin(ctx context.Context, e AdminLogEntry) error {
	at := e.At
	if at.IsZero() {
		at = time.Now()
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO admin_log (at, actor, via, action, entity, details) VALUES (?, ?, ?, ?, ?, ?);`,
		at.Unix(), e.Actor, e.Via, e.Action, e.Entity, e.Details)
	if err != nil {
		return translateErr("store.LogAdmin", err)
	}
	return nil
}

// AdminLog, defteri YENİDEN ESKİYE döner. limit<=0 sınırsız.
func (s *Store) AdminLog(ctx context.Context, limit int) ([]AdminLogEntry, error) {
	if limit <= 0 {
		limit = -1
	}

	// id ikincil sıralama: aynı saniyeye düşen kayıtlar (bir formda arka
	// arkaya yapılan işlemler) deterministik ve ekleme sırasında kalsın.
	rows, err := s.db.QueryContext(ctx, `
		SELECT at, actor, via, action, entity, details
		FROM admin_log
		ORDER BY at DESC, id DESC
		LIMIT ?;`, limit)
	if err != nil {
		return nil, translateErr("store.AdminLog", err)
	}
	defer rows.Close()

	entries := make([]AdminLogEntry, 0)
	for rows.Next() {
		var e AdminLogEntry
		var at int64
		if err := rows.Scan(&at, &e.Actor, &e.Via, &e.Action, &e.Entity, &e.Details); err != nil {
			return nil, translateErr("store.AdminLog", err)
		}
		e.At = time.Unix(at, 0)
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, translateErr("store.AdminLog", err)
	}
	return entries, nil
}

// Roles, tüm rolleri hedefleriyle, ada göre sıralı döner; hedefsiz rol
// boş Targets ile gelir.
func (s *Store) Roles(ctx context.Context) ([]model.Role, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.name, t.name
		FROM roles r
		LEFT JOIN role_targets rt ON rt.role_id = r.id
		LEFT JOIN targets      t  ON t.id       = rt.target_id
		ORDER BY r.name, t.name;`)
	if err != nil {
		return nil, translateErr("store.Roles", err)
	}
	defer rows.Close()

	roles := make([]model.Role, 0)
	index := map[string]int{}

	for rows.Next() {
		var name string
		var rawTarget sql.NullString
		if err := rows.Scan(&name, &rawTarget); err != nil {
			return nil, translateErr("store.Roles", err)
		}

		ri, ok := index[name]
		if !ok {
			roles = append(roles, model.Role{Name: name, Targets: make([]string, 0)})
			ri = len(roles) - 1
			index[name] = ri
		}
		// Hedefsiz rolün hayalet LEFT JOIN satırı: NULL hedefi atla.
		if rawTarget.Valid {
			roles[ri].Targets = append(roles[ri].Targets, rawTarget.String)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, translateErr("store.Roles", err)
	}
	return roles, nil
}

// rowID, ada göre tek bir id çözer; yoksa ErrNotFound. table/column
// çağıran koddan gelen SABİTLERDİR — kullanıcı girdisi buraya asla girmez
// (string birleştirmeli SQL'in tek meşru hâli).
func (s *Store) rowID(ctx context.Context, op, table, column, value string) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM `+table+` WHERE `+column+` = ?;`, value).Scan(&id)
	if err != nil {
		return "", translateErr(op, err)
	}
	return id, nil
}

// isFKRestrict, hatanın "bu satıra hâlâ referans var" olup olmadığını
// söyler.
//
// translateErr 787'yi ErrNotFound'a çevirir — o eşleme INSERT varsayımı
// ("işaret ettiğin ebeveyn yok"). DELETE'te anlam tersine döner: silmek
// istediğin satır BAŞKASININ ebeveyni. Bu yüzden Delete* fonksiyonları
// translateErr'den ÖNCE bu kontrolü yapar ve ErrConflict üretir.
//
// İki kod birden: SQLite, ON DELETE RESTRICT'i içeride tetikleyici gibi
// uyguladığı için ihlali 787 (FOREIGNKEY) değil 1811 (TRIGGER) olarak
// raporlar; varsayılan NO ACTION ise 787 verir. Şemadaki RESTRICT bilinçli
// bir karardı — kodu da onun diliyle dinliyoruz.
func isFKRestrict(err error) bool {
	var sqliteErr *sqlite.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	code := sqliteErr.Code()
	return code == sqlitelib.SQLITE_CONSTRAINT_FOREIGNKEY || code == sqlitelib.SQLITE_CONSTRAINT_TRIGGER
}

// DeleteTarget, hedefi ve rol bağlarını (CASCADE) kaldırır. Yoksa
// ErrNotFound; oturum kaydı varsa ErrConflict — denetim kaydı olan varlık
// silinmez, bu bir kısıt değil özellik (ayrıntı: isFKRestrict).
func (s *Store) DeleteTarget(ctx context.Context, name string) error {
	id, err := s.rowID(ctx, "store.DeleteTarget", "targets", "name", name)
	if err != nil {
		return err
	}

	if _, err := s.db.ExecContext(ctx, `DELETE FROM targets WHERE id = ?;`, id); err != nil {
		if isFKRestrict(err) {
			return fmt.Errorf("store.DeleteTarget: target %q has recorded sessions: %w", name, ErrConflict)
		}
		return translateErr("store.DeleteTarget", err)
	}
	return nil
}

// DeleteRole: rolün bağları (user_roles, role_targets) CASCADE ile gider;
// sessions rolü referanslamadığı için 787 bu yoldan çıkmaz — kontrol yine
// de duruyor, şema yarın değişirse sessizce yanlış hataya düşmeyelim.
func (s *Store) DeleteRole(ctx context.Context, name string) error {
	id, err := s.rowID(ctx, "store.DeleteRole", "roles", "name", name)
	if err != nil {
		return err
	}

	if _, err := s.db.ExecContext(ctx, `DELETE FROM roles WHERE id = ?;`, id); err != nil {
		if isFKRestrict(err) {
			return fmt.Errorf("store.DeleteRole: role %q is still referenced: %w", name, ErrConflict)
		}
		return translateErr("store.DeleteRole", err)
	}
	return nil
}

// DeleteUser: kullanıcıyı, bağlarını ve anahtarlarını kaldırır. Oturum
// kaydı olan kullanıcı için ErrConflict. Erişimi kesmenin doğru yolu
// zaten silmek değil: anahtarlarını ve rollerini almak — kayıt kalır,
// kapı kapanır.
func (s *Store) DeleteUser(ctx context.Context, username string) error {
	id, err := s.rowID(ctx, "store.DeleteUser", "users", "username", username)
	if err != nil {
		return err
	}

	if _, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?;`, id); err != nil {
		if isFKRestrict(err) {
			return fmt.Errorf("store.DeleteUser: user %q has recorded sessions: %w", username, ErrConflict)
		}
		return translateErr("store.DeleteUser", err)
	}
	return nil
}

// SyncRoles, kullanıcının SSO kaynaklı rollerini IdP'nin söylediğiyle
// DEĞİŞTİRİR. Elle atanmış roller (source='manual') etkilenmez.
//
// Her SSO girişinde çağrılır: gruptan çıkarılan kullanıcı yetkisini o an
// kaybeder, yeni gruba eklenen o an kazanır.
//
// TODO(yigit): implement.
//
// Akış:
//  1. Kullanıcının id'sini çöz (yoksa ErrNotFound).
//  2. source='sso' satırlarını SİL — hepsini, tek sorguda.
//  3. roleNames'teki her rol için satır ekle (source='sso').
//     Bilinmeyen rol adı: ATLA, hata verme. Sebep: rol adları
//     group_mappings'ten gelecek ve bir eşleme silinmiş olabilir; bir
//     kullanıcının girişini yönetici hatası yüzünden reddetmek yanlış.
//  4. ⚠️ Rol zaten source='manual' olarak varsa ON CONFLICT DO NOTHING:
//     elle verilen yetki kazanır ve IdP'ye bağlı olmadan yaşamaya devam
//     eder. "Elle verilen yetki elle alınır" kuralı.
//
// ⚠️ 2 ve 3 AYNI TRANSACTION'da olmalı. Ayrı yaparsan araya düşen bir
// hata kullanıcıyı yetkisiz bırakır ve bir sonraki girişe kadar öyle
// kalır — Migrate'te öğrendiğimiz dersin aynısı.
func (s *Store) SyncRoles(ctx context.Context, username string, roleNames []string) error {
	return errNotImplementedS51
}

// ---------------------------------------------------------------------
// Ayarlar (S5.1)
// ---------------------------------------------------------------------

// UseSecretBox, şifreli ayarları açıp mühürleyecek anahtarı bağlar.
//
// Store bunsuz da çalışır: şifresiz ayarlar okunur/yazılır, şifreli olana
// dokunulduğunda hata verilir. CLI'ın çoğu komutu sır gerektirmiyor ve
// anahtar dosyası olmadan da çalışabilmeli.
func (s *Store) UseSecretBox(box *secret.Box) { s.box = box }

// Setting, tek bir ayarı döner; şifreliyse çözer. Yoksa ErrNotFound.
//
// TODO(yigit): implement.
//
// encrypted=1 olan bir satır s.box nil iken okunmaya çalışılırsa AÇIK bir
// hata ver ("secret key not configured") — boş string dönmek, sırrı
// silinmiş gibi gösterir ve LDAP'ın parolasız bağlanmaya çalışmasına yol
// açar.
func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	return "", errNotImplementedS51
}

// SetSetting, ayarı yazar. encrypt=true ise değer mühürlenerek saklanır.
//
// TODO(yigit): implement. (UPSERT: aynı anahtar tekrar yazılabilmeli.)
//
// encrypt=true iken s.box nil ise REDDET — düz metin yazıp "şifreledim"
// sanmak, bu paketin bütün amacını sessizce boşa çıkarır.
func (s *Store) SetSetting(ctx context.Context, key, value string, encrypt bool, actor string) error {
	return errNotImplementedS51
}

// Settings, ada göre sıralı ayar listesi döner — ŞİFRELİ DEĞERLER
// MASKELENMİŞ olarak.
//
// TODO(yigit): implement.
//
// ⚠️ Bu fonksiyonun çıktısı admin API'sine gidecek. Şifreli bir ayarın
// değeri ASLA dönmemeli: sır yazılır ama okunmaz. Value alanına maske
// koy (Secret=true ile birlikte), böylece arayüz "değer var ama
// gösterilmiyor" ile "değer boş"u ayırt edebilir.
func (s *Store) Settings(ctx context.Context) ([]SettingView, error) {
	return nil, errNotImplementedS51
}

// SettingView, listeleme için ayar görünümü.
type SettingView struct {
	Key       string
	Value     string // şifreliyse maskeli
	Secret    bool
	UpdatedAt time.Time
	UpdatedBy string
}

// RevokeRole, kullanıcıdan rolü geri alır. Kullanıcı ya da rol yoksa
// ErrNotFound; bağ zaten yoksa SESSİZ no-op (AssignRole'un aynası).
func (s *Store) RevokeRole(ctx context.Context, username, roleName string) error {
	userID, err := s.rowID(ctx, "store.RevokeRole", "users", "username", username)
	if err != nil {
		return err
	}
	roleID, err := s.rowID(ctx, "store.RevokeRole", "roles", "name", roleName)
	if err != nil {
		return err
	}

	// Bağ zaten yoksa sessiz no-op: "bu yetkiyi al" isteği, yetki zaten
	// yokken de yerine getirilmiş sayılır (AssignRole'un aynası).
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM user_roles WHERE user_id = ? AND role_id = ?;`, userID, roleID); err != nil {
		return translateErr("store.RevokeRole", err)
	}
	return nil
}

// RevokeTarget, rolden hedef erişimini geri alır. GrantTarget'ın aynası.
func (s *Store) RevokeTarget(ctx context.Context, roleName, targetName string) error {
	roleID, err := s.rowID(ctx, "store.RevokeTarget", "roles", "name", roleName)
	if err != nil {
		return err
	}
	targetID, err := s.rowID(ctx, "store.RevokeTarget", "targets", "name", targetName)
	if err != nil {
		return err
	}

	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM role_targets WHERE role_id = ? AND target_id = ?;`, roleID, targetID); err != nil {
		return translateErr("store.RevokeTarget", err)
	}
	return nil
}

// RemovePublicKey, anahtarı kullanıcıdan kaldırır. Kullanıcı yoksa ya da
// anahtar BU kullanıcıya ait değilse ErrNotFound — başka birinin
// anahtarını "benimkiymiş gibi" silmek sessizce başarılı OLMAMALI.
// keyBlob ham bayt; base64 çevrimi içeride, AddPublicKey ile simetrik.
func (s *Store) RemovePublicKey(ctx context.Context, username string, keyBlob []byte) error {
	userID, err := s.rowID(ctx, "store.RemovePublicKey", "users", "username", username)
	if err != nil {
		return err
	}

	// user_id koşulu güvenliğin kendisi: yalnızca blob'la silseydik,
	// "ayse'nin anahtarını sil" isteği yigit'in anahtarını silebilirdi.
	// Sıfır satır = anahtar yok YA DA başkasının — ikisi de çağırana göre
	// "senin böyle bir anahtarın yok", yani ErrNotFound.
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM user_public_keys WHERE key_blob = ? AND user_id = ?;`,
		base64.StdEncoding.EncodeToString(keyBlob), userID)
	if err != nil {
		return translateErr("store.RemovePublicKey", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return translateErr("store.RemovePublicKey", err)
	}
	if n == 0 {
		return fmt.Errorf("store.RemovePublicKey: %w", ErrNotFound)
	}
	return nil
}

// SetUserAdmin, uygulama yönetim yetkisini verir ya da alır.
// Kullanıcı yoksa ErrNotFound.
func (s *Store) SetUserAdmin(ctx context.Context, username string, admin bool) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET is_admin = ? WHERE username = ?;`, admin, username)
	if err != nil {
		return translateErr("store.SetUserAdmin", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return translateErr("store.SetUserAdmin", err)
	}
	if n == 0 {
		return fmt.Errorf("store.SetUserAdmin: %w", ErrNotFound)
	}
	return nil
}

// SetUserEmail, kullanıcının e-postasını değiştirir; boş string adresi
// SİLER (NULL). Kullanıcı yoksa ErrNotFound; adres başka bir kullanıcıda
// kayıtlıysa ErrConflict (users.email UNIQUE — OIDC eşleşmesi tekil kalmalı).
//
// "user add"in reddettiği örtük değişikliğin AÇIK hâli: yönetici ne
// yaptığını komutun adıyla söylüyor.
func (s *Store) SetUserEmail(ctx context.Context, username, email string) error {
	// CreateUser ile aynı kural: boş e-posta NULL'dır, '' değil —
	// UNIQUE, e-postasız ikinci kullanıcıya takılmasın.
	val := sql.NullString{String: email, Valid: email != ""}

	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET email = ? WHERE username = ?;`, val, username)
	if err != nil {
		return translateErr("store.SetUserEmail", err)
	}

	n, err := res.RowsAffected()
	if err != nil {
		return translateErr("store.SetUserEmail", err)
	}
	if n == 0 {
		return fmt.Errorf("store.SetUserEmail: %w", ErrNotFound)
	}
	return nil
}

// SetUserOSUser, kullanıcının hedeflerdeki hesabını değiştirir. Boş değer
// şemadaki CHECK'e takılır; kullanıcı yoksa ErrNotFound.
//
// ⚠️ Bu, bir sonraki oturumdan itibaren kesilecek SERTİFİKALARIN
// principal'ını değiştirir — geçmiş denetim kayıtlarına dokunmaz
// (sessions.os_user o günkü kararı saklar; sebebi şemada yazıyor).
func (s *Store) SetUserOSUser(ctx context.Context, username, osUser string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET os_user = ? WHERE username = ?;`, osUser, username)
	if err != nil {
		return translateErr("store.SetUserOSUser", err)
	}

	n, err := res.RowsAffected()
	if err != nil {
		return translateErr("store.SetUserOSUser", err)
	}
	if n == 0 {
		return fmt.Errorf("store.SetUserOSUser: %w", ErrNotFound)
	}
	return nil
}

// Users, tüm kullanıcıları rolleriyle birlikte, ada göre sıralı döner.
//
// User'ın sorgusunun WHERE'siz hâli; gruplama iki seviyeli — önce
// kullanıcıya, sonra role. Desen User'dakiyle aynı, yalnızca indeks
// map'leri kullanıcı boyutu kazanıyor.
//
// Hiç kullanıcı yoksa boş dilim, hata değil.
func (s *Store) Users(ctx context.Context) ([]model.User, error) {
	queryStr := `
		SELECT u.username,
	       u.os_user,
	       u.is_admin,
	       r.name AS role_name,
	       t.name AS target_name
		FROM users u
		LEFT JOIN user_roles   ur ON ur.user_id = u.id
		LEFT JOIN roles        r  ON r.id       = ur.role_id
		LEFT JOIN role_targets rt ON rt.role_id = r.id
		LEFT JOIN targets      t  ON t.id       = rt.target_id
		ORDER BY u.username, r.name, t.name;
	`

	rows, err := s.db.QueryContext(ctx, queryStr)
	if err != nil {
		return nil, translateErr("store.Users", err)
	}
	defer rows.Close()

	// Boş dilim sözleşmesi: hiç kullanıcı yoksa nil değil [] dönsün diye
	// burada make ile başlıyoruz.
	users := make([]model.User, 0)
	userIndex := map[string]int{}
	// Rol indeksi kullanıcı BAŞINA tutulur: iki kullanıcı aynı role
	// sahipse bunlar ayrı gruplardır, tek map ikisini karıştırırdı.
	roleIndex := map[string]map[string]int{}

	for rows.Next() {
		var name, osUser string
		var admin bool
		var rawRole, rawTarget sql.NullString

		if err := rows.Scan(&name, &osUser, &admin, &rawRole, &rawTarget); err != nil {
			return nil, translateErr("store.Users", err)
		}

		ui, ok := userIndex[name]
		if !ok {
			users = append(users, model.User{Name: name, OSUser: osUser, Admin: admin, Roles: make([]model.Role, 0)})
			ui = len(users) - 1
			userIndex[name] = ui
			roleIndex[name] = map[string]int{}
		}

		if !rawRole.Valid {
			continue // rolsüz kullanıcının hayalet LEFT JOIN satırı
		}

		ri, ok := roleIndex[name][rawRole.String]
		if !ok {
			users[ui].Roles = append(users[ui].Roles, model.Role{Name: rawRole.String, Targets: make([]string, 0)})
			ri = len(users[ui].Roles) - 1
			roleIndex[name][rawRole.String] = ri
		}

		if rawTarget.Valid {
			users[ui].Roles[ri].Targets = append(users[ui].Roles[ri].Targets, rawTarget.String)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, translateErr("store.Users", err)
	}

	return users, nil
}

func (s *Store) UserByEmail(ctx context.Context, email string) (model.User, error) {
	if email == "" {
		return model.User{}, fmt.Errorf("store.UserByEmail: %w", ErrNotFound)
	}

	var username string
	queryStr := `
		SELECT username
		FROM users
		WHERE email = ?;
	`

	if err := s.db.QueryRowContext(ctx, queryStr, email).Scan(&username); err != nil {
		return model.User{}, translateErr("store.UserByEmail", err)
	}

	return s.User(ctx, username)
}

type PublicKey struct {
	Blob    []byte
	Comment string
	AddedAt time.Time
}

func (s *Store) AddPublicKey(ctx context.Context, username string, keyBlob []byte, comment string) error {
	var userID string
	queryUserStr := `
		SELECT id
		FROM users
		WHERE username=?;
	`

	if err := s.db.QueryRowContext(ctx, queryUserStr, username).Scan(&userID); err != nil {
		return translateErr("store.AddPublicKey", err)
	}

	blob := base64.StdEncoding.EncodeToString(keyBlob)

	insertQuery := `
		INSERT INTO user_public_keys (key_blob, user_id, comment, added_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(key_blob) DO NOTHING;
	`

	res, err := s.db.ExecContext(ctx, insertQuery, blob, userID, comment, time.Now().Unix())
	if err != nil {
		return translateErr("store.AddPublicKey", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return translateErr("store.AddPublicKey", err)
	}

	if affected > 0 {
		return nil
	}

	var ownerID string
	ownerQuery := `
		SELECT user_id
		FROM user_public_keys
		WHERE key_blob=?;
	`

	if err := s.db.QueryRowContext(ctx, ownerQuery, blob).Scan(&ownerID); err != nil {
		return translateErr("store.AddPublicKey", err)
	}

	if ownerID != userID {
		return fmt.Errorf("store.AddPublicKey: %w", ErrConflict)
	}

	return nil
}

func (s *Store) UserByPublicKey(ctx context.Context, keyBlob []byte) (model.User, error) {
	blob := base64.StdEncoding.EncodeToString(keyBlob)

	var username string
	queryUserStr := `
		SELECT u.username
		FROM user_public_keys k
		JOIN users u ON u.id = k.user_id
		WHERE k.key_blob = ?;
	`

	if err := s.db.QueryRowContext(ctx, queryUserStr, blob).Scan(&username); err != nil {
		return model.User{}, translateErr("store.UserByPublicKey", err)
	}

	user, err := s.User(ctx, username)
	if err != nil {
		return model.User{}, translateErr("store.UserByPublicKey", err)
	}

	return user, nil
}

func (s *Store) PublicKeys(ctx context.Context, username string) ([]PublicKey, error) {
	var publicKeys []PublicKey

	var userID string
	queryUserStr := `
		SELECT id
		FROM users
		WHERE username=?;
	`

	if err := s.db.QueryRowContext(ctx, queryUserStr, username).Scan(&userID); err != nil {
		return publicKeys, translateErr("store.PublicKeys", err)
	}

	queryPKeyStr := `
		SELECT key_blob, comment, added_at
		FROM user_public_keys
		WHERE user_id = ?
		ORDER BY added_at, key_blob;
	`

	rows, err := s.db.QueryContext(ctx, queryPKeyStr, userID)
	if err != nil {
		return publicKeys, translateErr("store.PublicKeys", err)
	}
	defer rows.Close()

	for rows.Next() {
		var publicKey PublicKey
		var addeddAt int64

		if err := rows.Scan(&publicKey.Blob, &publicKey.Comment, &addeddAt); err != nil {
			return publicKeys, translateErr("store.PublicKeys", err)
		}

		publicKey.AddedAt = time.Unix(addeddAt, 0)

		blob, err := base64.StdEncoding.DecodeString(string(publicKey.Blob))
		if err != nil {
			return publicKeys, translateErr("store.PublicKeys", err)
		}

		publicKey.Blob = blob

		publicKeys = append(publicKeys, publicKey)
	}

	if err = rows.Err(); err != nil {
		return publicKeys, translateErr("store.PublicKeys", err)
	}

	return publicKeys, nil
}

type SessionStart struct {
	ID string

	Username   string
	TargetName string

	OSUser string

	SrcIP         string
	StartedAt     time.Time
	RecordingPath string
}

func (s *Store) StartSession(ctx context.Context, rec SessionStart) error {
	var userID string
	queryUserStr := `
		SELECT id
		FROM users
		WHERE username=?;
	`

	var targetID string
	queryTargetStr := `
		SELECT id
		FROM targets
		WHERE name=?;
	`

	err := s.db.QueryRowContext(ctx, queryUserStr, rec.Username).Scan(&userID)
	if err != nil {
		return translateErr("store.StartSession", err)
	}

	err = s.db.QueryRowContext(ctx, queryTargetStr, rec.TargetName).Scan(&targetID)
	if err != nil {
		return translateErr("store.StartSession", err)
	}

	if _, err = s.db.ExecContext(ctx, `INSERT INTO sessions (id, user_id, target_id, os_user, src_ip, recording_path, started_at) VALUES (?, ?, ?, ?, ?, ?, ?);`, rec.ID, userID, targetID, rec.OSUser, rec.SrcIP, rec.RecordingPath, rec.StartedAt.Unix()); err != nil {
		return translateErr("store.StartSession", err)
	}

	return nil
}

func (s *Store) EndSession(ctx context.Context, id string, endedAt time.Time) error {
	var sessionID string
	queryStr := `
		SELECT id
		FROM sessions
		WHERE id=?;
	`

	err := s.db.QueryRowContext(ctx, queryStr, id).Scan(&sessionID)
	if err != nil {
		return translateErr("store.EndSession", err)
	}

	if _, err = s.db.ExecContext(ctx, `UPDATE sessions SET ended_at=? WHERE id=? AND ended_at IS NULL;`, endedAt.Unix(), sessionID); err != nil {
		return translateErr("store.EndSession", err)
	}

	return nil
}

// Session, tek bir oturumu kimlik ADLARIYLA döner. Yoksa ErrNotFound.
//
// Sessions'ın sorgusunun WHERE s.id = ? hâli; NULL/zaman çevrimleri de
// birebir aynı desen.
func (s *Store) Session(ctx context.Context, id string) (model.Session, error) {
	queryStr := `
		SELECT s.id,
	       u.username,
	       t.name,
	       s.os_user,
	       s.src_ip,
	       s.started_at,
	       s.ended_at,
	       s.recording_path
		FROM sessions s
		JOIN users   u ON u.id = s.user_id
		JOIN targets t ON t.id = s.target_id
		WHERE s.id = ?;
	`

	var session model.Session
	var startedAt int64
	var endedAt sql.NullInt64

	err := s.db.QueryRowContext(ctx, queryStr, id).Scan(
		&session.ID, &session.User, &session.Target, &session.OSUser,
		&session.SrcIP, &startedAt, &endedAt, &session.RecordingPath,
	)
	if err != nil {
		return model.Session{}, translateErr("store.Session", err)
	}

	session.StartedAt = time.Unix(startedAt, 0)
	if endedAt.Valid {
		session.EndedAt = time.Unix(endedAt.Int64, 0)
	}

	return session, nil
}

func (s *Store) Sessions(ctx context.Context, username string, limit int) ([]model.Session, error) {
	var sessions []model.Session

	queryStr := `
		SELECT s.id,
	       u.username,
	       t.name,
	       s.os_user,
	       s.src_ip,
	       s.started_at,
	       s.ended_at,
	       s.recording_path
		FROM sessions s
		JOIN users   u ON u.id = s.user_id
		JOIN targets t ON t.id = s.target_id
		WHERE (? = '' OR u.username = ?)
		ORDER BY s.started_at DESC, s.id DESC
		LIMIT ?;
	`

	if limit <= 0 {
		limit = -1
	}

	rows, err := s.db.QueryContext(ctx, queryStr, username, username, limit)
	if err != nil {
		return nil, translateErr("store.Sessions", err)
	}
	defer rows.Close()

	for rows.Next() {
		var session model.Session

		var startedAt int64
		var endedAt sql.NullInt64

		if err := rows.Scan(&session.ID, &session.User, &session.Target, &session.OSUser, &session.SrcIP, &startedAt, &endedAt, &session.RecordingPath); err != nil {
			return nil, translateErr("store.Sessions", err)
		}

		session.StartedAt = time.Unix(startedAt, 0)

		if endedAt.Valid {
			session.EndedAt = time.Unix(endedAt.Int64, 0)
		}

		sessions = append(sessions, session)
	}

	if err = rows.Err(); err != nil {
		return nil, translateErr("store.Sessions", err)
	}

	return sessions, nil
}

func translateErr(op string, err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%s: %w: %v", op, ErrNotFound, err)
	}

	var sqliteErr *sqlite.Error
	if errors.As(err, &sqliteErr) {
		switch sqliteErr.Code() {
		case sqlitelib.SQLITE_CONSTRAINT_UNIQUE, sqlitelib.SQLITE_CONSTRAINT_PRIMARYKEY:
			return fmt.Errorf("%s: %w: %v", op, ErrConflict, err)

		case sqlitelib.SQLITE_CONSTRAINT_FOREIGNKEY:
			return fmt.Errorf("%s: %w: %v", op, ErrNotFound, err)
		}
	}

	return fmt.Errorf("%s: %w", op, err)
}
