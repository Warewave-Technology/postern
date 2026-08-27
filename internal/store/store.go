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
	"sort"
	"strings"
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

	// ErrAccessDenied: kimlik geçerli ama postern'de karşılığı yok —
	// JIT sağlamada hiçbir grup role eşleşmediğinde.
	ErrAccessDenied = errors.New("store: access denied")

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
	       u.sso_only,
	       r.name AS role_name,
	       t.name AS target_name
		FROM users u
		-- ⚠️ Süre filtresi JOIN koşulunda, WHERE'de DEĞİL: WHERE'e
		-- koysaydık süresi dolmuş tek rolü olan kullanıcı satır
		-- üretmez ve "kullanıcı yok" gibi görünürdü. JOIN koşulu
		-- yalnızca eşleşmeyi düşürür, kullanıcıyı değil.
		LEFT JOIN user_roles   ur ON ur.user_id = u.id
		                         AND (ur.expires_at IS NULL OR ur.expires_at > ?)
		LEFT JOIN roles        r  ON r.id       = ur.role_id
		LEFT JOIN role_targets rt ON rt.role_id = r.id
		LEFT JOIN targets      t  ON t.id       = rt.target_id
		WHERE u.username = ?
		ORDER BY r.name, t.name;
	`

	rows, err := s.db.QueryContext(ctx, queryStr, time.Now().Unix(), username)
	if err != nil {
		return model.User{}, translateErr("store.User", err)
	}
	defer rows.Close()

	roleIndexMap := make(map[string]int)

	var found bool

	for rows.Next() {
		var scannedName, scannedOSUser string
		var scannedAdmin, scannedSSOOnly bool
		var rawRole, rawTarget sql.NullString

		if err := rows.Scan(&scannedName, &scannedOSUser, &scannedAdmin, &scannedSSOOnly, &rawRole, &rawTarget); err != nil {
			return model.User{}, translateErr("store.User", err)
		}

		if !found {
			found = true
			user.Name = scannedName
			user.OSUser = scannedOSUser
			user.Admin = scannedAdmin
			user.SSOOnly = scannedSSOOnly
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
func (s *Store) AssignRole(ctx context.Context, username, roleName string, expiresAt time.Time) error {
	userID, err := s.rowID(ctx, "store.AssignRole", "users", "username", username)
	if err != nil {
		return err
	}
	roleID, err := s.rowID(ctx, "store.AssignRole", "roles", "name", roleName)
	if err != nil {
		return err
	}

	// Sıfır time.Time "süresiz" demek. Unix()'e verilseydi 1970 öncesi
	// bir sayı üretir ve "çoktan doldu" anlamına gelirdi.
	var expires sql.NullInt64
	if !expiresAt.IsZero() {
		expires = sql.NullInt64{Int64: expiresAt.Unix(), Valid: true}
	}

	// DO UPDATE, DO NOTHING değil: "bu yetkiyi uzat" ayrı bir komut
	// gerektirmemeli. source'un da yazılması bilinçli — SSO'dan gelmiş
	// bir rolü yönetici elle onaylıyorsa artık ona aittir ve bir sonraki
	// senkronizasyonda silinmez.
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO user_roles (user_id, role_id, source, expires_at)
		VALUES (?, ?, 'manual', ?)
		ON CONFLICT(user_id, role_id) DO UPDATE SET
			source = 'manual',
			expires_at = excluded.expires_at;`,
		userID, roleID, expires)
	if err != nil {
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
func (s *Store) SyncRoles(ctx context.Context, username string, roleNames []string) error {
	userID, err := s.rowID(ctx, "store.SyncRoles", "users", "username", username)
	if err != nil {
		return err
	}

	// Silme ve yazma AYNI transaction'da: araya düşen bir hata
	// kullanıcıyı bir sonraki girişe kadar yetkisiz bırakırdı.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return translateErr("store.SyncRoles", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM user_roles WHERE user_id = ? AND source = 'sso';`, userID); err != nil {
		return translateErr("store.SyncRoles", err)
	}

	for _, name := range roleNames {
		// Bilinmeyen rol: ATLA. Rol adları group_mappings'ten geliyor ve
		// bir eşleme silinmiş olabilir; yönetici hatası yüzünden
		// kullanıcının girişini reddetmek yanlış olurdu.
		var roleID string
		err := tx.QueryRowContext(ctx, `SELECT id FROM roles WHERE name = ?;`, name).Scan(&roleID)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return translateErr("store.SyncRoles", err)
		}

		// DO NOTHING: rol zaten elle atanmışsa o kayıt kazanır ve IdP'ye
		// bağlı olmadan yaşamaya devam eder ("elle verilen elle alınır").
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO user_roles (user_id, role_id, source, expires_at)
			VALUES (?, ?, 'sso', NULL)
			ON CONFLICT(user_id, role_id) DO NOTHING;`, userID, roleID); err != nil {
			return translateErr("store.SyncRoles", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return translateErr("store.SyncRoles", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// Grup eşlemeleri ve JIT sağlama (S5.2)
// ---------------------------------------------------------------------

// GroupMapping, bir dış grubun hangi role karşılık geldiği.
type GroupMapping struct {
	ExternalGroup string
	Role          string
	CreatedAt     time.Time
	CreatedBy     string
}

// AddGroupMapping, dış grubu role bağlar. Rol yoksa ErrNotFound; aynı
// eşleme ikinci kez eklenirse ErrConflict.
func (s *Store) AddGroupMapping(ctx context.Context, externalGroup, roleName, actor string) error {
	roleID, err := s.rowID(ctx, "store.AddGroupMapping", "roles", "name", roleName)
	if err != nil {
		return err
	}

	id, err := newID()
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO group_mappings (id, external_group, role_id, created_at, created_by)
		VALUES (?, ?, ?, ?, ?);`,
		id, externalGroup, roleID, time.Now().Unix(), actor)
	if err != nil {
		return translateErr("store.AddGroupMapping", err)
	}
	return nil
}

// RemoveGroupMapping, eşlemeyi kaldırır. Yoksa ErrNotFound.
//
// ⚠️ Bu, kullanıcıların rollerini ANINDA değiştirmez: mevcut SSO
// atamaları bir sonraki girişte yenilenir. Yetkiyi hemen kesmek gerekiyorsa
// rolü ya da kullanıcının erişimini ayrıca ele almak gerekir.
func (s *Store) RemoveGroupMapping(ctx context.Context, externalGroup, roleName string) error {
	roleID, err := s.rowID(ctx, "store.RemoveGroupMapping", "roles", "name", roleName)
	if err != nil {
		return err
	}

	res, err := s.db.ExecContext(ctx,
		`DELETE FROM group_mappings WHERE external_group = ? AND role_id = ?;`,
		externalGroup, roleID)
	if err != nil {
		return translateErr("store.RemoveGroupMapping", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return translateErr("store.RemoveGroupMapping", err)
	}
	if n == 0 {
		return fmt.Errorf("store.RemoveGroupMapping: %w", ErrNotFound)
	}
	return nil
}

// GroupMappings, tüm eşlemeleri grup adına göre sıralı döner.
func (s *Store) GroupMappings(ctx context.Context) ([]GroupMapping, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT gm.external_group, r.name, gm.created_at, gm.created_by
		FROM group_mappings gm
		JOIN roles r ON r.id = gm.role_id
		ORDER BY gm.external_group, r.name;`)
	if err != nil {
		return nil, translateErr("store.GroupMappings", err)
	}
	defer rows.Close()

	out := make([]GroupMapping, 0)
	for rows.Next() {
		var m GroupMapping
		var createdAt int64
		if err := rows.Scan(&m.ExternalGroup, &m.Role, &createdAt, &m.CreatedBy); err != nil {
			return nil, translateErr("store.GroupMappings", err)
		}
		m.CreatedAt = time.Unix(createdAt, 0)
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, translateErr("store.GroupMappings", err)
	}
	return out, nil
}

// RolesForGroups, verilen dış grup adlarının karşılığı rolleri ve
// eşleşmeyen grupları döner.
//
// Eşleşmeyenler çağırana veriliyor ki kaydedebilsin (RecordUnmappedGroups)
// ve yönetici neyi eşlemediğini görebilsin.
func (s *Store) RolesForGroups(ctx context.Context, groups []string) (roles, unmapped []string, err error) {
	roleSet := map[string]struct{}{}
	unmapped = make([]string, 0)

	for _, g := range groups {
		rows, qerr := s.db.QueryContext(ctx, `
			SELECT r.name
			FROM group_mappings gm
			JOIN roles r ON r.id = gm.role_id
			WHERE gm.external_group = ?;`, g)
		if qerr != nil {
			return nil, nil, translateErr("store.RolesForGroups", qerr)
		}

		found := false
		for rows.Next() {
			var name string
			if serr := rows.Scan(&name); serr != nil {
				rows.Close()
				return nil, nil, translateErr("store.RolesForGroups", serr)
			}
			roleSet[name] = struct{}{}
			found = true
		}
		rerr := rows.Err()
		rows.Close()
		if rerr != nil {
			return nil, nil, translateErr("store.RolesForGroups", rerr)
		}
		if !found {
			unmapped = append(unmapped, g)
		}
	}

	roles = make([]string, 0, len(roleSet))
	for r := range roleSet {
		roles = append(roles, r)
	}
	sort.Strings(roles)
	sort.Strings(unmapped)
	return roles, unmapped, nil
}

// RecordUnmappedGroups, eşlenmemiş grupları teşhis tablosuna işler.
//
// Hata döndürmez: bu bir teşhis kaydı, girişi düşürmesi için sebep yok.
// Sorun çıkarsa çağıran loglar.
func (s *Store) RecordUnmappedGroups(ctx context.Context, groups []string) error {
	now := time.Now().Unix()
	for _, g := range groups {
		if _, err := s.db.ExecContext(ctx, `
			INSERT INTO unmapped_groups (name, last_seen, seen_count)
			VALUES (?, ?, 1)
			ON CONFLICT(name) DO UPDATE SET
				last_seen = excluded.last_seen,
				seen_count = unmapped_groups.seen_count + 1;`, g, now); err != nil {
			return translateErr("store.RecordUnmappedGroups", err)
		}
	}
	return nil
}

// UnmappedGroup, teşhis listesindeki bir kayıt.
type UnmappedGroup struct {
	Name      string
	LastSeen  time.Time
	SeenCount int
}

// UnmappedGroups, eşlenmemiş grupları en çok görülenden aza doğru döner.
func (s *Store) UnmappedGroups(ctx context.Context) ([]UnmappedGroup, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT name, last_seen, seen_count
		FROM unmapped_groups
		ORDER BY seen_count DESC, name;`)
	if err != nil {
		return nil, translateErr("store.UnmappedGroups", err)
	}
	defer rows.Close()

	out := make([]UnmappedGroup, 0)
	for rows.Next() {
		var g UnmappedGroup
		var lastSeen int64
		if err := rows.Scan(&g.Name, &lastSeen, &g.SeenCount); err != nil {
			return nil, translateErr("store.UnmappedGroups", err)
		}
		g.LastSeen = time.Unix(lastSeen, 0)
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, translateErr("store.UnmappedGroups", err)
	}
	return out, nil
}

// ProvisionRequest, JIT sağlama için kimlik sağlayıcıdan gelen bilgi.
type ProvisionRequest struct {
	// Username, IdP'nin verdiği kullanıcı adı — aynı zamanda hedeflerdeki
	// hesap adı olacak (os_user). Kurumsal ortamda "isim.soyisim".
	Username string
	Email    string
	// Groups, IdP'nin bildirdiği ham grup adları.
	Groups []string
}

// ProvisionUser, IdP kimliğinden kullanıcıyı oluşturur/günceller ve SSO
// rollerini senkronize eder. Dönen değer yetkileriyle birlikte kullanıcıdır.
//
// SÖZLEŞME: hiçbir grup role eşleşmiyorsa kullanıcı OLUŞTURULMAZ ve
// ErrAccessDenied döner. "IdP'de hesabın olması postern'de hesabın olması
// demek değil" kuralının JIT çağındaki hâli — sadece "elle ekle" yerine
// "grubunu eşle" oldu. Yan faydası: users tablosu IdP'nin tüm dizinine
// dönüşmez, yalnızca gerçekten erişimi olanları içerir.
//
// Var olan kullanıcı için: eşleşme kalmadıysa kullanıcı SİLİNMEZ (denetim
// kaydı ona bağlı) ama SSO rolleri temizlenir — erişim biter, iz kalır.
func (s *Store) ProvisionUser(ctx context.Context, req ProvisionRequest) (model.User, error) {
	roles, unmapped, err := s.RolesForGroups(ctx, req.Groups)
	if err != nil {
		return model.User{}, err
	}

	// Teşhis kaydı: yönetici neyi eşlemediğini görsün. Hatası girişi
	// düşürmez, çağıran loglar.
	if len(unmapped) > 0 {
		if rerr := s.RecordUnmappedGroups(ctx, unmapped); rerr != nil {
			return model.User{}, rerr
		}
	}

	existing, err := s.User(ctx, req.Username)
	switch {
	case err == nil:
		// Var olan kullanıcı: e-posta değişmiş olabilir, güncelle.
		if req.Email != "" && !strings.EqualFold(req.Email, existing.Name) {
			if serr := s.SetUserEmail(ctx, req.Username, req.Email); serr != nil &&
				!errors.Is(serr, ErrConflict) {
				return model.User{}, serr
			}
		}
	case errors.Is(err, ErrNotFound):
		// Yeni kullanıcı: yalnızca en az bir rol eşleşiyorsa yarat.
		if len(roles) == 0 {
			return model.User{}, fmt.Errorf("store.ProvisionUser[%s]: %w", req.Username, ErrAccessDenied)
		}
		if _, cerr := s.CreateUser(ctx, req.Username, req.Email, req.Username); cerr != nil {
			return model.User{}, cerr
		}
		// JIT kullanıcılar SSO'ya bağlı doğar: anahtarla giriş yapamaz,
		// yani IdP'de kapatılınca erişimi gerçekten biter.
		if serr := s.SetUserSSOOnly(ctx, req.Username, true); serr != nil {
			return model.User{}, serr
		}
	default:
		return model.User{}, err
	}

	if serr := s.SyncRoles(ctx, req.Username, roles); serr != nil {
		return model.User{}, serr
	}

	return s.User(ctx, req.Username)
}

// SetUserSSOOnly, kullanıcının yalnızca kimlik sağlayıcı üzerinden
// girebilmesini açar/kapatır. Kullanıcı yoksa ErrNotFound.
func (s *Store) SetUserSSOOnly(ctx context.Context, username string, ssoOnly bool) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET sso_only = ? WHERE username = ?;`, ssoOnly, username)
	if err != nil {
		return translateErr("store.SetUserSSOOnly", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return translateErr("store.SetUserSSOOnly", err)
	}
	if n == 0 {
		return fmt.Errorf("store.SetUserSSOOnly: %w", ErrNotFound)
	}
	return nil
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
// Anahtar yapılandırılmamışken şifreli bir ayara dokunmak AÇIK hata
// verir: boş string dönmek sırrı silinmiş gibi gösterir ve LDAP'ın
// parolasız bağlanmaya çalışmasına yol açardı.
func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	var value string
	var encrypted bool

	err := s.db.QueryRowContext(ctx,
		`SELECT value, encrypted FROM settings WHERE key = ?;`, key).Scan(&value, &encrypted)
	if err != nil {
		return "", translateErr("store.Setting", err)
	}

	if !encrypted {
		return value, nil
	}

	// Anahtar yokken boş string dönmek, sırrı SİLİNMİŞ gibi gösterir ve
	// LDAP'ın parolasız bağlanmaya çalışmasına yol açardı. Açık hata.
	if s.box == nil {
		return "", fmt.Errorf("store.Setting[%s]: secret key not configured", key)
	}

	plain, err := s.box.Unseal(value)
	if err != nil {
		return "", fmt.Errorf("store.Setting[%s]: %w", key, err)
	}
	return plain, nil
}

// SetSetting, ayarı yazar. encrypt=true ise değer mühürlenerek saklanır.
//
// encrypt=true iken anahtar yoksa REDDEDİLİR — düz metin yazıp
// "şifreledim" sanmak bu paketin bütün amacını sessizce boşa çıkarır.
func (s *Store) SetSetting(ctx context.Context, key, value string, encrypt bool, actor string) error {
	stored := value
	if encrypt {
		// Düz metin yazıp "şifreledim" sanmak bu paketin bütün amacını
		// sessizce boşa çıkarır: anahtar yoksa REDDET.
		if s.box == nil {
			return fmt.Errorf("store.SetSetting[%s]: secret key not configured", key)
		}
		sealed, err := s.box.Seal(value)
		if err != nil {
			return fmt.Errorf("store.SetSetting[%s]: %w", key, err)
		}
		stored = sealed
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO settings (key, value, encrypted, updated_at, updated_by)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET
			value = excluded.value,
			encrypted = excluded.encrypted,
			updated_at = excluded.updated_at,
			updated_by = excluded.updated_by;`,
		key, stored, encrypt, time.Now().Unix(), actor)
	if err != nil {
		return translateErr("store.SetSetting", err)
	}
	return nil
}

// Settings, ada göre sıralı ayar listesi döner — ŞİFRELİ DEĞERLER
// MASKELENMİŞ olarak.
//
// ⚠️ Bu fonksiyonun çıktısı admin API'sine gidiyor: şifreli bir ayarın
// değeri ASLA dönmez, maskelenir. Sır yazılır ama okunmaz.
func (s *Store) Settings(ctx context.Context) ([]SettingView, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT key, value, encrypted, updated_at, updated_by
		FROM settings
		ORDER BY key;`)
	if err != nil {
		return nil, translateErr("store.Settings", err)
	}
	defer rows.Close()

	out := make([]SettingView, 0)
	for rows.Next() {
		var v SettingView
		var value string
		var updatedAt int64

		if err := rows.Scan(&v.Key, &value, &v.Secret, &updatedAt, &v.UpdatedBy); err != nil {
			return nil, translateErr("store.Settings", err)
		}
		v.UpdatedAt = time.Unix(updatedAt, 0)

		// ⚠️ Şifreli değer BURADAN ÇIKMAZ. Bu liste admin API'sine
		// gidiyor; sır yazılır ama okunmaz. Maske boş bırakılmıyor ki
		// arayüz "değer var" ile "değer yok"u ayırt edebilsin.
		if v.Secret {
			v.Value = secretMask
		} else {
			v.Value = value
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, translateErr("store.Settings", err)
	}
	return out, nil
}

// secretMask, şifreli ayarların listede göründüğü değer.
const secretMask = "********"

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
	       u.sso_only,
	       r.name AS role_name,
	       t.name AS target_name
		FROM users u
		LEFT JOIN user_roles   ur ON ur.user_id = u.id
		                         AND (ur.expires_at IS NULL OR ur.expires_at > ?)
		LEFT JOIN roles        r  ON r.id       = ur.role_id
		LEFT JOIN role_targets rt ON rt.role_id = r.id
		LEFT JOIN targets      t  ON t.id       = rt.target_id
		ORDER BY u.username, r.name, t.name;
	`

	rows, err := s.db.QueryContext(ctx, queryStr, time.Now().Unix())
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
		var admin, ssoOnly bool
		var rawRole, rawTarget sql.NullString

		if err := rows.Scan(&name, &osUser, &admin, &ssoOnly, &rawRole, &rawTarget); err != nil {
			return nil, translateErr("store.Users", err)
		}

		ui, ok := userIndex[name]
		if !ok {
			users = append(users, model.User{Name: name, OSUser: osUser, Admin: admin, SSOOnly: ssoOnly, Roles: make([]model.Role, 0)})
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
