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
)

var (
	// ErrNotFound, aranan kaydın olmadığını söyler.
	ErrNotFound = errors.New("store: not found")

	// ErrConflict, benzersizlik kısıtının ihlal edildiğini söyler
	// (aynı adla ikinci bir kullanıcı, rol, hedef...).
	ErrConflict = errors.New("store: already exists")
)

type Store struct {
	db *sql.DB
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
		var rawRole, rawTarget sql.NullString

		if err := rows.Scan(&scannedName, &scannedOSUser, &rawRole, &rawTarget); err != nil {
			return model.User{}, translateErr("store.User", err)
		}

		if !found {
			found = true
			user.Name = scannedName
			user.OSUser = scannedOSUser
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

func (s *Store) AssignRole(ctx context.Context, username, roleName string) error {
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
		var rawRole, rawTarget sql.NullString

		if err := rows.Scan(&name, &osUser, &rawRole, &rawTarget); err != nil {
			return nil, translateErr("store.Users", err)
		}

		ui, ok := userIndex[name]
		if !ok {
			users = append(users, model.User{Name: name, OSUser: osUser, Roles: make([]model.Role, 0)})
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
