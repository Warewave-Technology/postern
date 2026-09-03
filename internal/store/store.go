package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/secret"
)

var (
	// ErrNotFound, aranan kaydın olmadığını söyler.
	ErrNotFound = errors.New("store: not found")

	// ErrConflict, benzersizlik kısıtının ihlal edildiğini söyler
	// (aynı adla ikinci bir kullanıcı, rol, hedef...).
	ErrConflict = errors.New("store: already exists")

	// ErrInvalid: değerin kendisi kabul edilebilir değil — çağıranın
	// yeniden denemesi değil, DÜZELTMESİ gerekiyor. ErrConflict'ten
	// ayrı, çünkü "zaten var" ile "böyle olamaz" farklı cevaplar
	// gerektiriyor (409'a karşı 400).
	ErrInvalid = errors.New("store: invalid value")

	// ErrAccessDenied: kimlik geçerli ama postern'de karşılığı yok —
	// JIT sağlamada hiçbir grup role eşleşmediğinde.
	ErrAccessDenied = errors.New("store: access denied")

	// ErrIdentityConflict: kullanıcı adı var olan bir hesapla eşleşiyor
	// ama o hesap BAŞKA bir IdP kimliğine bağlı.
	//
	// ErrAccessDenied'dan AYRI TUTULUYOR çünkü ikisi operatöre bambaşka
	// şeyler söyler. "Grup eşlenmemiş" bir yapılandırma eksiğidir; bu
	// ise kullanıcı adı geri dönüşümü ya da hesap devralma denemesidir
	// — incelenmesi gereken bir olay. Tek bir sentinel altında
	// toplandığında giriş reddi "no mapped groups" diye loglanıyordu ve
	// olayı araştıran yönetici, düzeltmeyecek bir eşlemeyi düzeltmeye
	// gönderiliyordu.
	//
	// İstemciye giden yanıt İKİSİNDE DE aynı: ayrım yalnızca logda.
	ErrIdentityConflict = errors.New("store: identity conflict")

	/*
	 * ErrAdminBindRefused: adı eşleşen bir YÖNETİCİ hesabını, ilk kez
	 * görülen bir kimliğe bağlama denemesi.
	 *
	 * ErrIdentityConflict'ten AYRI, çünkü operatörün yapacağı şey
	 * farklı: orada bir devralma denemesi var ve incelenmeli; burada
	 * meşru bir yönetici de olabilir ve yolu açık — yöneticiliği
	 * geçici olarak kaldırıp bağlaması yeterli. Aynı sentinel altında
	 * toplansaydı, ikisi de "incelenecek olay" diye loglanır ve
	 * gerçekten incelenmesi gereken seyrek olay gürültüye karışırdı.
	 */
	ErrAdminBindRefused = errors.New("store: administrator account cannot be claimed by username")

	/*
	 * ErrAccountNotProvisioned: kimlik doğrulandı, postern hesabı yok ve
	 * hesapların kendiliğinden açılması KAPALI.
	 *
	 * ⚠️ ErrAccessDenied'dan AYRI, çünkü çağıranın yapacağı şey farklı:
	 * orada kapı kapanıyor, burada kişi onay kuyruğuna yazılıyor ve
	 * bunu ekranda görüyor. Tek sentinel altında toplansalardı kuyruk
	 * hiç dolmazdı.
	 */
	ErrAccountNotProvisioned = errors.New("store: account does not exist and auto-create is off")

	/*
	 * ErrAdminPasswordRefused: yönetici hesabına kullanıcı parolası
	 * konmak istendi.
	 *
	 * ⚠️ KURALI VERİTABANI TUTUYOR (göç 026), bu sentinel yalnızca onun
	 * reddini konuşulabilir bir hataya çeviriyor. Burada bir `if`
	 * yazmıyoruz: kural bir kez, kaçınılmaz olduğu yerde duruyor.
	 *
	 * Neden kural: acil durum kapısı tahmin edilebilir bir değere
	 * bağlanamaz. Yönetici hesabının kimlik bilgisi makine üretimi
	 * kalmak zorunda — postern'in "her şey bozulduğunda içeri girilir"
	 * iddiası tam olarak buna dayanıyor.
	 */
	ErrAdminPasswordRefused = errors.New("store: an administrator account cannot hold a password")

	// errNotImplementedS51, S5.1 iskeletinin bekleyen fonksiyonları.
	errNotImplementedS51 = errors.New("store: not implemented")

	// errNotImplementedS33, S3.3 iskeletinin bekleyen fonksiyonları.
	errNotImplementedS33 = errors.New("store: not implemented")
)

type Store struct {
	db *sql.DB

	// box, şifreli ayarları açan anahtar. nil olabilir — bkz. UseSecretBox.
	box *secret.Box

	// searchTimeout, denetim aramalarının sunucu tarafı sınırı.
	// Sıfır = searchtimeout.go'daki varsayılan; yalnızca testler
	// değiştiriyor (SetSearchTimeoutForTest).
	searchTimeout time.Duration
}

func Open(ctx context.Context, conn string) (*Store, error) {
	connStr, err := dsn(conn)
	if err != nil {
		return nil, fmt.Errorf("store.Open: %w", err)
	}

	db, err := sql.Open(driverName, connStr)
	if err != nil {
		return nil, fmt.Errorf("store.Open: %w", err)
	}

	// Havuz ayarları. SQLite'ta anlamsızdı (tek dosya, tek yazar);
	// PostgreSQL'de ayarlanmazsa database/sql sınırsız bağlantı açar ve
	// sunucunun max_connections'ını tüketmek mümkün.
	//
	// 25/5, "bir bastion aynı anda kaç sorgu koşturur" sorusuna göre
	// seçildi: iş yükü oturum açılış/kapanışları ve panel istekleri —
	// uzun süren analitik sorgu yok.
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	// Bağlantıları döndürmek, arada duran bir yük dengeleyicinin sessizce
	// düşürdüğü bağlantılarla çalışmayı önler.
	db.SetConnMaxLifetime(30 * time.Minute)

	if err := db.PingContext(ctx); err != nil {
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

/*
 * refuseBadOSUser, hedeflerdeki hesap adını YAZMADAN ÖNCE eler.
 *
 * ⚠️ ÖLÇÜLEN ARIZA: kural yalnızca politika kapısındaydı, yazma
 * yollarında yoktu. Sonuç, "kurulmuş görünüp her oturumda reddedilen"
 * hesaplardı: JIT sağlama os_user'ı IdP kullanıcı adından birebir
 * alıyor (ProvisionUser -> CreateUser(..., req.Username)), Entra ID ise
 * preferred_username'e UPN koyuyor. "yigit@corp.com" desene uymuyor.
 * Hesap açılıyor, roller veriliyor, panelde hedef kartları görünüyor —
 * ve her bağlantı "access denied" ile düşüyor. Sebebi açıklayan tek
 * cümle ("OSUser name violation") yalnızca bastion'ın log'unda.
 *
 * ⚠️ RET, GİRİŞ ANINDA VE GÜRÜLTÜLÜ OLMALI. Bu yüzden kontrol
 * CreateUser'da: yeni bir çağıran eklendiğinde kuralı hatırlaması
 * gerekmesin diye kapı, tabloya yazan yerin kendisinde.
 *
 * ⚠️ NORMALLEŞTİRMİYORUZ. "yigit@corp.com" -> "yigit" cazip ama
 * a@x.com ile a@y.com'u aynı hesaba çarptırırdı; iki insanı tek
 * principal'da birleştirmek, bu projenin (iss,sub) ile bağlama
 * kararının tam tersi olurdu.
 */
func refuseBadOSUser(op, osUser string) error {
	if model.ValidOSUserName(osUser) {
		return nil
	}
	return fmt.Errorf("%s: %q is not a usable account name on targets "+
		"(lowercase letter or _ first, then letters, digits, _ . -, at most 32); "+
		"create the account explicitly with a valid os-user: %w",
		op, osUser, ErrInvalid)
}

func (s *Store) CreateUser(ctx context.Context, username, email, osUser string) (string, error) {
	if err := refuseBadOSUser("store.CreateUser", osUser); err != nil {
		return "", err
	}

	userID, err := newID()
	if err != nil {
		return "", fmt.Errorf("store.CreateUser: %w", err)
	}

	userEmail := sql.NullString{String: email, Valid: email != ""}

	queryStr := `
		INSERT INTO users (id, username, email, os_user, created_at)
		VALUES ($1, $2, $3, $4, $5);
	`

	if _, err = s.db.ExecContext(ctx, queryStr, userID, username, userEmail, osUser, time.Now().Unix()); err != nil {
		return "", translateErr("store.CreateUser", err)
	}

	return userID, nil
}

func (s *Store) User(ctx context.Context, username string) (model.User, error) {
	var user model.User
	// #nosec G202 -- birleştirilen parça sabit (dialect.go); değerler $N ile gidiyor
	queryStr := `
		SELECT u.username,
	       u.os_user,
	       u.is_admin,
	       u.sso_only,
	       (u.dir_subject IS NOT NULL) AS dir_bound,
	       r.name AS role_name,
	       t.name AS target_name
		FROM users u
		-- ⚠️ Süre filtresi JOIN koşulunda, WHERE'de DEĞİL: WHERE'e
		-- koysaydık süresi dolmuş tek rolü olan kullanıcı satır
		-- üretmez ve "kullanıcı yok" gibi görünürdü. JOIN koşulu
		-- yalnızca eşleşmeyi düşürür, kullanıcıyı değil.
		LEFT JOIN user_roles   ur ON ur.user_id = u.id
		                         AND (ur.expires_at IS NULL OR ur.expires_at > $1)
		LEFT JOIN roles        r  ON r.id       = ur.role_id
		LEFT JOIN role_targets rt ON rt.role_id = r.id
		LEFT JOIN targets      t  ON t.id       = rt.target_id
		WHERE ` + ciEq("u.username", "$2") + `
		ORDER BY r.name, ` + ciOrder("t.name") + `;
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
		var scannedAdmin, scannedSSOOnly, scannedDirBound bool
		var rawRole, rawTarget sql.NullString

		if err := rows.Scan(&scannedName, &scannedOSUser, &scannedAdmin, &scannedSSOOnly,
			&scannedDirBound, &rawRole, &rawTarget); err != nil {
			return model.User{}, translateErr("store.User", err)
		}

		if !found {
			found = true
			user.Name = scannedName
			user.OSUser = scannedOSUser
			user.Admin = scannedAdmin
			user.SSOOnly = scannedSSOOnly
			user.DirBound = scannedDirBound
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
		VALUES ($1, $2);
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
		VALUES ($1, $2, $3, $4, $5);
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
		WHERE ` + ciEq("name", "$1") + `;
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

	// #nosec G202 -- birleştirilen parça sabit (dialect.go); değerler $N ile gidiyor
	queryStr := `
		SELECT name, host, port, host_key
		FROM targets
		ORDER BY ` + ciOrder("name") + `;
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
	// rows KAPANDIKTAN sonra: aynı bağlantı üzerinde açık bir sonuç
	// kümesi dururken ikinci sorgu açmak, havuzdan fazladan bağlantı
	// tutmak demek.
	rows.Close()

	// Etiketler TEK sorguyla: hedef başına ayrı sorgu, elli hedefli bir
	// listede elli gidiş dönüş olurdu (N+1).
	labels, err := s.allTargetLabels(ctx)
	if err != nil {
		return nil, err
	}
	for i := range targets {
		targets[i].Labels = labels[targets[i].Name]
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
		VALUES ($1, $2, 'manual', $3)
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
		WHERE ` + ciEq("name", "$1") + `;
	`

	var roleID string
	queryRoleStr := `
		SELECT id
		FROM roles
		WHERE name=$1;
	`

	err := s.db.QueryRowContext(ctx, queryTargetStr, targetName).Scan(&targetID)
	if err != nil {
		return translateErr("store.GrantTarget", err)
	}

	err = s.db.QueryRowContext(ctx, queryRoleStr, roleName).Scan(&roleID)
	if err != nil {
		return translateErr("store.GrantTarget", err)
	}

	if _, err = s.db.ExecContext(ctx, `INSERT INTO role_targets (role_id, target_id) VALUES ($1, $2) ON CONFLICT(role_id, target_id) DO NOTHING;`, roleID, targetID); err != nil {
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
		`INSERT INTO admin_log (at, actor, via, action, entity, details) VALUES ($1, $2, $3, $4, $5, $6);`,
		at.Unix(), e.Actor, e.Via, e.Action, e.Entity, e.Details)
	if err != nil {
		return translateErr("store.LogAdmin", err)
	}
	return nil
}

// AdminLog, defteri YENİDEN ESKİYE döner. limit<=0 sınırsız.
func (s *Store) AdminLog(ctx context.Context, limit int) ([]AdminLogEntry, error) {
	// id ikincil sıralama: aynı saniyeye düşen kayıtlar (bir formda arka
	// arkaya yapılan işlemler) deterministik ve ekleme sırasında kalsın.
	// #nosec G202 -- birleştirilen parça sabit (dialect.go); değerler $N ile gidiyor
	rows, err := s.db.QueryContext(ctx, `
		SELECT at, actor, via, action, entity, details
		FROM admin_log
		ORDER BY at DESC, id DESC`+limitClause(limit, "$1")+`;`,
		limitArgs(limit)...)
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
	// #nosec G202 -- birleştirilen parça sabit (dialect.go); değerler $N ile gidiyor
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.name, t.name
		FROM roles r
		LEFT JOIN role_targets rt ON rt.role_id = r.id
		LEFT JOIN targets      t  ON t.id       = rt.target_id
		ORDER BY r.name, `+ciOrder("t.name")+`;`)
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
	cond := column + " = $1"
	if ciColumns[table+"."+column] {
		cond = ciEq(column, "$1")
	}

	var id string
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM `+table+` WHERE `+cond+`;`, value).Scan(&id)
	if err != nil {
		return "", translateErr(op, err)
	}
	return id, nil
}

// DeleteTarget, hedefi ve rol bağlarını (CASCADE) kaldırır. Yoksa
// ErrNotFound; oturum kaydı varsa ErrConflict — denetim kaydı olan varlık
// silinmez, bu bir kısıt değil özellik (ayrıntı: isFKRestrict).
func (s *Store) DeleteTarget(ctx context.Context, name string) error {
	id, err := s.rowID(ctx, "store.DeleteTarget", "targets", "name", name)
	if err != nil {
		return err
	}

	if _, err := s.db.ExecContext(ctx, `DELETE FROM targets WHERE id = $1;`, id); err != nil {
		if isRestrictViolation(err) {
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

	if _, err := s.db.ExecContext(ctx, `DELETE FROM roles WHERE id = $1;`, id); err != nil {
		if isRestrictViolation(err) {
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

	if _, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1;`, id); err != nil {
		if isRestrictViolation(err) {
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
		`DELETE FROM user_roles WHERE user_id = $1 AND source = 'sso';`, userID); err != nil {
		return translateErr("store.SyncRoles", err)
	}

	for _, name := range roleNames {
		// Bilinmeyen rol: ATLA. Rol adları group_mappings'ten geliyor ve
		// bir eşleme silinmiş olabilir; yönetici hatası yüzünden
		// kullanıcının girişini reddetmek yanlış olurdu.
		var roleID string
		err := tx.QueryRowContext(ctx, `SELECT id FROM roles WHERE name = $1;`, name).Scan(&roleID)
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
			VALUES ($1, $2, 'sso', NULL)
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
		VALUES ($1, $2, $3, $4, $5);`,
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
		// #nosec G202 -- birleştirilen parça sabit (dialect.go); değerler $N ile gidiyor
		`DELETE FROM group_mappings WHERE `+ciEq("external_group", "$1")+` AND role_id = $2;`,
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
	// #nosec G202 -- birleştirilen parça sabit (dialect.go); değerler $N ile gidiyor
	rows, err := s.db.QueryContext(ctx, `
		SELECT gm.external_group, r.name, gm.created_at, gm.created_by
		FROM group_mappings gm
		JOIN roles r ON r.id = gm.role_id
		ORDER BY `+ciOrder("gm.external_group")+`, r.name;`)
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
		// #nosec G202 -- birleştirilen parça sabit (dialect.go); değerler $N ile gidiyor
		rows, qerr := s.db.QueryContext(ctx, `
			SELECT r.name
			FROM group_mappings gm
			JOIN roles r ON r.id = gm.role_id
			WHERE `+ciEq("gm.external_group", "$1")+`;`, g)
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
			VALUES ($1, $2, 1)
			ON CONFLICT (lower(name)) DO UPDATE SET
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
	// #nosec G202 -- birleştirilen parça sabit (dialect.go); değerler $N ile gidiyor
	rows, err := s.db.QueryContext(ctx, `
		SELECT name, last_seen, seen_count
		FROM unmapped_groups
		ORDER BY seen_count DESC, `+ciOrder("name")+`;`)
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

	/*
	 * GroupsResolved, grupların GERÇEKTEN öğrenilip öğrenilmediği.
	 *
	 * ⚠️ SIFIR DEĞERİ false VE BU KASITLI. false iken SSO rollerine
	 * HİÇ DOKUNULMAZ. Alanı doldurmayı unutan bir çağrı yolu, rolleri
	 * TAZELEMEMİŞ olur — rolleri SİLMİŞ değil. İki yanlıştan geri
	 * dönülebilir olanı bu.
	 *
	 * Neden gerekti: kaynak "kullanıcıyı bulamadım" dediğinde de boş
	 * bir grup listesi geliyordu ve buradaki kod onu "hiçbir gruba üye
	 * değil" diye okuyup bütün SSO rollerini siliyordu. Giriş yolunda
	 * ne bekleme süresi ne tavan var; senkronizasyon döngüsündeki
	 * korumaların hiçbiri burada çalışmıyor.
	 */
	GroupsResolved bool

	// Issuer ve Subject, IdP kimliğinin KALICI anahtarı (OIDC "iss" ve
	// "sub"). Username DEĞİL bunlar eşleştirme anahtarıdır: username
	// birçok sağlayıcıda değiştirilebilir ve geri dönüştürülebilir.
	// Boş bırakılırsa eşleştirme yapılamaz ve ProvisionUser reddeder.
	Issuer  string
	Subject string

	/*
	 * AdminGroupMember, GELEN KİMLİĞİN kendisinin yönetici grubunda
	 * olduğu.
	 *
	 * ⚠️ Adı bir yöneticiyle eşleşen hesabı devralmanın önündeki kapıyı
	 * bu açıyor — ve açması doğru: yönetici grubunda olan kişi zaten
	 * yöneticidir, başka bir yönetici hesabını almakla YENİ bir yetki
	 * kazanmaz. Kapatsaydık, dizin grubundan yönetici olan herkes
	 * yükseltmeden sonra kendi hesabına giremezdi.
	 *
	 * ⚠️ Çağıran bunu YALNIZCA grupları gerçekten çözülmüşken true
	 * yapmalı. Sıfır değeri false ve bu kasıtlı: alanı doldurmayı
	 * unutan bir yol, kapıyı AÇMIŞ değil KAPATMIŞ olur.
	 */
	AdminGroupMember bool

	/*
	 * AutoCreate, hesabın KENDİLİĞİNDEN açılabileceği.
	 *
	 * ⚠️ Sıfır değeri false ve bu kasıtlı: alanı doldurmayı unutan bir
	 * çağrı yolu hesap AÇMAZ, açar değil. İki yanlıştan geri
	 * dönülebilir olanı bu.
	 *
	 * Kapalıyken kullanıcı ErrAccountNotProvisioned alıyor ve çağıran
	 * onu onay kuyruğuna yazıyor — kapıda bırakmıyor.
	 */
	AutoCreate bool
}

/*
 * consumeBindConsent, yönetici hesabı için verilmiş TEK KULLANIMLIK
 * bağlama iznini harcar.
 *
 * ⚠️ Okuma ve silme TEK ifadede: iki adıma bölünseydi, aynı anda gelen
 * iki giriş denemesi aynı izni tüketebilir ve izin BİR kez verilmişken
 * İKİ hesap bağlanabilirdi.
 */
func (s *Store) consumeBindConsent(ctx context.Context, username string) (bool, error) {
	// RETURNING yeni satırı verir (yani NULL); önemli olan SATIRIN
	// dönüp dönmediği — dönmüşse izin vardı ve şu an harcandı.
	var touched string
	err := s.db.QueryRowContext(ctx, `
		UPDATE users SET bind_consent_at = NULL
		WHERE username = $1 AND bind_consent_at IS NOT NULL
		RETURNING username;`, username).Scan(&touched)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, translateErr("store.consumeBindConsent", err)
	}
	return true, nil
}

// AllowIdentityBind, bir yönetici hesabının SIRADAKİ kimlik bağlamasına
// izin verir. Tek kullanımlık.
func (s *Store) AllowIdentityBind(ctx context.Context, username string, at time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET bind_consent_at = $1 WHERE username = $2;`, at.Unix(), username)
	if err != nil {
		return translateErr("store.AllowIdentityBind", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store.AllowIdentityBind[%s]: %w", username, ErrNotFound)
	}
	return nil
}

// hasIdPIdentity, hesabın bir IdP kimliğine BAĞLI olup olmadığı.
//
// "Bağlı değil" ile "yok" ayrımı çağıranın işi: burada kullanıcı zaten
// bulunmuş oluyor.
func (s *Store) hasIdPIdentity(ctx context.Context, username string) (bool, error) {
	var subject sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT idp_subject FROM users WHERE `+ciEq("username", "$1")+`;`, username).Scan(&subject)
	if err != nil {
		return false, translateErr("store.hasIdPIdentity", err)
	}
	return subject.Valid, nil
}

// UserByIdPSubject, (issuer, subject) çiftine bağlı kullanıcıyı döner.
func (s *Store) UserByIdPSubject(ctx context.Context, issuer, subject string) (model.User, error) {
	var username string
	err := s.db.QueryRowContext(ctx,
		`SELECT username FROM users WHERE idp_issuer = $1 AND idp_subject = $2;`,
		issuer, subject).Scan(&username)
	if err != nil {
		return model.User{}, translateErr("store.UserByIdPSubject", err)
	}
	return s.User(ctx, username)
}

// BindIdPSubject, bir postern hesabını bir IdP kimliğine bağlar.
//
// SADECE HENÜZ BAĞLI DEĞİLSE: WHERE koşulu idp_subject IS NULL. Var
// olan bir bağı sessizce değiştirmek, tam olarak önlemeye çalıştığımız
// devralmayı geri getirirdi. Zaten bağlıysa ErrConflict.
func (s *Store) BindIdPSubject(ctx context.Context, username, issuer, subject string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE users SET idp_issuer = $1, idp_subject = $2
		WHERE username = $3 AND idp_subject IS NULL;`, issuer, subject, username)
	if err != nil {
		return translateErr("store.BindIdPSubject", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return translateErr("store.BindIdPSubject", err)
	}
	if n == 0 {
		// Ya kullanıcı yok ya da BAŞKA bir kimliğe bağlı. İkisi de
		// "buradan devam etme" demek.
		return fmt.Errorf("store.BindIdPSubject[%s]: %w", username, ErrConflict)
	}
	return nil
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
	var roles, unmapped []string
	if req.GroupsResolved {
		var err error
		// ⚠️ Kaynak cevap verdi ama hiç grup söylemediyse `unknown`.
		// Onsuz, grup claim'i göndermeyen bir IdP'de HİÇ KİMSE hesap
		// açamıyordu (aşağıdaki ErrAccessDenied) ve yöneticinin bunu
		// düzeltecek bir tutamağı yoktu.
		roles, unmapped, err = s.RolesForGroups(ctx, model.ResolvedGroups(req.Groups))
		if err != nil {
			return model.User{}, err
		}
	}

	// Teşhis kaydı: yönetici neyi eşlemediğini görsün. Hatası girişi
	// düşürmez, çağıran loglar.
	if len(unmapped) > 0 {
		if rerr := s.RecordUnmappedGroups(ctx, unmapped); rerr != nil {
			return model.User{}, rerr
		}
	}

	// ⚠️ EŞLEŞTİRME ÖNCE (issuer, subject) İLE.
	//
	// Bu sıra bir güvenlik açığının düzeltilmesidir. Eskiden yalnızca
	// username ile eşleştiriliyordu ve username preferred_username
	// claim'inden geliyor — birçok sağlayıcıda kullanıcının kendi
	// değiştirebildiği bir alan. Adını var olan bir postern kullanıcısı
	// yapan herkes o hesabı rolleriyle ve is_admin bayrağıyla
	// devralıyordu.
	if req.Issuer == "" || req.Subject == "" {
		return model.User{}, fmt.Errorf(
			"store.ProvisionUser[%s]: identity carries no issuer/subject: %w",
			req.Username, ErrAccessDenied)
	}

	bound, berr := s.UserByIdPSubject(ctx, req.Issuer, req.Subject)
	if berr != nil && !errors.Is(berr, ErrNotFound) {
		return model.User{}, berr
	}
	if berr == nil {
		// Bu IdP kimliği zaten bir hesaba bağlı. Kullanıcı adı IdP'de
		// değişmiş olabilir — sorun değil, aynı kişi.
		//
		// Roller YALNIZCA gruplar öğrenilebildiyse tazelenir. Aksi
		// hâlde hesap olduğu gibi dönüyor: kimlik doğrulandı, yetki
		// hakkında yeni bir şey öğrenmedik, o hâlde yetkiye
		// dokunmuyoruz. İptal kararı korumalı senkronizasyon
		// yolunundur.
		if req.GroupsResolved {
			if serr := s.SyncRoles(ctx, bound.Name, roles); serr != nil {
				return model.User{}, serr
			}
		}
		return s.User(ctx, bound.Name)
	}

	// Buradan sonrası YENİ bir karar: hesap açmak ya da var olan bir
	// hesabı bu kimliğe bağlamak. Grupları öğrenemediysek o kararı
	// verecek bilgi elimizde yok ve varsayılan REDDETMEK.
	if !req.GroupsResolved {
		return model.User{}, fmt.Errorf(
			"store.ProvisionUser[%s]: group membership could not be resolved: %w",
			req.Username, ErrAccessDenied)
	}

	existing, err := s.User(ctx, req.Username)
	switch {
	case err == nil:
		/*
		 * ⚠️ YÖNETİCİ HESABI AD EŞLEŞMESİYLE DEVRALINAMAZ.
		 *
		 * ÖLÇÜLEN SALDIRI (demo ortamında uçtan uca çalıştırıldı):
		 * "developers" grubundaki sıradan bir çalışan, IdP'de kendi
		 * preferred_username'ini "ops" yaptı ve OOB girişini
		 * çalıştırdı. Aşağıdaki bağlama başarılı oldu ve postern'in
		 * CLI yönetici hesabı — is_admin=true, admin_via='cli' —
		 * saldırganın kimliğine geçti. Ölçüm:
		 *
		 *   önce:  ops | admin=true | via=cli | idp_subject=YOK
		 *   sonra: ops | admin=true | via=cli | idp_subject=f4b15fbf-…
		 *
		 * Rol eşlemesi bunu DURDURMAZ ve durdurması da beklenmemeli:
		 * saldırgan kendi rollerini alıyor (developer), ama hesabın
		 * is_admin bayrağı hiçbir eşlemeden gelmiyor — CLI'dan ya da
		 * yönetici grubundan geliyor. Aşağıdaki len(roles)==0 kapısı
		 * da yalnızca YENİ hesap dalında; var olan bir hesabı
		 * devralmaya uygulanmıyor.
		 *
		 * ⚠️ Pencere 011'den beri bilerek açıktı (onboarding için) ve
		 * o gün is_admin yalnızca CLI'dan geliyordu. Yöneticiliğin
		 * gruptan da gelebilmesi (017), OIDC'ye hiç dokunmamış
		 * yönetici hesaplarının sayısını artırdı — yani pencerenin
		 * DEĞERİ arttı.
		 *
		 * Sıradan hesaplar için ilk bağlama hâlâ serbest: onboarding'i
		 * kırmadan, yalnızca yetkiyi taşıyan hesapları kapatıyoruz.
		 * Meşru bir yönetici bağlanacaksa yol açık ve iki komut:
		 * yöneticiliği geçici olarak kaldır, bir kez giriş yaptır,
		 * geri ver.
		 */
		/*
		 * ⚠️ YALNIZCA HENÜZ BAĞLANMAMIŞ hesaplar için.
		 *
		 * Hesap ZATEN başka bir kimliğe bağlıysa doğru cevap
		 * ErrIdentityConflict: orada bir devralma DENEMESİ var ve
		 * incelenmeli. Buradaki mesaj ise "yöneticiliği kaldır, giriş
		 * yaptır, geri ver" diyor — bağlı bir hesapta bu TAMAMEN
		 * yanlış tavsiye olurdu, çünkü sorun yöneticilik değil, adın
		 * başkasına ait olması. (Mevcut bir test bu sırayı yakaladı.)
		 */
		if cerr := s.claimExistingAccount(ctx, req.Username,
			req.Issuer, req.Subject, req.AdminGroupMember); cerr != nil {
			return model.User{}, cerr
		}

		if req.Email != "" && !strings.EqualFold(req.Email, existing.Name) {
			if serr := s.SetUserEmail(ctx, req.Username, req.Email); serr != nil &&
				!errors.Is(serr, ErrConflict) {
				return model.User{}, serr
			}
		}
	case errors.Is(err, ErrNotFound):
		/*
		 * ⚠️ OTOMATİK AÇILIŞ KAPALIYSA BURADA DURUYORUZ — rol
		 * kontrolünden ÖNCE.
		 *
		 * Kuyruk, "seni tanımıyoruz" hâlinin tamamı için: hiçbir grubu
		 * eşleşmeyen kişi de oraya düşmeli ki yönetici onaylayıp elle
		 * rol verebilsin. Rol kapısını önce uygulasaydık, tam da
		 * kuyruğun var olma sebebi olan nüfusu kapıda bırakırdık.
		 *
		 * ⚠️ Bu kontrol eskiden YALNIZCA dizin kapısındaydı: OIDC
		 * kurulumlarında ayar okunuyor ama hiçbir şey yapmıyordu, yani
		 * sihirbazın "kuyruğa al" seçeneği orada yalandı.
		 */
		if !req.AutoCreate {
			return model.User{}, fmt.Errorf(
				"store.ProvisionUser[%s]: %w", req.Username, ErrAccountNotProvisioned)
		}

		// Yeni kullanıcı: yalnızca en az bir rol eşleşiyorsa yarat.
		if len(roles) == 0 {
			return model.User{}, fmt.Errorf("store.ProvisionUser[%s]: %w", req.Username, ErrAccessDenied)
		}

		// ⚠️ OTOMATİK olarak ayrıcalıklı bir hesap adı üretme.
		//
		// JIT sağlamada os_user, IdP'nin preferred_username claim'inden
		// AYNEN alınıyor. Adını "postgres" ya da "backup" yapabilen bir
		// IdP kimliği, o hesabın adına sertifika istenmesine yol açar.
		//
		// Kontrol BURADA, policy'de değil: bir operatörün BİLEREK
		// "postgres" hesabına erişim vermesi meşru bir iş akışı (DBA
		// erişimi) ve `user modify --os-user` ile hâlâ mümkün. Yasak
		// olan, kimsenin karar vermediği OTOMATİK yol.
		//
		// Derinlik katmanı, tek savunma değil: asıl kapı hedefin
		// AuthorizedPrincipalsFile'ı ve postern onun yetkilendirmediği
		// bir principal'ı kullandıramaz.
		if reservedOSUsers[req.Username] {
			return model.User{}, fmt.Errorf(
				"store.ProvisionUser[%s]: refusing to auto-provision a reserved system account name; "+
					"create the account explicitly with a different os-user: %w",
				req.Username, ErrAccessDenied)
		}
		if _, cerr := s.CreateUser(ctx, req.Username, req.Email, req.Username); cerr != nil {
			return model.User{}, cerr
		}
		if berr := s.BindIdPSubject(ctx, req.Username, req.Issuer, req.Subject); berr != nil {
			return model.User{}, berr
		}
		// JIT kullanıcılar SSO'ya bağlı doğar: anahtarla giriş yapamaz,
		// yani IdP'de kapatılınca erişimi gerçekten biter.
		if serr := s.SetUserSSOOnly(ctx, req.Username, true); serr != nil {
			return model.User{}, serr
		}

		// ⚠️ OTOMATİK AÇILAN HESAP DA DENETİM SATIRI BIRAKMALI.
		//
		// Burası bir YETKİ VERME noktası: hesap açılıyor ve altındaki
		// SyncRoles rolleri — dolayısıyla hedef erişimini — veriyor.
		// CLI'dan yapılan aynı iş (user.create, role.grant) denetim
		// günlüğüne düşerken bu yol sessizdi: panelde günlüğe bakan bir
		// operatör, SSO ile gelip sysadmin olan kullanıcıları HİÇ
		// görmüyordu. Denetim izi ürünün kendisi olan bir sistemde,
		// yetkinin en sık verildiği yolun kayıtsız olması kabul edilemez.
		//
		// Yeni migration gerekmiyor: via='sso' 010'da eklendi, action
		// serbest metin.
		if lerr := s.LogAdmin(ctx, AdminLogEntry{
			Actor: "system", Via: "sso", Action: "user.create",
			Entity: req.Username,
			Details: fmt.Sprintf("provisioned on first sign-in; roles from directory groups: %s",
				strings.Join(roles, ", ")),
		}); lerr != nil {
			return model.User{}, fmt.Errorf("store.ProvisionUser[%s]: audit: %w", req.Username, lerr)
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
		`UPDATE users SET sso_only = $1 WHERE username = $2;`, ssoOnly, username)
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
// DeleteSetting, bir ayarı siler. Yoksa ErrNotFound.
//
// Sır düşürmek için var: LDAP adresi değişince saklanan bind parolası
// düşürülüyor (bkz. httpapi.adminSetSetting). Değeri boşa çekmek yerine
// SATIRI silmek gerekiyor — boş bir değer "ayarlanmış ama boş" demek ve
// LoadConfig onu farklı yorumluyor.
func (s *Store) DeleteSetting(ctx context.Context, key string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM settings WHERE key = $1;`, key)
	if err != nil {
		return translateErr("store.DeleteSetting", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return translateErr("store.DeleteSetting", err)
	}
	if n == 0 {
		return fmt.Errorf("store.DeleteSetting[%s]: %w", key, ErrNotFound)
	}
	return nil
}

func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	var value string
	var encrypted bool

	err := s.db.QueryRowContext(ctx,
		`SELECT value, encrypted FROM settings WHERE key = $1;`, key).Scan(&value, &encrypted)
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
		VALUES ($1, $2, $3, $4, $5)
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
		`DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2;`, userID, roleID); err != nil {
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
		`DELETE FROM role_targets WHERE role_id = $1 AND target_id = $2;`, roleID, targetID); err != nil {
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
		`DELETE FROM user_public_keys WHERE key_blob = $1 AND user_id = $2;`,
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
	// admin_via = 'cli': bu yetkiyi grup mantığı geri ALAMAZ. Acil durum
	// için elle açılan bir yöneticinin, dizinde o grubu görülmediği için
	// sessizce yetkisini kaybetmesi tam olarak kaçınılması gereken şey.
	via := any(nil)
	if admin {
		via = "cli"
	}

	/*
	 * ⚠️ YÜKSELTMEDEN ÖNCE PAROLA DÜŞÜYOR — ve bunu TEK İŞLEMDE
	 * yapıyoruz.
	 *
	 * Göç 026 "yönetici parola tutamaz" diyor ve kuralı veritabanı
	 * uyguluyor: parolası olan birini yönetici yapma girişimi, tetikle
	 * güncellenen holder_is_admin üzerinden CHECK'e takılıp DÜŞÜYOR.
	 * Doğru davranış, ama tek başına bir çıkmaz: operatör "neden
	 * olmuyor" diye bakar, cevabı SQLSTATE'te bulur.
	 *
	 * Çözüm, kuralı gevşetmek değil önünü açmak: parola siliniyor,
	 * sonra yükseltme yapılıyor. Kişi hiçbir şey kaybetmiyor — yönetici
	 * olarak zaten acil durum sırrıyla girecek (`postern admin issue`),
	 * ve bu iki adım aynı işlemde olduğu için arada "parolası da yok
	 * yöneticiliği de yok" diye bir an oluşmuyor.
	 *
	 * DÜŞÜRMEK YERİNE REDDETMEK denenebilirdi ama dizin grubundan gelen
	 * yükseltmede başında insan yok; orada ret, tüm eşitlemenin durması
	 * demek.
	 */
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return translateErr("store.SetUserAdmin", err)
	}
	defer tx.Rollback() //nolint:errcheck // commit sonrası no-op

	if admin {
		if _, derr := tx.ExecContext(ctx, `
			DELETE FROM local_credentials
			 WHERE created_by <> 'cli'
			   AND user_id = (SELECT id FROM users WHERE username = $1);`,
			username); derr != nil {
			return translateErr("store.SetUserAdmin", derr)
		}
		// ⚠️ Bayrak da düşüyor: yöneticinin değiştirebileceği bir parola
		// yok, dolayısıyla "değiştirene kadar hiçbir şey yapamazsın"
		// demek onu kalıcı olarak kilitlerdi. Gerekçenin tamamı göç
		// 026'daki CHECK'in başında.
		if _, derr := tx.ExecContext(ctx, `
			UPDATE local_credentials SET must_change = FALSE
			 WHERE user_id = (SELECT id FROM users WHERE username = $1);`,
			username); derr != nil {
			return translateErr("store.SetUserAdmin", derr)
		}
	}

	res, err := tx.ExecContext(ctx,
		`UPDATE users SET is_admin = $1, admin_via = $2 WHERE username = $3;`,
		admin, via, username)
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
	if err := tx.Commit(); err != nil {
		return translateErr("store.SetUserAdmin", err)
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
		`UPDATE users SET email = $1 WHERE username = $2;`, val, username)
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
	if err := refuseBadOSUser("store.SetUserOSUser", osUser); err != nil {
		return err
	}

	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET os_user = $1 WHERE username = $2;`, osUser, username)
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
	// #nosec G202 -- birleştirilen parça sabit (dialect.go); değerler $N ile gidiyor
	queryStr := `
		SELECT u.username,
	       u.os_user,
	       u.is_admin,
	       u.sso_only,
	       r.name AS role_name,
	       t.name AS target_name
		FROM users u
		LEFT JOIN user_roles   ur ON ur.user_id = u.id
		                         AND (ur.expires_at IS NULL OR ur.expires_at > $1)
		LEFT JOIN roles        r  ON r.id       = ur.role_id
		LEFT JOIN role_targets rt ON rt.role_id = r.id
		LEFT JOIN targets      t  ON t.id       = rt.target_id
		-- ⚠️ PURGE EDİLMİŞ SATIRLAR LİSTEDE YOK.
		--
		-- Onlar bir KAYIT, bir kullanıcı değil: adı serbest bırakılmış,
		-- anahtarları ve rolleri alınmış, giriş yapamayan bir iz.
		-- Listede durmaları hem gürültü hem yanıltıcı — "purged:9bf1…"
		-- diye bir hesap yok. İzin kendisi PurgedAccounts'tan okunuyor.
		WHERE u.purged_at IS NULL
		ORDER BY u.username, r.name, ` + ciOrder("t.name") + `;
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
		WHERE email = $1;
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
		WHERE username=$1;
	`

	if err := s.db.QueryRowContext(ctx, queryUserStr, username).Scan(&userID); err != nil {
		return translateErr("store.AddPublicKey", err)
	}

	blob := base64.StdEncoding.EncodeToString(keyBlob)

	insertQuery := `
		INSERT INTO user_public_keys (key_blob, user_id, comment, added_at)
		VALUES ($1, $2, $3, $4)
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
		/*
		 * ⚠️ "İLK ANAHTAR EKLENDİ" DAMGASI BURADA, ÇAĞIRANDA DEĞİL.
		 *
		 * Damga, "ilk anahtar bedava, ikincisi yeniden doğrulama ister"
		 * kuralının dayanağı (httpapi/mykeys.go). Eskiden yalnızca
		 * kullanıcının kendi ekleme yolu vuruyordu ve iki yol açık
		 * kalıyordu: panelden yönetici ekleyince ve CLI'dan
		 * `postern user key add` ile eklenince damga konmuyordu. Sonuç
		 * ölçülebilir bir açık — hesabın anahtarı ZATEN VARKEN "ilk
		 * anahtar" muafiyeti hâlâ açık kalıyor, yani kişi hiçbir
		 * doğrulama olmadan kendi anahtarını ekleyebiliyordu.
		 *
		 * Aynı gerekçe göç 026'da da yazılı: kuralı çağıranlara
		 * dağıtmak, bir sonraki çağrı yolunun onu sessizce delmesi
		 * demek. Kural, kaçınılmaz olduğu yerde duruyor.
		 *
		 * COALESCE sayesinde ikinci çağrı ilk anın damgasını KAYDIRMIYOR.
		 */
		if merr := s.MarkFirstKeyAdded(ctx, username, time.Now()); merr != nil {
			return merr
		}
		return nil
	}

	var ownerID string
	ownerQuery := `
		SELECT user_id
		FROM user_public_keys
		WHERE key_blob=$1;
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
		WHERE k.key_blob = $1;
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
		WHERE username=$1;
	`

	if err := s.db.QueryRowContext(ctx, queryUserStr, username).Scan(&userID); err != nil {
		return publicKeys, translateErr("store.PublicKeys", err)
	}

	queryPKeyStr := `
		SELECT key_blob, comment, added_at
		FROM user_public_keys
		WHERE user_id = $1
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
		WHERE username=$1;
	`

	var targetID string
	queryTargetStr := `
		SELECT id
		FROM targets
		WHERE ` + ciEq("name", "$1") + `;
	`

	err := s.db.QueryRowContext(ctx, queryUserStr, rec.Username).Scan(&userID)
	if err != nil {
		return translateErr("store.StartSession", err)
	}

	err = s.db.QueryRowContext(ctx, queryTargetStr, rec.TargetName).Scan(&targetID)
	if err != nil {
		return translateErr("store.StartSession", err)
	}

	if _, err = s.db.ExecContext(ctx, `INSERT INTO sessions (id, user_id, target_id, os_user, src_ip, recording_path, started_at) VALUES ($1, $2, $3, $4, $5, $6, $7);`, rec.ID, userID, targetID, rec.OSUser, rec.SrcIP, rec.RecordingPath, rec.StartedAt.Unix()); err != nil {
		return translateErr("store.StartSession", err)
	}

	return nil
}

func (s *Store) EndSession(ctx context.Context, id string, endedAt time.Time) error {
	var sessionID string
	queryStr := `
		SELECT id
		FROM sessions
		WHERE id=$1;
	`

	err := s.db.QueryRowContext(ctx, queryStr, id).Scan(&sessionID)
	if err != nil {
		return translateErr("store.EndSession", err)
	}

	if _, err = s.db.ExecContext(ctx, `UPDATE sessions SET ended_at=$1 WHERE id=$2 AND ended_at IS NULL;`, endedAt.Unix(), sessionID); err != nil {
		return translateErr("store.EndSession", err)
	}

	return nil
}

// Session, tek bir oturumu kimlik ADLARIYLA döner. Yoksa ErrNotFound.
//
// Sessions'ın sorgusunun WHERE s.id = $1 hâli; NULL/zaman çevrimleri de
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
		WHERE s.id = $1;
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

	// #nosec G202 -- birleştirilen parça sabit (dialect.go); değerler $N ile gidiyor
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
		-- $1 İKİ KEZ geçiyor: numaralı yer tutucunun ? üzerindeki
		-- somut faydası. Aynı değeri iki kez göndermek gerekmiyor.
		--
		-- ⚠️ HARF DUYARSIZ — VE BU BİR DÜZELTME. Karşılaştırma düz "="
		-- idi, oysa users.username harf duyarsız bir sütun (dialect.go
		-- ciColumns, 009/019'daki lower() indeksleri) ve deponun başka
		-- her sorgusu ciEq kullanıyor. "postern session list --user
		-- Ayse" yazan denetçi, ayse'nin yüzlerce oturumu varken "no
		-- sessions recorded" cevabını alıyordu: yazım farkı yüzünden
		-- "hiç bağlanmamış" diye okunan bir boşluk.
		WHERE ($1 = '' OR ` + ciEq("u.username", "$1") + `)
		ORDER BY s.started_at DESC, s.id DESC` + limitClause(limit, "$2") + `;
	`

	rows, err := s.db.QueryContext(ctx, queryStr, limitArgs(limit, username)...)
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

	// Sınıflandırma lehçeye bağlı; ayrıntı dialect.go'da.
	switch {
	case isUniqueViolation(err):
		// "Bu kayıt zaten var."
		return fmt.Errorf("%s: %w: %v", op, ErrConflict, err)

	case isForeignKeyViolation(err):
		// "İşaret ettiğin şey yok." ErrConflict DEĞİL: AssignRole'a olmayan
		// bir kullanıcı adı verildiğinde çıkan hata budur ve sözleşme orada
		// ErrNotFound diyor.
		return fmt.Errorf("%s: %w: %v", op, ErrNotFound, err)
	}

	return fmt.Errorf("%s: %w", op, err)
}

// reservedOSUsers, JIT sağlamanın OTOMATİK üretmeyeceği hesap adları.
//
// Hemen her Linux dağıtımında UID < 1000 ile gelen hesaplar. Hedefin
// UID'lerini bilemediğimiz için ad üzerinden gidiyoruz. Gerekçe
// ProvisionUser'daki kullanım yerinde.
var reservedOSUsers = map[string]bool{
	"root": true, "daemon": true, "bin": true, "sys": true, "sync": true,
	"games": true, "man": true, "lp": true, "mail": true, "news": true,
	"uucp": true, "proxy": true, "backup": true, "list": true, "irc": true,
	"nobody": true, "systemd-network": true, "systemd-resolve": true,
	"messagebus": true, "syslog": true, "tss": true, "landscape": true,
	"pollinate": true, "sshd": true, "postgres": true, "mysql": true,
	"redis": true, "nginx": true, "www-data": true, "docker": true,
	"adm": true, "wheel": true, "sudo": true, "operator": true,
	"halt": true, "shutdown": true, "ftp": true, "ntp": true, "dbus": true,
}

// HasIdPIdentity, hesabın bir OIDC kimliğine bağlı olup olmadığı.
//
// hasIdPIdentity'nin dışa açık eşi: sihirbaz "bu yönetici kaynağı
// çevirince kendini kilitler mi" sorusunu buradan soruyor.
func (s *Store) HasIdPIdentity(ctx context.Context, username string) (bool, error) {
	return s.hasIdPIdentity(ctx, username)
}

/*
 * SeenGroupNames, postern'in BUGÜNE KADAR gördüğü grup adları.
 *
 * İki kaynaktan: kullanıcılara gerçekten atanmış SSO rollerinin
 * eşlemeleri, ve eşlenmemiş grup teşhis tablosu. İkisi birlikte,
 * "bu ad hiç geldi mi" sorusunun elimizdeki en iyi cevabı.
 *
 * ⚠️ Kesin bir liste DEĞİL ve öyle sunulmamalı: bir kaynağa "hangi
 * gruplar var" diye genel olarak sorulamıyor (OIDC claim'i
 * listelenemez). Bu yüzden çağıran bunu bir teşhis olarak kullanıyor,
 * bir iddia olarak değil.
 */
func (s *Store) SeenGroupNames(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT g.name FROM (
		    SELECT name FROM unmapped_groups
		    UNION
		    SELECT gm.external_group AS name
		    FROM group_mappings gm
		    JOIN roles r      ON r.id = gm.role_id
		    JOIN user_roles ur ON ur.role_id = r.id AND ur.source = 'sso'
		) g;`)
	if err != nil {
		return nil, translateErr("store.SeenGroupNames", err)
	}
	defer rows.Close()

	out := make([]string, 0)
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, translateErr("store.SeenGroupNames", err)
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, translateErr("store.SeenGroupNames", err)
	}
	return out, nil
}

/*
 * claimExistingAccount, VAR OLAN bir hesabı bir kimliğe bağlar.
 *
 * ⚠️ ADI EŞLEŞEN HESABI DEVRALMANIN TEK KAPISI. İki çağıranı var ve
 * ikisi de aynı kapıdan geçmek zorunda:
 *
 *   - ProvisionUser: kullanıcı adı eşleşti,
 *   - giriş yollarının E-POSTA dalı: IdP kullanıcı adı vermedi.
 *
 * İkincisi eskiden hesabı DOĞRUDAN döndürüyordu — ne bağ kontrolü, ne
 * yönetici koruması. Yani 011'in ve 020'nin kapattığı iki kapı, IdP
 * kullanıcı adı göndermediği anda birlikte atlanıyordu. Kuralı ikinci
 * kez yazmak yerine tek yere çıkardık: ikinci kopya, ikinci kez
 * unutulacak kural demekti.
 *
 * ⚠️ ROLLERE DOKUNMUYOR ve dokunmamalı: e-posta dalında gruplar hiç
 * sorulamadı. "Çözüldü ve boş" ile "çözülemedi"yi karıştırmak, bütün
 * SSO rollerini silerdi.
 */
func (s *Store) claimExistingAccount(ctx context.Context,
	username, issuer, subject string, adminGroupMember bool) error {

	existing, err := s.User(ctx, username)
	if err != nil {
		return err
	}

	alreadyBound, berr := s.hasIdPIdentity(ctx, username)
	if berr != nil {
		return berr
	}

	/*
	 * ⚠️ Yönetici grubundaki bir kimlik için kapı AÇIK: o kişi zaten
	 * yönetici ve başka bir yönetici hesabını almakla yeni bir yetki
	 * kazanmıyor. Kapalı tutmak, dizin grubundan yönetici olan herkesin
	 * yükseltmeden sonra kendi hesabına girememesi demekti.
	 *
	 * Ölçülen saldırı buradan geçmiyor: saldırgan "developers"
	 * grubundaydı, yönetici grubunda değil.
	 */
	if existing.Admin && !alreadyBound && !adminGroupMember {
		/*
		 * ⚠️ Yalnızca HENÜZ BAĞLANMAMIŞ hesaplar için. Hesap zaten
		 * başka bir kimliğe bağlıysa doğru cevap ErrIdentityConflict:
		 * oradaki mesaj "yöneticiliği kaldır, giriş yaptır" diyor ve
		 * bağlı bir hesapta bu tamamen yanlış tavsiye olurdu.
		 */
		consumed, cerr := s.consumeBindConsent(ctx, username)
		if cerr != nil {
			return cerr
		}
		if !consumed {
			return fmt.Errorf(
				"store.claimExistingAccount[%s]: an administrator account cannot be "+
					"claimed by a matching username or email; allow it deliberately "+
					"on the bastion host (`postern user allow-bind --name %s`) and "+
					"have them sign in once: %w",
				username, username, ErrAdminBindRefused)
		}
	}

	if bindErr := s.BindIdPSubject(ctx, username, issuer, subject); bindErr != nil {
		return fmt.Errorf(
			"store.claimExistingAccount[%s]: account is bound to a different identity: %w",
			username, ErrIdentityConflict)
	}

	/*
	 * ⚠️ İLK BAĞLAMA (TOFU) DENETLENEBİLİR OLMALI.
	 *
	 * Kalan tek devralma penceresi bu. Sessiz kalırsa kimse fark etmez;
	 * denetim satırı yazılamıyorsa bağlamayı yapmış olmayı da istemeyiz,
	 * o yüzden hata yukarı taşınıyor.
	 */
	if lerr := s.LogAdmin(ctx, AdminLogEntry{
		Actor: "system", Via: "sso", Action: "user.idp_bind", Entity: username,
		Details: fmt.Sprintf("first sign-in bound this account to issuer %s subject %s",
			issuer, subject),
	}); lerr != nil {
		return fmt.Errorf("store.claimExistingAccount[%s]: audit: %w", username, lerr)
	}
	return nil
}

/*
 * ClaimByVerifiedEmail, giriş yollarının E-POSTA dalı için: hesabı
 * bulur ve aynı kapıdan geçirir.
 *
 * ⚠️ ProvisionUser KULLANILAMAZ, çünkü o gruplar çözülemediğinde
 * REDDEDİYOR — ve haklı: yeni bir hesap açıp açmamaya karar verecek
 * bilgi yok. Ama burada hesap ZATEN VAR; verilecek karar "bu kimlik bu
 * hesabı alabilir mi", ve o karar gruplara bağlı değil.
 */
func (s *Store) ClaimByVerifiedEmail(ctx context.Context,
	email, issuer, subject string, adminGroupMember bool) (model.User, error) {

	u, err := s.UserByEmail(ctx, email)
	if err != nil {
		return model.User{}, err
	}
	if err := s.claimExistingAccount(ctx, u.Name, issuer, subject, adminGroupMember); err != nil {
		return model.User{}, err
	}
	return s.User(ctx, u.Name)
}

/*
 * RoleGrantSource, bir atamanın NEREDEN geldiğini söyler: "manual" ya
 * da "sso". found=false, böyle bir atama yok demek.
 *
 * ⚠️ NEDEN GEREKLİ: AssignRole'un ON CONFLICT dalı source'u koşulsuz
 * 'manual' yapıyor, SyncRoles ise yalnızca source='sso' satırlarını
 * siliyor. Yani dizinden gelen bir rolü elle "yeniden vermek", o rolü
 * senkronizasyonun erişemeyeceği bir yere taşıyor: kişi gruptan
 * çıkarıldığında rol ÜZERİNDE KALIYOR ve hiçbir otomatik yol onu geri
 * alamıyor. Bu okuma olmadan çağıran, sessizce kalıcı yetki üretiyor.
 *
 * Kimseyi engellemek için değil, SÖYLEYEBİLMEK için var.
 */
func (s *Store) RoleGrantSource(ctx context.Context, username, roleName string) (source string, found bool, err error) {
	userID, err := s.rowID(ctx, "store.RoleGrantSource", "users", "username", username)
	if err != nil {
		return "", false, err
	}
	roleID, err := s.rowID(ctx, "store.RoleGrantSource", "roles", "name", roleName)
	if err != nil {
		return "", false, err
	}

	qerr := s.db.QueryRowContext(ctx,
		`SELECT source FROM user_roles WHERE user_id = $1 AND role_id = $2;`,
		userID, roleID).Scan(&source)
	if errors.Is(qerr, sql.ErrNoRows) {
		return "", false, nil
	}
	if qerr != nil {
		return "", false, translateErr("store.RoleGrantSource", qerr)
	}
	return source, true, nil
}

// Ping, veritabanına ulaşılabildiğini doğrular.
//
// ⚠️ Sağlık ucu için var ve BAŞKA HİÇBİR ŞEY YAPMIYOR: bir sorgu
// çalıştırmak, kimlik istemeyen bir uçtan tetiklenebilen iş demekti.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return translateErr("store.Ping", err)
	}
	return nil
}
