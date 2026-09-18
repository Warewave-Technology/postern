package store

/*
 * postern'in bir hedefteki hesaba ne yaptığı.
 *
 * ⚠️ BU TABLO HEDEFİN KENDİSİNİN SÖYLEYEMEDİĞİ İKİ ŞEYİ TUTUYOR:
 * hesabı postern'in mi açtığı yoksa devraldığı mı (origin), ve en son
 * hangi istenen duruma göre yazdığı (applied_fp). Birincisi bir silme
 * kararının doğruluğunu, ikincisi bağlanma anının hızını belirliyor;
 * ikisi de makineye bakarak öğrenilemiyor.
 */

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Hesabın kaynağı: postern açtı, ya da zaten vardı ve devralındı.
const (
	OriginCreated = "created"
	OriginAdopted = "adopted"
)

// Hesabın hedefteki durumu.
const (
	HostAccountActive  = "active"
	HostAccountLocked  = "locked"
	HostAccountRemoved = "removed"
	HostAccountFailed  = "failed"
)

// HostAccount, bir (hedef, kişi) çiftinin hedefteki hâli.
type HostAccount struct {
	TargetName string `json:"target"`
	Username   string `json:"username"`
	OSUser     string `json:"os_user"`

	Origin string `json:"origin"`
	State  string `json:"state"`

	// AwaitingDecision, insan olmayan bir yolda kilitlendi ve bir kişinin
	// "sil ya da aç" demesini bekliyor (bkz. K3).
	AwaitingDecision bool `json:"awaiting_decision"`

	DesiredFP string    `json:"desired_fp"`
	AppliedFP string    `json:"applied_fp"`
	AppliedAt time.Time `json:"applied_at,omitzero"`

	Attempts      int       `json:"attempts"`
	LastError     string    `json:"last_error,omitempty"`
	NextAttemptAt time.Time `json:"next_attempt_at,omitzero"`

	FirstSeen time.Time `json:"first_seen"`
	UpdatedAt time.Time `json:"updated_at"`
}

const hostAccountColumns = `target_name, username, os_user, origin, state,
	awaiting_decision, desired_fp, applied_fp, applied_at,
	attempts, last_error, next_attempt_at, first_seen, updated_at`

/*
 * SaveHostAccount, satırı yazar ya da günceller.
 *
 * ⚠️ origin GÜNCELLENMİYOR (`DO UPDATE` listesinde yok). İlk yazmada
 * sabitleniyor: hesabı postern'in mi açtığı yoksa devraldığı mı sorusu
 * hedefe bakarak cevaplanamıyor ve ikinci bir yazmanın onu ezmesi, silme
 * diyaloğunun doğruyu söyleyebilmesini imkânsız kılardı.
 *
 * ⚠️ first_seen de öyle: "postern bu makinede bu kişiye ne zaman ilk kez
 * dokundu" sorusu, denetim anlatısının parçası.
 */
func (s *Store) SaveHostAccount(ctx context.Context, a HostAccount) error {
	const op = "store.SaveHostAccount"
	if err := refuseBadUsername(op, a.Username); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO host_accounts (`+hostAccountColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (target_name, username) DO UPDATE SET
			os_user           = EXCLUDED.os_user,
			state             = EXCLUDED.state,
			awaiting_decision = EXCLUDED.awaiting_decision,
			desired_fp        = EXCLUDED.desired_fp,
			applied_fp        = EXCLUDED.applied_fp,
			applied_at        = EXCLUDED.applied_at,
			attempts          = EXCLUDED.attempts,
			last_error        = EXCLUDED.last_error,
			next_attempt_at   = EXCLUDED.next_attempt_at,
			updated_at        = EXCLUDED.updated_at;`,
		a.TargetName, a.Username, a.OSUser, a.Origin, a.State,
		a.AwaitingDecision, a.DesiredFP, a.AppliedFP, nullTime(a.AppliedAt),
		a.Attempts, a.LastError, nullTime(a.NextAttemptAt),
		unixOrNow(a.FirstSeen), unixOrNow(a.UpdatedAt))

	return translateErr(op, err)
}

// HostAccountFor, tek bir çiftin satırı. Yoksa ErrNotFound.
func (s *Store) HostAccountFor(ctx context.Context, target, username string) (HostAccount, error) {
	const op = "store.HostAccountFor"
	row := s.db.QueryRowContext(ctx, `
		SELECT `+hostAccountColumns+` FROM host_accounts
		WHERE target_name = $1 AND username = $2;`, target, username)
	a, err := scanHostAccount(row)
	if err != nil {
		return HostAccount{}, translateErr(op, err)
	}

	return a, nil
}

// HostAccountsForUser, kişinin dokunulmuş bütün hedefleri.
func (s *Store) HostAccountsForUser(ctx context.Context, username string) ([]HostAccount, error) {
	const op = "store.HostAccountsForUser"
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+hostAccountColumns+` FROM host_accounts
		WHERE username = $1 ORDER BY target_name;`, username)
	if err != nil {
		return nil, translateErr(op, err)
	}
	defer rows.Close()

	return scanHostAccounts(op, rows)
}

/*
 * HostAccountsAwaitingDecision, kilitlenmiş ve insan kararı bekleyenler.
 *
 * ⚠️ KENDİ SORGUSU VE KENDİ İNDEKSİ. Panel bu listeyi her açılışta
 * okuyor; bütün satırları çekip Go'da süzmek on bin hesaplı bir kurulumda
 * paneli yavaşlatır, ve listenin genelde kısa olması bu maliyeti görünmez
 * kılar — yani yanlış olduğu anlaşılmaz.
 */
func (s *Store) HostAccountsAwaitingDecision(ctx context.Context) ([]HostAccount, error) {
	const op = "store.HostAccountsAwaitingDecision"
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+hostAccountColumns+` FROM host_accounts
		WHERE awaiting_decision ORDER BY target_name, username;`)
	if err != nil {
		return nil, translateErr(op, err)
	}
	defer rows.Close()

	return scanHostAccounts(op, rows)
}

func scanHostAccount(r rowScanner) (HostAccount, error) {
	var a HostAccount
	var appliedAt, nextAttempt sql.NullInt64
	var firstSeen, updatedAt int64
	err := r.Scan(&a.TargetName, &a.Username, &a.OSUser, &a.Origin, &a.State,
		&a.AwaitingDecision, &a.DesiredFP, &a.AppliedFP, &appliedAt,
		&a.Attempts, &a.LastError, &nextAttempt, &firstSeen, &updatedAt)
	if err != nil {
		return a, err
	}
	if appliedAt.Valid {
		a.AppliedAt = time.Unix(appliedAt.Int64, 0)
	}
	if nextAttempt.Valid {
		a.NextAttemptAt = time.Unix(nextAttempt.Int64, 0)
	}
	a.FirstSeen = time.Unix(firstSeen, 0)
	a.UpdatedAt = time.Unix(updatedAt, 0)

	return a, nil
}

func scanHostAccounts(op string, rows *sql.Rows) ([]HostAccount, error) {
	out := []HostAccount{}
	for rows.Next() {
		a, err := scanHostAccount(rows)
		if err != nil {
			return nil, translateErr(op, err)
		}
		out = append(out, a)
	}

	return out, translateErr(op, rows.Err())
}

// nullTime, sıfır zamanı NULL'a çevirir: "hiç uygulanmadı" ile "1970'te
// uygulandı" ayrı cümleler.
func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}

	return t.Unix()
}

func unixOrNow(t time.Time) int64 {
	if t.IsZero() {
		return time.Now().Unix()
	}

	return t.Unix()
}

// Derleyici, translateErr'in sql.ErrNoRows'u ErrNotFound'a çevirdiğini
// varsayıyor; bu satır o varsayımı görünür kılıyor.
var _ = errors.Is

/*
 * HostAccountsOwedALock, hedefe erişimi bitmiş ama hedefte hâlâ açık olan
 * hesaplar.
 *
 * ⚠️ İŞARET SÜTUNU YOK, İŞ DURUMDAN TÜRETİLİYOR. Bir `pending` bayrağı,
 * onu yazmayı unutan her yeni yazma yolunda sessiz bir boşluk açardı —
 * ve bu tam olarak "grubu düşen kişi makinede açık kaldı" boşluğu olurdu.
 * Burada sorulan şey doğrudan gerçeğin kendisi: satır hedefte açık mı, ve
 * kişi oraya hâlâ bir group üzerinden erişiyor mu?
 *
 * ⚠️ SÜRESİ DOLMUŞ ÜYELİK ERİŞİM SAYILMIYOR (expires_at). Süreli bir
 * group'un süresi dolduğunda erişim biter; onu saymak, süreyi anlamsız
 * kılardı.
 *
 * ⚠️ state='active' ŞARTI: zaten kilitli bir satır yeniden kilitlenmiyor,
 * ve silinmiş olan hiç dokunulmuyor.
 */
func (s *Store) HostAccountsOwedALock(ctx context.Context, now time.Time) ([]HostAccount, error) {
	const op = "store.HostAccountsOwedALock"
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+hostAccountColumns+` FROM host_accounts ha
		WHERE ha.state = 'active'
		  AND (ha.next_attempt_at IS NULL OR ha.next_attempt_at <= $1)
		  AND NOT EXISTS (
			SELECT 1
			FROM users u
			JOIN user_groups   ug ON ug.user_id = u.id
			                     AND (ug.expires_at IS NULL OR ug.expires_at > $1)
			JOIN group_targets gt ON gt.group_id = ug.group_id
			JOIN targets       t  ON t.id = gt.target_id
			WHERE u.username = ha.username AND t.name = ha.target_name
		  )
		ORDER BY ha.target_name, ha.username;`, now.Unix())
	if err != nil {
		return nil, translateErr(op, err)
	}
	defer rows.Close()

	return scanHostAccounts(op, rows)
}

// ActiveHostAccounts, hedefte açık olan hesapların sayısı — blast radius
// tavanının paydası.
func (s *Store) ActiveHostAccounts(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM host_accounts WHERE state = 'active';`).Scan(&n)
	if err != nil {
		return 0, translateErr("store.ActiveHostAccounts", err)
	}

	return n, nil
}
