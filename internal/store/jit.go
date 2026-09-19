package store

/*
 * Geçici (JIT) erişim hakları — göç 041.
 *
 * ⚠️ SATIRLAR SİLİNMİYOR. Geri alınmış bir hak, "geçen salı o makinede
 * kimin root'u vardı" sorusunun cevabı. username/os_user/target birer
 * FOTOĞRAF, yabancı anahtar değil: hesap silinip aynı adla yeniden
 * açılabiliyor, hedef kaldırılabiliyor; kayıt ikisini de atlatmalı.
 */

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Warewave-Technology/postern/v2/internal/sudoers"
)

// JITGrant, bir hedefte süreli açılmış hesap.
type JITGrant struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Target   string   `json:"target"`
	OSUser   string   `json:"os_user"`
	Groups   []string `json:"groups"`
	// Sudo, yalnızca bu hesaba yazılan kural; nil ise yok.
	Sudo *sudoers.Rule `json:"sudo,omitempty"`

	GrantedBy string    `json:"granted_by"`
	GrantedAt time.Time `json:"granted_at"`
	ExpiresAt time.Time `json:"expires_at"`

	// AppliedAt sıfırsa hak hedefe TAM olarak uygulanamadı; rapor sebebi
	// söylüyor ve süpürücü kalan ne varsa toplayacak.
	AppliedAt   time.Time `json:"applied_at,omitzero"`
	ApplyReport string    `json:"apply_report,omitempty"`

	RevokedAt    time.Time `json:"revoked_at,omitzero"`
	RevokeReport string    `json:"revoke_report,omitempty"`
	/*
	 * CreatedGroups, postern'in BU hak için açtığı gruplar. Geri almada
	 * boş kalanlar silinebiliyor; önceden var olan grup buraya girmiyor
	 * ve hiç silinmiyor — "postern açtıysa siler" (hesaptaki kanıtın
	 * grup için karşılığı).
	 */
	CreatedGroups []string `json:"created_groups"`
	// CleanupGroups, geri almada boş kalan açılmış grupları silme izni.
	CleanupGroups bool `json:"cleanup_groups"`

	/*
	 * RevokeError, son geri alma denemesinin neden bitmediği; NextAttempt,
	 * süpürücünün bir daha ne zaman deneyeceği. Sıfırdan farklı bir deneme
	 * sayısıyla boş bir hata "şu an deneniyor" demek değil — her deneme
	 * ya revoked_at ya revoke_error yazıyor.
	 */
	RevokeError    string    `json:"revoke_error,omitempty"`
	RevokeAttempts int       `json:"revoke_attempts"`
	NextAttempt    time.Time `json:"next_attempt,omitzero"`
}

// Active, hesap hedefte hâlâ açık mı (postern'in bildiği kadarıyla).
func (g JITGrant) Active() bool { return g.RevokedAt.IsZero() }

// Due, süresi dolmuş ve henüz geri alınmamış mı.
func (g JITGrant) Due(now time.Time) bool {
	return g.Active() && !now.Before(g.ExpiresAt)
}

const jitColumns = `id, username, target, os_user, groups, sudo_rule, granted_by, granted_at,
	expires_at, applied_at, apply_report, revoked_at, revoke_report, revoke_error,
	revoke_attempts, next_attempt, created_groups, cleanup_groups`

/*
 * CreateJITGrant, hakkı UYGULAMADAN ÖNCE yazar ve kimliğini döner.
 *
 * ⚠️ ÖNCE SATIR, SONRA MAKİNE. Uygulama ortasında süreç ölürse hedefte
 * yarım bir hesap kalır; satır yoksa süpürücünün onu bulacağı bir şey de
 * yoktur. applied_at boş bir satır "hedefte ne olduğu bilinmiyor" demek
 * ve süresi dolmuş sayılıyor.
 */
func (s *Store) CreateJITGrant(ctx context.Context, g JITGrant) (string, error) {
	if g.Username == "" || g.Target == "" || g.OSUser == "" {
		return "", fmt.Errorf("store.CreateJITGrant: user, target and os_user are required: %w", ErrInvalid)
	}
	if !g.ExpiresAt.After(g.GrantedAt) {
		return "", fmt.Errorf("store.CreateJITGrant: expires_at is not after granted_at: %w", ErrInvalid)
	}

	id, err := newID()
	if err != nil {
		return "", fmt.Errorf("store.CreateJITGrant: %w", err)
	}

	groups, err := json.Marshal(nonNil(g.Groups))
	if err != nil {
		return "", fmt.Errorf("store.CreateJITGrant: %w", err)
	}
	var rule any
	if g.Sudo != nil {
		b, err := json.Marshal(g.Sudo)
		if err != nil {
			return "", fmt.Errorf("store.CreateJITGrant: %w", err)
		}
		rule = string(b)
	}

	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO jit_grants
		       (id, username, target, os_user, groups, sudo_rule, granted_by, granted_at, expires_at, cleanup_groups)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);`,
		id, g.Username, g.Target, g.OSUser, string(groups), rule, g.GrantedBy,
		g.GrantedAt.Unix(), g.ExpiresAt.Unix(), g.CleanupGroups); err != nil {
		return "", translateErr("store.CreateJITGrant", err)
	}

	return id, nil
}

/*
 * MarkJITGrantApplied, uygulamanın sonucunu yazar.
 *
 * ⚠️ TAM UYGULANAMAYAN HAK HEMEN DÜŞÜYOR: expires_at şu ana çekiliyor,
 * süpürücü yarım kalanı ilk turunda toplayacak. Yarım bir hesabı istenen
 * süre boyunca makinede bırakmak, kimsenin onaylamadığı bir erişim
 * bırakmak olurdu.
 */
func (s *Store) MarkJITGrantApplied(ctx context.Context, id string, ok bool, report string, now time.Time) error {
	var res sql.Result
	var err error
	if ok {
		res, err = s.db.ExecContext(ctx, `
			UPDATE jit_grants SET applied_at = $2, apply_report = $3
			WHERE id = $1 AND revoked_at IS NULL;`, id, now.Unix(), report)
	} else {
		res, err = s.db.ExecContext(ctx, `
			UPDATE jit_grants SET apply_report = $3, expires_at = LEAST(expires_at, $2)
			WHERE id = $1 AND revoked_at IS NULL;`, id, now.Unix(), report)
	}
	if err != nil {
		return translateErr("store.MarkJITGrantApplied", err)
	}

	return oneRow("store.MarkJITGrantApplied", res)
}

// ExpireJITGrant, hakkı ŞİMDİ süresi dolmuş sayar: elle geri alma bunu
// yazıp geri alma yolunu çağırıyor, böylece elle ve otomatik geri alma
// aynı koddan geçiyor.
func (s *Store) ExpireJITGrant(ctx context.Context, id string, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE jit_grants SET expires_at = LEAST(expires_at, $2), next_attempt = NULL
		WHERE id = $1 AND revoked_at IS NULL;`, id, now.Unix())
	if err != nil {
		return translateErr("store.ExpireJITGrant", err)
	}

	return oneRow("store.ExpireJITGrant", res)
}

// MarkJITGrantRevoked, hesabın hedeften gittiğini yazar.
func (s *Store) MarkJITGrantRevoked(ctx context.Context, id, report string, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE jit_grants
		SET revoked_at = $2, revoke_report = $3, revoke_error = '', next_attempt = NULL
		WHERE id = $1 AND revoked_at IS NULL;`, id, now.Unix(), report)
	if err != nil {
		return translateErr("store.MarkJITGrantRevoked", err)
	}

	return oneRow("store.MarkJITGrantRevoked", res)
}

/*
 * MarkJITGrantRevokeFailed, geri almanın bitmediğini ve bir sonraki
 * denemeyi yazar.
 *
 * ⚠️ HATA SİLİNMİYOR, ÜSTÜNE YAZILIYOR. Panel "geri alma X'ten beri
 * başarısız" diyebilmeli; başarısız denemeyi sessizce ertelemek, süresi
 * dolmuş bir root hesabını kimsenin görmediği bir yerde açık bırakırdı.
 */
func (s *Store) MarkJITGrantRevokeFailed(ctx context.Context, id, reason string, next time.Time) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE jit_grants
		SET revoke_error = $2, revoke_attempts = revoke_attempts + 1, next_attempt = $3
		WHERE id = $1 AND revoked_at IS NULL;`, id, reason, next.Unix())
	if err != nil {
		return translateErr("store.MarkJITGrantRevokeFailed", err)
	}

	return oneRow("store.MarkJITGrantRevokeFailed", res)
}

// JITGrant, tek bir hakkı okur.
func (s *Store) JITGrant(ctx context.Context, id string) (JITGrant, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+jitColumns+` FROM jit_grants WHERE id = $1;`, id)
	if err != nil {
		return JITGrant{}, translateErr("store.JITGrant", err)
	}
	defer rows.Close()

	out, err := scanJITGrants("store.JITGrant", rows)
	if err != nil {
		return JITGrant{}, err
	}
	if len(out) == 0 {
		return JITGrant{}, fmt.Errorf("store.JITGrant: %w", ErrNotFound)
	}

	return out[0], nil
}

// JITGrantsForTarget, bir hedefin haklarını yeniden eskiye döner.
func (s *Store) JITGrantsForTarget(ctx context.Context, target string, limit int) ([]JITGrant, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+jitColumns+` FROM jit_grants
		WHERE target = $1 ORDER BY granted_at DESC, id LIMIT $2;`, target, limit)
	if err != nil {
		return nil, translateErr("store.JITGrantsForTarget", err)
	}
	defer rows.Close()

	return scanJITGrants("store.JITGrantsForTarget", rows)
}

// SetJITGrantCreatedGroups, hak uygulanırken postern'in AÇTIĞI grupları
// kaydeder; geri alma yalnızca bunları silmeyi düşünür.
func (s *Store) SetJITGrantCreatedGroups(ctx context.Context, id string, groups []string) error {
	b, err := json.Marshal(nonNil(groups))
	if err != nil {
		return fmt.Errorf("store.SetJITGrantCreatedGroups: %w", err)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE jit_grants SET created_groups = $2 WHERE id = $1;`, id, string(b))
	if err != nil {
		return translateErr("store.SetJITGrantCreatedGroups", err)
	}
	return oneRow("store.SetJITGrantCreatedGroups", res)
}

// JITGrants, bütün hedeflerdeki hakları yeniden eskiye döner — panelin
// geçici erişim sekmesi "kimin nerede açık hesabı var" sorusunu tek
// ekranda cevaplıyor.
func (s *Store) JITGrants(ctx context.Context, limit int) ([]JITGrant, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+jitColumns+` FROM jit_grants
		ORDER BY granted_at DESC, id LIMIT $1;`, limit)
	if err != nil {
		return nil, translateErr("store.JITGrants", err)
	}
	defer rows.Close()

	return scanJITGrants("store.JITGrants", rows)
}

// ActiveJITGrantsForUser, kişinin hâlâ açık hakları — silme öncesi bakılan
// liste.
func (s *Store) ActiveJITGrantsForUser(ctx context.Context, username string) ([]JITGrant, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+jitColumns+` FROM jit_grants
		WHERE username = $1 AND revoked_at IS NULL ORDER BY granted_at, id;`, username)
	if err != nil {
		return nil, translateErr("store.ActiveJITGrantsForUser", err)
	}
	defer rows.Close()

	return scanJITGrants("store.ActiveJITGrantsForUser", rows)
}

/*
 * DueJITGrants, süresi dolmuş, geri alınmamış ve yeniden deneme zamanı
 * gelmiş hakları döner — süpürücünün her turda sorduğu soru.
 */
func (s *Store) DueJITGrants(ctx context.Context, now time.Time) ([]JITGrant, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+jitColumns+` FROM jit_grants
		WHERE revoked_at IS NULL AND expires_at <= $1
		  AND (next_attempt IS NULL OR next_attempt <= $1)
		ORDER BY expires_at, id;`, now.Unix())
	if err != nil {
		return nil, translateErr("store.DueJITGrants", err)
	}
	defer rows.Close()

	return scanJITGrants("store.DueJITGrants", rows)
}

func scanJITGrants(op string, rows *sql.Rows) ([]JITGrant, error) {
	out := make([]JITGrant, 0)
	for rows.Next() {
		var g JITGrant
		var groups, created string
		var rule sql.NullString
		var grantedAt, expiresAt int64
		var appliedAt, revokedAt, nextAttempt sql.NullInt64

		if err := rows.Scan(&g.ID, &g.Username, &g.Target, &g.OSUser, &groups, &rule,
			&g.GrantedBy, &grantedAt, &expiresAt, &appliedAt, &g.ApplyReport,
			&revokedAt, &g.RevokeReport, &g.RevokeError, &g.RevokeAttempts, &nextAttempt,
			&created, &g.CleanupGroups); err != nil {
			return nil, translateErr(op, err)
		}
		if err := json.Unmarshal([]byte(created), &g.CreatedGroups); err != nil {
			return nil, fmt.Errorf("%s: grant %s: created_groups are not a JSON list: %w", op, g.ID, err)
		}
		g.CreatedGroups = nonNil(g.CreatedGroups)
		if err := json.Unmarshal([]byte(groups), &g.Groups); err != nil {
			return nil, fmt.Errorf("%s: grant %s: groups are not a JSON list: %w", op, g.ID, err)
		}
		g.Groups = nonNil(g.Groups)
		if rule.Valid {
			var r sudoers.Rule
			if err := json.Unmarshal([]byte(rule.String), &r); err != nil {
				return nil, fmt.Errorf("%s: grant %s: sudo rule is not JSON: %w", op, g.ID, err)
			}
			g.Sudo = &r
		}
		g.GrantedAt = time.Unix(grantedAt, 0)
		g.ExpiresAt = time.Unix(expiresAt, 0)
		if appliedAt.Valid {
			g.AppliedAt = time.Unix(appliedAt.Int64, 0)
		}
		if revokedAt.Valid {
			g.RevokedAt = time.Unix(revokedAt.Int64, 0)
		}
		if nextAttempt.Valid {
			g.NextAttempt = time.Unix(nextAttempt.Int64, 0)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, translateErr(op, err)
	}

	return out, nil
}

// oneRow, güncellemenin bir satıra değdiğini doğrular; değmediyse hak ya
// yok ya çoktan geri alınmış — ikisi de çağıranın bilmesi gereken şey.
func oneRow(op string, res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return translateErr(op, err)
	}
	if n == 0 {
		return fmt.Errorf("%s: %w", op, ErrNotFound)
	}

	return nil
}

func nonNil(in []string) []string {
	if in == nil {
		return []string{}
	}

	return in
}

/*
 * FailedRevokes, geri alınamamış haklar — süresi dolmuş ama hedefteki
 * hesabı hâlâ duran kayıtlar.
 *
 * ⚠️ SINIRSIZ VE KENDİ SORGUSU, JITGrants'ın SÜZÜLMÜŞ HÂLİ DEĞİL. Liste
 * en yeniden eskiye sıralı ve sınırlı; geri alması aylardır düşen bir
 * hak, üstüne binen yeni haklarla o sınırın altına kayar ve tam da en
 * çok bakılması gereken kayıt görünmez olurdu. Sayı zaten küçük: burada
 * bir satır olması, bir makinede fazladan bir hesap durması demek.
 */
func (s *Store) FailedRevokes(ctx context.Context) ([]JITGrant, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+jitColumns+` FROM jit_grants
		WHERE revoked_at IS NULL AND revoke_error <> ''
		ORDER BY expires_at, id;`)
	if err != nil {
		return nil, translateErr("store.FailedRevokes", err)
	}
	defer rows.Close()

	return scanJITGrants("store.FailedRevokes", rows)
}
