package store

/*
 * Rolün taşıdığı sudo kuralı (göç 046).
 *
 * ⚠️ KURAL ROLE AİT, HAKKA DEĞİL. Hak başına yazılan kural hedefte
 * hesabın kendi dosyasında duruyor ve hesapla birlikte gidiyor; bu kural
 * rolün GRUBUNA yazılıyor (`%rol`) ve kişi hakkı üyelikten çekiyor.
 * İkisi bir arada: rolün verdiği sabit yetki, hakkın verdiği ek yetki.
 *
 * ⚠️ ROL BAŞINA TEK KURAL. Hedefte bir grubun tek sudoers dosyası var ve
 * sudoers.Render tek bir Rule'dan üretiyor; rol başına birden çok isimli
 * şablon, o tek dosyaya birleştirme demekti — kimsenin istemediği bir
 * birleştirme ve geri almada referans sayma. Bir kural, içinde istenen
 * kadar komut.
 */

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Warewave-Technology/postern/internal/sudoers"
)

// RoleSudo, bir rolün sudo kuralı ve onu en son kimin yazdığı.
type RoleSudo struct {
	Role      string       `json:"role"`
	Rule      sudoers.Rule `json:"rule"`
	UpdatedBy string       `json:"updated_by"`
	UpdatedAt time.Time    `json:"updated_at"`
}

/*
 * SetRoleSudo, rolün kuralını yazar (varsa değiştirir).
 *
 * ⚠️ KAÇIŞ RİSKİ VERİTABANINDA BEKLEMİYOR. sudoers.Validate'in kaçış
 * bulduğu bir kural (vim, less, find -exec ...) onaylanmadıkça
 * YAZILMIYOR — render anında reddedilmesini beklemek, kuralı kaydedip
 * hedefe gitme anında patlayan bir bomba bırakmak olurdu. Onaylanan kural
 * onay bayrağıyla birlikte duruyor ki denetim satırı da ekran da bunun
 * bir karar olduğunu söyleyebilsin.
 */
func (s *Store) SetRoleSudo(ctx context.Context, role string, rule sudoers.Rule, actor string) error {
	const op = "store.SetRoleSudo"
	if findings := sudoers.Validate(rule); sudoers.Refuses(findings, rule.Acknowledged) {
		return fmt.Errorf("%s: %s: %w", op, sudoers.Describe(findings), ErrInvalid)
	}
	if len(rule.Commands) == 0 {
		return fmt.Errorf("%s: a rule with no command grants nothing: %w", op, ErrInvalid)
	}
	roleID, err := s.rowID(ctx, op, "roles", "name", role)
	if err != nil {
		return err
	}
	blob, err := json.Marshal(rule)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO role_sudo_rules (role_id, rule, acknowledged, updated_by, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (role_id) DO UPDATE SET
			rule = excluded.rule, acknowledged = excluded.acknowledged,
			updated_by = excluded.updated_by, updated_at = excluded.updated_at;`,
		roleID, string(blob), rule.Acknowledged, actor, time.Now().Unix())

	return translateErr(op, err)
}

// RoleSudoRule, rolün kuralı. Kural yoksa ErrNotFound.
func (s *Store) RoleSudoRule(ctx context.Context, role string) (RoleSudo, error) {
	const op = "store.RoleSudoRule"
	var out RoleSudo
	var blob string
	var updated int64
	err := s.db.QueryRowContext(ctx, `
		SELECT r.name, t.rule, t.updated_by, t.updated_at
		FROM role_sudo_rules t JOIN roles r ON r.id = t.role_id
		WHERE `+ciEq("r.name", "$1")+`;`, role).Scan(&out.Role, &blob, &out.UpdatedBy, &updated)
	if err != nil {
		return out, translateErr(op, err)
	}
	if err := json.Unmarshal([]byte(blob), &out.Rule); err != nil {
		return out, fmt.Errorf("%s[%s]: %w", op, role, err)
	}
	out.UpdatedAt = time.Unix(updated, 0).UTC()

	return out, nil
}

/*
 * RoleSudoRules, bütün rollerin kuralları, rol adıyla anahtarlı.
 *
 * Hak verme akışı bunu TEK sorguyla alıyor: kişinin seçtiği grupların
 * hangileri rol ve hangilerinin kuralı var, hepsi tek okumada.
 */
func (s *Store) RoleSudoRules(ctx context.Context) (map[string]RoleSudo, error) {
	const op = "store.RoleSudoRules"
	// #nosec G202 -- birleştirilen parça sabit (dialect.go); değer yok
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.name, t.rule, t.updated_by, t.updated_at
		FROM role_sudo_rules t JOIN roles r ON r.id = t.role_id
		ORDER BY `+ciOrder("r.name")+`;`)
	if err != nil {
		return nil, translateErr(op, err)
	}
	defer rows.Close()

	out := map[string]RoleSudo{}
	for rows.Next() {
		var one RoleSudo
		var blob string
		var updated int64
		if err := rows.Scan(&one.Role, &blob, &one.UpdatedBy, &updated); err != nil {
			return nil, translateErr(op, err)
		}
		if err := json.Unmarshal([]byte(blob), &one.Rule); err != nil {
			return nil, fmt.Errorf("%s[%s]: %w", op, one.Role, err)
		}
		one.UpdatedAt = time.Unix(updated, 0).UTC()
		out[one.Role] = one
	}

	return out, translateErr(op, rows.Err())
}

/*
 * DeleteRoleSudo, rolün kuralını siler.
 *
 * ⚠️ HEDEFTEKİ DOSYA BUNUNLA GİTMİYOR. Kural postern'de siliniyor;
 * makinelerdeki /etc/sudoers.d/postern-<rol> dosyası postern o hedefe bir
 * daha dokunana kadar duruyor. Sessiz kalmıyoruz: çağıran bunu operatöre
 * söylüyor, çünkü "sildim" demek yetkinin kalktığı anlamına gelmiyor.
 */
func (s *Store) DeleteRoleSudo(ctx context.Context, role string) error {
	const op = "store.DeleteRoleSudo"
	roleID, err := s.rowID(ctx, op, "roles", "name", role)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM role_sudo_rules WHERE role_id = $1;`, roleID)
	if err != nil {
		return translateErr(op, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return translateErr(op, err)
	}
	if n == 0 {
		return fmt.Errorf("%s[%s]: %w", op, role, ErrNotFound)
	}

	return nil
}
