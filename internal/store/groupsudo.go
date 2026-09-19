package store

/*
 * Rolün taşıdığı sudo kuralı (göç 046).
 *
 * ⚠️ KURAL ROLE AİT, HAKKA DEĞİL. Hak başına yazılan kural hedefte
 * hesabın kendi dosyasında duruyor ve hesapla birlikte gidiyor; bu kural
 * grubun GRUBUNA yazılıyor (`%grup`) ve kişi hakkı üyelikten çekiyor.
 * İkisi bir arada: grubun verdiği sabit yetki, hakkın verdiği ek yetki.
 *
 * ⚠️ ROL BAŞINA TEK KURAL. Hedefte bir grubun tek sudoers dosyası var ve
 * sudoers.Render tek bir Rule'dan üretiyor; grup başına birden çok isimli
 * şablon, o tek dosyaya birleştirme demekti — kimsenin istemediği bir
 * birleştirme ve geri almada referans sayma. Bir kural, içinde istenen
 * kadar komut.
 */

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Warewave-Technology/postern/v2/internal/sudoers"
)

// GroupSudo, bir grubun sudo kuralı ve onu en son kimin yazdığı.
type GroupSudo struct {
	Group     string       `json:"group"`
	Rule      sudoers.Rule `json:"rule"`
	UpdatedBy string       `json:"updated_by"`
	UpdatedAt time.Time    `json:"updated_at"`
}

/*
 * SetGroupSudo, grubun kuralını yazar (varsa değiştirir).
 *
 * ⚠️ KAÇIŞ RİSKİ VERİTABANINDA BEKLEMİYOR. sudoers.Validate'in kaçış
 * bulduğu bir kural (vim, less, find -exec ...) onaylanmadıkça
 * YAZILMIYOR — render anında reddedilmesini beklemek, kuralı kaydedip
 * hedefe gitme anında patlayan bir bomba bırakmak olurdu. Onaylanan kural
 * onay bayrağıyla birlikte duruyor ki denetim satırı da ekran da bunun
 * bir karar olduğunu söyleyebilsin.
 */
func (s *Store) SetGroupSudo(ctx context.Context, group string, rule sudoers.Rule, actor string) error {
	const op = "store.SetGroupSudo"
	if findings := sudoers.Validate(rule); sudoers.Refuses(findings, rule.Acknowledged) {
		return fmt.Errorf("%s: %s: %w", op, sudoers.Describe(findings), ErrInvalid)
	}
	if len(rule.Commands) == 0 {
		return fmt.Errorf("%s: a rule with no command grants nothing: %w", op, ErrInvalid)
	}
	roleID, err := s.rowID(ctx, op, "groups", "name", group)
	if err != nil {
		return err
	}
	blob, err := json.Marshal(rule)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO group_sudo_rules (group_id, rule, acknowledged, updated_by, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (group_id) DO UPDATE SET
			rule = excluded.rule, acknowledged = excluded.acknowledged,
			updated_by = excluded.updated_by, updated_at = excluded.updated_at;`,
		roleID, string(blob), rule.Acknowledged, actor, time.Now().Unix())

	return translateErr(op, err)
}

// GroupSudoRule, grubun kuralı. Kural yoksa ErrNotFound.
func (s *Store) GroupSudoRule(ctx context.Context, group string) (GroupSudo, error) {
	const op = "store.GroupSudoRule"
	var out GroupSudo
	var blob string
	var updated int64
	err := s.db.QueryRowContext(ctx, `
		SELECT r.name, t.rule, t.updated_by, t.updated_at
		FROM group_sudo_rules t JOIN groups r ON r.id = t.group_id
		WHERE `+ciEq("r.name", "$1")+`;`, group).Scan(&out.Group, &blob, &out.UpdatedBy, &updated)
	if err != nil {
		return out, translateErr(op, err)
	}
	if err := json.Unmarshal([]byte(blob), &out.Rule); err != nil {
		return out, fmt.Errorf("%s[%s]: %w", op, group, err)
	}
	out.UpdatedAt = time.Unix(updated, 0).UTC()

	return out, nil
}

/*
 * GroupSudoRules, bütün grupların kuralları, grup adıyla anahtarlı.
 *
 * Hak verme akışı bunu TEK sorguyla alıyor: kişinin seçtiği grupların
 * hangileri grup ve hangilerinin kuralı var, hepsi tek okumada.
 */
func (s *Store) GroupSudoRules(ctx context.Context) (map[string]GroupSudo, error) {
	const op = "store.GroupSudoRules"
	// #nosec G202 -- birleştirilen parça sabit (dialect.go); değer yok
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.name, t.rule, t.updated_by, t.updated_at
		FROM group_sudo_rules t JOIN groups r ON r.id = t.group_id
		ORDER BY `+ciOrder("r.name")+`;`)
	if err != nil {
		return nil, translateErr(op, err)
	}
	defer rows.Close()

	out := map[string]GroupSudo{}
	for rows.Next() {
		var one GroupSudo
		var blob string
		var updated int64
		if err := rows.Scan(&one.Group, &blob, &one.UpdatedBy, &updated); err != nil {
			return nil, translateErr(op, err)
		}
		if err := json.Unmarshal([]byte(blob), &one.Rule); err != nil {
			return nil, fmt.Errorf("%s[%s]: %w", op, one.Group, err)
		}
		one.UpdatedAt = time.Unix(updated, 0).UTC()
		out[one.Group] = one
	}

	return out, translateErr(op, rows.Err())
}

/*
 * DeleteGroupSudo, grubun kuralını siler.
 *
 * ⚠️ HEDEFTEKİ DOSYA BUNUNLA GİTMİYOR. Kural postern'de siliniyor;
 * makinelerdeki /etc/sudoers.d/postern-<grup> dosyası postern o hedefe bir
 * daha dokunana kadar duruyor. Sessiz kalmıyoruz: çağıran bunu operatöre
 * söylüyor, çünkü "sildim" demek yetkinin kalktığı anlamına gelmiyor.
 */
func (s *Store) DeleteGroupSudo(ctx context.Context, group string) error {
	const op = "store.DeleteGroupSudo"
	roleID, err := s.rowID(ctx, op, "groups", "name", group)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM group_sudo_rules WHERE group_id = $1;`, roleID)
	if err != nil {
		return translateErr(op, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return translateErr(op, err)
	}
	if n == 0 {
		return fmt.Errorf("%s[%s]: %w", op, group, ErrNotFound)
	}

	return nil
}
