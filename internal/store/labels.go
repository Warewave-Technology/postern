package store

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Etiket, hedefe iliştirilen key=value notu: "env=prod", "team=payments".
//
// ⚠️ ETİKET BİR YETKİ DEĞİL. Erişimi rol → hedef bağı veriyor; etiket
// yalnızca operatörün hedefleri gruplayıp bulması için. Bu ayrım
// bilinçli: etiketten yetki türetmek, panelden etiket ekleyebilen
// herkese yetki dağıtma imkânı verirdi.

// labelKeyRe, kabul edilen anahtar biçimi.
//
// Dar tutuluyor çünkü anahtar hem URL yolunda (DELETE .../labels/{key})
// hem de arama dizesinde geçiyor. Boşluk ve eğik çizgi dışlanmasa,
// "env prod" gibi bir anahtar arama kutusunda iki terime bölünür ve
// kendi etiketini arayan operatör onu bulamazdı.
var labelKeyRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$`)

const maxLabelValue = 255

// ValidateLabel, anahtar/değer çiftini denetler.
//
// DIŞA AÇIK, çünkü hedef yaratma yolu etiketleri hedefi AÇMADAN ÖNCE
// doğrulamak zorunda: önce açıp sonra etiketi reddetmek, yarısı
// uygulanmış bir istek bırakırdı.
func ValidateLabel(key, value string) error {
	if !labelKeyRe.MatchString(key) {
		return fmt.Errorf(
			"label key %q is not allowed: use letters, digits, dot, dash or underscore (max 63)", key)
	}
	if utf8.RuneCountInString(value) > maxLabelValue {
		return fmt.Errorf("label value is longer than %d characters", maxLabelValue)
	}
	// Kontrol karakteri değeri tabloda ve logda bozuyor; ayrıca yeni
	// satır, tek satır olduğu varsayılan denetim detayını kırardı.
	if strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("label value contains a control character")
	}
	return nil
}

// TargetLabels, tek bir hedefin etiketleri.
func (s *Store) TargetLabels(ctx context.Context, targetName string) (map[string]string, error) {
	id, err := s.rowID(ctx, "store.TargetLabels", "targets", "name", targetName)
	if err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT key, value FROM target_labels WHERE target_id = $1 ORDER BY key;`, id)
	if err != nil {
		return nil, translateErr("store.TargetLabels", err)
	}
	defer rows.Close()

	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, translateErr("store.TargetLabels", err)
		}
		out[k] = v
	}
	if err := rows.Err(); err != nil {
		return nil, translateErr("store.TargetLabels", err)
	}
	return out, nil
}

// allTargetLabels, hedef adı → etiketler.
//
// TEK SORGU: hedef başına ayrı sorgu atmak, elli hedefli bir listede
// elli gidiş dönüş demekti (N+1).
func (s *Store) allTargetLabels(ctx context.Context) (map[string]map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT t.name, l.key, l.value
		FROM target_labels l
		JOIN targets t ON t.id = l.target_id
		ORDER BY t.name, l.key;`)
	if err != nil {
		return nil, translateErr("store.allTargetLabels", err)
	}
	defer rows.Close()

	out := map[string]map[string]string{}
	for rows.Next() {
		var name, k, v string
		if err := rows.Scan(&name, &k, &v); err != nil {
			return nil, translateErr("store.allTargetLabels", err)
		}
		if out[name] == nil {
			out[name] = map[string]string{}
		}
		out[name][k] = v
	}
	if err := rows.Err(); err != nil {
		return nil, translateErr("store.allTargetLabels", err)
	}
	return out, nil
}

// SetTargetLabel, etiketi ekler ya da değerini değiştirir.
//
// Denetim satırı BURADA yazılıyor, çağıranda değil: etiket hedefin
// nasıl bulunacağını belirliyor ve "prod" etiketini bir makineden
// alıp başkasına takan kişinin izi kalmalı.
func (s *Store) SetTargetLabel(ctx context.Context, targetName, key, value, actor, via string) error {
	if err := ValidateLabel(key, value); err != nil {
		return fmt.Errorf("store.SetTargetLabel: %w", err)
	}

	id, err := s.rowID(ctx, "store.SetTargetLabel", "targets", "name", targetName)
	if err != nil {
		return err
	}

	// Var olan anahtarın değerini güncelle: ikinci kez "env=staging"
	// yazan operatör, ilkini elle silmek zorunda kalmasın.
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO target_labels (target_id, key, value)
		VALUES ($1, $2, $3)
		ON CONFLICT (target_id, key) DO UPDATE SET value = EXCLUDED.value;`,
		id, key, value)
	if err != nil {
		return translateErr("store.SetTargetLabel", err)
	}

	return s.LogAdmin(ctx, AdminLogEntry{
		Actor: actor, Via: via, Action: "target.label_set", Entity: targetName,
		Details: key + "=" + value,
	})
}

// DeleteTargetLabel, etiketi kaldırır. Yoksa ErrNotFound.
func (s *Store) DeleteTargetLabel(ctx context.Context, targetName, key, actor, via string) error {
	id, err := s.rowID(ctx, "store.DeleteTargetLabel", "targets", "name", targetName)
	if err != nil {
		return err
	}

	res, err := s.db.ExecContext(ctx,
		`DELETE FROM target_labels WHERE target_id = $1 AND key = $2;`, id, key)
	if err != nil {
		return translateErr("store.DeleteTargetLabel", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return translateErr("store.DeleteTargetLabel", err)
	}
	if n == 0 {
		// "Silindi" demek yanlış olurdu: olmayan bir etiketi kaldırdım
		// diye cevap veren bir API, yanlış hedefe bakan operatöre
		// işini yaptığını söyler.
		return fmt.Errorf("store.DeleteTargetLabel[%s/%s]: %w", targetName, key, ErrNotFound)
	}

	return s.LogAdmin(ctx, AdminLogEntry{
		Actor: actor, Via: via, Action: "target.label_remove", Entity: targetName,
		Details: key,
	})
}
