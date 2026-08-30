package store

// Hesabın yaşam döngüsü: aktif → pasif → silinmiş, ve hepsi geri
// alınabilir. Gerekçe göç 023'te.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/warewave/postern/internal/model"
)

// Hesap durumları.
const (
	StateActive   = "active"
	StateInactive = "inactive"
	StateDeleted  = "deleted"
)

/*
 * ConfirmAccount, kaynağın bu kişiyi ŞU AN doğruladığını kaydeder.
 *
 * ⚠️ HER BAŞARILI GİRİŞTE çağrılmalı — OIDC, dizin, hepsi. Zaman
 * temelli iptalin tek girdisi bu damga; koyulmayan bir kapı, o kapıdan
 * girenleri yavaş yavaş pasifleştirirdi.
 *
 * ⚠️ VE HESABI GERİ AKTİF EDİYOR. Pasifleşme "kaynak bunu bir süredir
 * doğrulamadı" demek; kaynak yeniden doğruladığı anda sebep ortadan
 * kalkıyor. Elle müdahale gerektirseydi, tatilden dönen herkes
 * yöneticiye başvururdu.
 *
 * 'deleted' hesap KENDİLİĞİNDEN geri gelmiyor: orada bir insan kararı
 * var (ya da uzun bir sessizlik) ve onu bir girişin sessizce bozması
 * doğru olmaz.
 */
func (s *Store) ConfirmAccount(ctx context.Context, username string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET last_confirmed_at = $1,
		    state = CASE WHEN state = 'inactive' THEN 'active' ELSE state END
		WHERE username = $2;`, at.Unix(), username)
	if err != nil {
		return translateErr("store.ConfirmAccount", err)
	}
	return nil
}

// AccountState, hesabın durumu ve son doğrulanma anı.
func (s *Store) AccountState(ctx context.Context, username string) (state string, confirmed time.Time, err error) {
	var at sql.NullInt64
	qerr := s.db.QueryRowContext(ctx,
		`SELECT state, last_confirmed_at FROM users WHERE username = $1;`,
		username).Scan(&state, &at)
	if qerr != nil {
		return "", time.Time{}, translateErr("store.AccountState", qerr)
	}
	if at.Valid {
		confirmed = time.Unix(at.Int64, 0).UTC()
	}
	return state, confirmed, nil
}

/*
 * SetAccountState, durumu elle değiştirir (panel/CLI).
 *
 * ⚠️ 'deleted'ten 'active'e dönüş SERBEST: yanlışlıkla silinmiş bir
 * hesabın geri gelememesi, tek tıkla kalıcı bir kayıp demekti. Fiziki
 * silme zaten yok.
 */
func (s *Store) SetAccountState(ctx context.Context, username, state string) error {
	switch state {
	case StateActive, StateInactive, StateDeleted:
	default:
		return fmt.Errorf("store.SetAccountState: unknown state %q", state)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET state = $1 WHERE username = $2;`, state, username)
	if err != nil {
		return translateErr("store.SetAccountState", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store.SetAccountState[%s]: %w", username, ErrNotFound)
	}
	return nil
}

// StaleAccount, süresi dolmuş bir hesabın özeti.
type StaleAccount struct {
	Username    string
	State       string
	Confirmed   time.Time
	SSOOnly     bool
	DirBound    bool
	ManualRoles int
}

/*
 * StaleAccounts, kaynağın BELİRLİ BİR SÜREDİR doğrulamadığı hesapları
 * döner.
 *
 * ⚠️ KAPSAM: yalnızca kaynaktan gelen hesaplar (sso_only ya da dizine
 * bağlı). Yerel hesaplar DIŞARIDA ve bu kapsam daraltması özelliğin
 * otomasyon için güvenli olmasının tek sebebi: CI ve servis hesapları
 * yerel açılıyor, hiçbir kaynağa sorulamıyor ve "doğrulanmamış olmaları"
 * normal. Onları da kapsayan bir sayaç, her otomasyonu süre dolunca
 * keserdi.
 */
func (s *Store) StaleAccounts(ctx context.Context, olderThan time.Time, state string) ([]StaleAccount, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT u.username, u.state, u.last_confirmed_at, u.sso_only,
		       (u.dir_subject IS NOT NULL) AS dir_bound,
		       COUNT(*) FILTER (WHERE ur.source = 'manual') AS manual_roles
		FROM users u
		LEFT JOIN user_roles ur ON ur.user_id = u.id
		WHERE u.state = $1
		  AND (u.sso_only = TRUE OR u.dir_subject IS NOT NULL)
		  AND u.last_confirmed_at IS NOT NULL
		  AND u.last_confirmed_at < $2
		GROUP BY u.username, u.state, u.last_confirmed_at, u.sso_only, u.dir_subject
		ORDER BY u.last_confirmed_at;`, state, olderThan.Unix())
	if err != nil {
		return nil, translateErr("store.StaleAccounts", err)
	}
	defer rows.Close()

	out := make([]StaleAccount, 0)
	for rows.Next() {
		var a StaleAccount
		var at sql.NullInt64
		if err := rows.Scan(&a.Username, &a.State, &at, &a.SSOOnly,
			&a.DirBound, &a.ManualRoles); err != nil {
			return nil, translateErr("store.StaleAccounts", err)
		}
		if at.Valid {
			a.Confirmed = time.Unix(at.Int64, 0).UTC()
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, translateErr("store.StaleAccounts", err)
	}
	return out, nil
}

// SourceAccountCount, kaynaktan gelen toplam hesap sayısı — patlama
// yarıçapı oranının paydası.
func (s *Store) SourceAccountCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
		SELECT count(*) FROM users
		WHERE state <> 'deleted' AND (sso_only = TRUE OR dir_subject IS NOT NULL);`).Scan(&n)
	if err != nil {
		return 0, translateErr("store.SourceAccountCount", err)
	}
	return n, nil
}

/*
 * RefuseIfDeleted, silinmiş bir hesabın giriş yapmasını engeller.
 *
 * ⚠️ 'inactive' BURADA REDDEDİLMİYOR ve bu tasarımın kendisi:
 * pasifleşme "kaynak bir süredir doğrulamadı" demek ve BAŞARILI GİRİŞİN
 * kendisi o doğrulama. Reddetseydik, geri dönüş yolu bir yöneticiden
 * geçerdi ve tatilden dönen herkes kuyruğa girerdi.
 *
 * 'deleted' farklı: orada uzun bir sessizlik ya da bir insan kararı var
 * ve onu bir girişin sessizce bozması, "silindi" demenin anlamını yok
 * ederdi.
 */
func (s *Store) RefuseIfDeleted(ctx context.Context, username string) error {
	state, _, err := s.AccountState(ctx, username)
	if err != nil {
		return err
	}
	if state == StateDeleted {
		return fmt.Errorf("store.RefuseIfDeleted[%s]: %w", username, ErrAccessDenied)
	}
	return nil
}

// ActiveUser, hesabın giriş yapabilir durumda olduğunu doğrular.
func (s *Store) ActiveUser(ctx context.Context, username string) (model.User, error) {
	state, _, err := s.AccountState(ctx, username)
	if err != nil {
		return model.User{}, err
	}
	if state != StateActive {
		return model.User{}, fmt.Errorf("store.ActiveUser[%s]: state %s: %w",
			username, state, ErrAccessDenied)
	}
	return s.User(ctx, username)
}
