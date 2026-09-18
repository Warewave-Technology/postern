package store

/*
 * Kişinin filo boyunca taşıdığı numara.
 *
 * ⚠️ NEDEN SABİT BİR NUMARA. Her host kendi numarasını verseydi aynı kişi
 * bir makinede 1003, öbüründe 1007 olurdu; paylaşılan bir dosya sisteminde
 * ya da yedekten dönen bir dizinde dosyaların sahibi yanlış — kötü
 * hâlinde BAŞKA BİRİ — görünürdü.
 */

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// UserUID, kişiye ayrılmış numara ve nereden geldiği.
type UserUID struct {
	Username string `json:"username"`
	UID      int    `json:"uid"`
	Source   string `json:"source"`
}

// Numaranın kaynağı.
const (
	UIDFromDirectory = "directory"
	UIDFromPool      = "pool"
)

// UIDFor, kişiye ayrılmış numarayı döner; yoksa ErrNotFound.
func (s *Store) UIDFor(ctx context.Context, username string) (UserUID, error) {
	const op = "store.UIDFor"
	var u UserUID
	err := s.db.QueryRowContext(ctx,
		`SELECT username, uid, source FROM user_uids WHERE username = $1;`, username).
		Scan(&u.Username, &u.UID, &u.Source)
	if err != nil {
		return UserUID{}, translateErr(op, err)
	}

	return u, nil
}

/*
 * ReserveUID, kişiye numarayı ayırır.
 *
 * ⚠️ VAR OLAN AYIRMA EZİLMİYOR (ON CONFLICT DO NOTHING) ve çağıran
 * SONUÇTAKİ numarayı okuyor. Bir kişinin numarasını sonradan
 * değiştirmek, o kişinin filodaki bütün dosyalarının sahipliğini bir
 * anda koparmak demek — dizin bir gün uidNumber yayınlamaya başlasa bile.
 */
func (s *Store) ReserveUID(ctx context.Context, username string, uid int, source string) (UserUID, error) {
	const op = "store.ReserveUID"
	if err := refuseBadUsername(op, username); err != nil {
		return UserUID{}, err
	}
	if uid <= 0 {
		return UserUID{}, fmt.Errorf("%s: uid %d is not usable: %w", op, uid, ErrInvalid)
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO user_uids (username, uid, source, created_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (username) DO NOTHING;`,
		username, uid, source, time.Now().Unix())
	if err != nil {
		return UserUID{}, translateErr(op, err)
	}

	return s.UIDFor(ctx, username)
}

/*
 * AllocateUIDFromPool, havuzdaki EN KÜÇÜK boş numarayı kişiye ayırır.
 *
 * ⚠️ YARIŞ, KISITIN İŞİ. İki oturum aynı anda aynı boş numarayı seçebilir;
 * uid üzerindeki UNIQUE bunu bir hataya çeviriyor ve kaybeden taraf bir
 * sonrakini deniyor. Kısıt olmasaydı iki kişi aynı kimliği paylaşırdı ve
 * bu, dosya sahipliğinde geri dönüşü olmayan bir karışıklık olurdu.
 */
func (s *Store) AllocateUIDFromPool(ctx context.Context, username string, min, max int) (UserUID, error) {
	const op = "store.AllocateUIDFromPool"
	if existing, err := s.UIDFor(ctx, username); err == nil {
		return existing, nil
	} else if !errors.Is(err, ErrNotFound) {
		return UserUID{}, err
	}

	for attempt := 0; attempt < 8; attempt++ {
		var next int
		/*
		 * Havuzdaki en küçük boş numara: aralıktaki her sayı için o
		 * sayının ayrılmamış olduğuna bakıyoruz. generate_series,
		 * 5000'lik bir aralıkta tek sorgu — ve boşlukları da dolduruyor,
		 * yani silinen bir kişinin numarası yeniden kullanılabilir hâle
		 * geliyor.
		 */
		err := s.db.QueryRowContext(ctx, `
			SELECT n FROM generate_series($1::int, $2::int) AS n
			WHERE NOT EXISTS (SELECT 1 FROM user_uids u WHERE u.uid = n)
			ORDER BY n LIMIT 1;`, min, max).Scan(&next)
		if err != nil {
			return UserUID{}, fmt.Errorf("%s: no free number between %d and %d: %w",
				op, min, max, translateErr(op, err))
		}

		u, rerr := s.ReserveUID(ctx, username, next, UIDFromPool)
		if rerr == nil {
			return u, nil
		}
		if !errors.Is(rerr, ErrConflict) {
			return UserUID{}, rerr
		}
		// Numarayı başkası kaptı: bir sonrakini dene.
	}

	return UserUID{}, fmt.Errorf("%s: could not take a free number after 8 tries: %w", op, ErrConflict)
}
