package store

// TOTP ikinci faktörünün saklanması (göç 028).

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// TOTPCredential, bir hesabın ikinci faktörü.
type TOTPCredential struct {
	// ⚠️ Secret JSON'a ÇIKMIYOR. Bu değer kod üretmeye yeter; bir
	// listeleme ucundan sızması, ikinci faktörü ikinci faktör olmaktan
	// çıkarır. Yalnızca kayıt akışında, bir kez gösteriliyor.
	Secret string `json:"-"`

	Confirmed   bool      `json:"confirmed"`
	ConfirmedAt time.Time `json:"confirmed_at,omitzero"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsedAt  time.Time `json:"last_used_at,omitzero"`
}

/*
 * BeginTOTP, kayıt başlatır (ya da BAŞTAN başlatır).
 *
 * ⚠️ Doğrulanmış bir kaydın üzerine YAZMIYOR. Yazsaydı, oturumu çalınan
 * bir hesapta saldırgan kaydı sıfırlayıp kendi telefonunu bağlar ve
 * ikinci faktör sessizce el değiştirirdi. Doğrulanmış kaydı değiştirmek
 * ancak önce onu kapatmakla (DisableTOTP, kod ister) mümkün.
 */
func (s *Store) BeginTOTP(ctx context.Context, username, secret string) error {
	userID, err := s.userID(ctx, username)
	if err != nil {
		return err
	}
	/*
	 * ⚠️ ANAHTAR YOKSA KAYIT AÇILMIYOR (göç 033).
	 *
	 * Gerekçe SetSetting'inkiyle aynı: düz metin yazıp "mühürledim" sanmak,
	 * mekanizmanın bütün amacını sessizce boşa çıkarır. TOTP artık yerel
	 * hesapların GİRİŞ faktörü; sırrı korumasız yazmak, korumayı iddia edip
	 * vermemek olurdu.
	 *
	 * Hata, düzeltmenin adını veriyor — "secret key not configured" tek
	 * başına operatöre ne yapacağını söylemiyor.
	 */
	if s.box == nil {
		return fmt.Errorf(
			"store.BeginTOTP[%s]: secret key not configured; run `postern secret init`",
			username)
	}
	stored, err := s.box.Seal(secret)
	if err != nil {
		return fmt.Errorf("store.BeginTOTP[%s]: %w", username, err)
	}

	now := time.Now().Unix()
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO totp_credentials (user_id, secret, sealed, created_at)
		VALUES ($1, $2, TRUE, $3)
		ON CONFLICT (user_id) DO UPDATE SET
		    secret     = EXCLUDED.secret,
		    sealed     = TRUE,
		    created_at = EXCLUDED.created_at,
		    last_step  = -1
		WHERE totp_credentials.confirmed_at IS NULL;`,
		userID, stored, now)
	if err != nil {
		return translateErr("store.BeginTOTP", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store.BeginTOTP[%s]: already enrolled: %w", username, ErrConflict)
	}
	return nil
}

/*
 * ConfirmTOTP, kaydı DOĞRULANMIŞ işaretler.
 *
 * Yalnızca doğrulanmamış bir kayıt onaylanabilir: ikinci bir onay
 * çağrısı, kullanılmış bir adımı geri açmamalı.
 */
func (s *Store) ConfirmTOTP(ctx context.Context, username string, step int64) error {
	userID, err := s.userID(ctx, username)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	res, err := s.db.ExecContext(ctx, `
		UPDATE totp_credentials
		SET confirmed_at = $2, last_step = $3, last_used_at = $2
		WHERE user_id = $1 AND confirmed_at IS NULL;`, userID, now, step)
	if err != nil {
		return translateErr("store.ConfirmTOTP", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store.ConfirmTOTP[%s]: %w", username, ErrNotFound)
	}
	return nil
}

// TOTP, hesabın ikinci faktörünü döner. Yoksa ErrNotFound.
func (s *Store) TOTP(ctx context.Context, username string) (TOTPCredential, error) {
	var c TOTPCredential
	var confirmed, lastUsed sql.NullInt64
	var created int64
	var sealed bool
	err := s.db.QueryRowContext(ctx, `
		SELECT t.secret, t.sealed, t.confirmed_at, t.created_at, t.last_used_at
		FROM totp_credentials t
		JOIN users u ON u.id = t.user_id
		WHERE `+ciEq("u.username", "$1")+`;`, username).
		Scan(&c.Secret, &sealed, &confirmed, &created, &lastUsed)
	if err != nil {
		return TOTPCredential{}, translateErr("store.TOTP", err)
	}

	/*
	 * Mühürlü satır, anahtar olmadan AÇIK HATA verir.
	 *
	 * ⚠️ Sessizce mühürlü değeri döndürmek çok daha kötü olurdu: çağıran onu
	 * sır sanıp kod üretir, üretilen kod hiçbir zaman tutmaz ve kullanıcı
	 * "doğru kodu giriyorum ama kabul etmiyor" hâline düşer — nedeni hiçbir
	 * yerde görünmeden.
	 *
	 * sealed=false satırlar 033 öncesinden kalma; anahtarsız da okunurlar ve
	 * ilk başarılı kullanımda mühürlenirler (UseTOTPStep).
	 */
	if sealed {
		if s.box == nil {
			return TOTPCredential{}, fmt.Errorf(
				"store.TOTP[%s]: secret key not configured; run `postern secret init`",
				username)
		}
		plain, uerr := s.box.Unseal(c.Secret)
		if uerr != nil {
			return TOTPCredential{}, fmt.Errorf("store.TOTP[%s]: %w", username, uerr)
		}
		c.Secret = plain
	}
	c.CreatedAt = time.Unix(created, 0).UTC()
	if confirmed.Valid {
		c.Confirmed = true
		c.ConfirmedAt = time.Unix(confirmed.Int64, 0).UTC()
	}
	if lastUsed.Valid {
		c.LastUsedAt = time.Unix(lastUsed.Int64, 0).UTC()
	}
	return c, nil
}

/*
 * UseTOTPStep, bir adımı TÜKETİR ve daha önce kullanılmışsa reddeder.
 *
 * ⚠️ TEK BİR İFADEDE KARŞILAŞTIR-VE-YAZ. Önce okuyup sonra yazan bir
 * uygulama, aynı kodla gönderilen İKİ eşzamanlı isteğin ikisini de
 * geçirirdi: her ikisi de eski değeri okur, her ikisi de kabul eder.
 * Tekrar korumasının bütün anlamı tam olarak o yarışı kapatmak.
 *
 * `last_step < $2` aynı zamanda pencere içindeki DAHA ESKİ adımları da
 * kapatıyor: adım N kullanıldıysa, hâlâ geçerli olan N-1 kodu da ölür.
 */
func (s *Store) UseTOTPStep(ctx context.Context, username string, step int64) error {
	userID, err := s.userID(ctx, username)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE totp_credentials
		SET last_step = $2, last_used_at = $3
		WHERE user_id = $1
		  AND confirmed_at IS NOT NULL
		  AND last_step < $2;`, userID, step, time.Now().Unix())
	if err != nil {
		return translateErr("store.UseTOTPStep", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store.UseTOTPStep[%s]: code already used: %w",
			username, ErrConflict)
	}

	// 033 öncesinden kalma düz metin satırı, BAŞARILI kullanımdan sonra
	// mühürle. Buraya bağlı olmasının sebebi: kodun tuttuğunu bildiğimiz tek
	// an burası, yani mühürlediğimiz değerin doğru sır olduğunu biliyoruz.
	s.upgradeTOTPSeal(ctx, userID)
	return nil
}

/*
 * upgradeTOTPSeal, düz metin kalmış bir TOTP sırrını yerinde mühürler.
 *
 * ⚠️ SESSİZ VE İSTEĞE BAĞLI. Hatası yutuluyor, çünkü bu bir yükseltme
 * işlemi ve BAŞARILI bir doğrulamanın ardından koşuyor: burada dönen bir
 * hata kullanıcının girişini düşürseydi, mühürleme çabası ikinci faktörü
 * çalışmaz hâle getiren şeyin ta kendisi olurdu. Mühürlenemeyen satır bir
 * sonraki kullanımda yeniden denenir; o zamana kadar 033 öncesi gibi
 * okunmaya devam eder.
 *
 * Anahtar yoksa hiç denemiyor: mühür anahtarsız kurulamaz ve bu yol,
 * BeginTOTP'nin aksine, operatöre söylenecek bir şey değil — kayıt zaten
 * çalışıyor.
 */
func (s *Store) upgradeTOTPSeal(ctx context.Context, userID string) {
	if s.box == nil {
		return
	}
	var plain string
	err := s.db.QueryRowContext(ctx,
		`SELECT secret FROM totp_credentials WHERE user_id = $1 AND NOT sealed;`,
		userID).Scan(&plain)
	if err != nil {
		return // zaten mühürlü ya da satır yok
	}
	sealed, err := s.box.Seal(plain)
	if err != nil {
		return
	}
	// NOT sealed koşulu tekrar: araya giren eşzamanlı bir yükseltme varsa
	// onun yazdığının üstüne yazmıyoruz.
	_, _ = s.db.ExecContext(ctx,
		`UPDATE totp_credentials SET secret = $2, sealed = TRUE
		 WHERE user_id = $1 AND NOT sealed;`, userID, sealed)
}

// DisableTOTP, ikinci faktörü kaldırır.
func (s *Store) DisableTOTP(ctx context.Context, username string) error {
	userID, err := s.userID(ctx, username)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM totp_credentials WHERE user_id = $1;`, userID)
	if err != nil {
		return translateErr("store.DisableTOTP", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store.DisableTOTP[%s]: %w", username, ErrNotFound)
	}
	return nil
}

/*
 * userID, kullanıcı adını kimliğe çevirir.
 *
 * ⚠️ ORTAK rowID'YE DEVREDİYOR — kendi sorgusunu yazıyordu ve o sorgu
 * `username = $1` idi, yani HARF DUYARLI. users.username 019'dan beri
 * harf duyarsız tekil ve ciColumns'ta yazılı; rowID o tabloyu görünce
 * ciEq'e geçiyor. Bu dosyanın OKUMA yolu (TOTP) zaten ciEq kullanıyordu,
 * dört YAZMA yolu kullanmıyordu.
 *
 * Bugün bunu sömüren bir yüzey ölçülemedi. Ama ortak yardımcının
 * dayattığı bir kuralı kopyalayıp düşüren bir fonksiyon, tam olarak
 * ciColumns'ın var olma sebebini ortadan kaldırıyor: kural tek yerde
 * yazılı olmalı, yoksa bir sonraki çağıran onu tekrar kaybediyor.
 */
func (s *Store) userID(ctx context.Context, username string) (string, error) {
	return s.rowID(ctx, "store.userID", "users", "username", username)
}
