package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Warewave-Technology/postern/internal/secret"
)

/*
 * newTOTPStore, TOTP testleri için sır kutusu BAĞLANMIŞ bir Store döner.
 *
 * Göç 033'ten beri BeginTOTP anahtarsız kayıt açmayı reddediyor, yani TOTP'ye
 * dokunan her testin bir kutuya ihtiyacı var. Kutusuz davranışı sınayan
 * testler bilerek düz newTestStore kullanıyor.
 */
func newTOTPStore(t *testing.T) *Store {
	t.Helper()
	s := newTestStore(t)
	attachBox(t, s)
	return s
}

func attachBox(t *testing.T, s *Store) {
	t.Helper()
	box, err := secret.Init(filepath.Join(t.TempDir(), "secret.key"))
	if err != nil {
		t.Fatalf("secret.Init: %v", err)
	}
	s.UseSecretBox(box)
}

// rawTOTPSecret, satırdaki HAM değeri okur — mühürlü mü düz metin mi,
// onu store'un kendi okuma yolundan geçmeden görmek için.
func rawTOTPSecret(t *testing.T, s *Store, username string) (string, bool) {
	t.Helper()
	var raw string
	var sealed bool
	err := s.db.QueryRowContext(context.Background(), `
		SELECT t.secret, t.sealed FROM totp_credentials t
		JOIN users u ON u.id = t.user_id WHERE u.username = $1;`, username).
		Scan(&raw, &sealed)
	if err != nil {
		t.Fatalf("ham satır okunamadı: %v", err)
	}
	return raw, sealed
}

func seedTOTPUser(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.CreateUser(context.Background(), "yigit", "", "yigit"); err != nil {
		t.Fatal(err)
	}
}

func TestTOTPEnrollConfirmAndRead(t *testing.T) {
	ctx := context.Background()
	s := newTOTPStore(t)
	seedTOTPUser(t, s)

	if _, err := s.TOTP(ctx, "yigit"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("kayıtsız hesapta hata = %v, ErrNotFound bekleniyordu", err)
	}

	if err := s.BeginTOTP(ctx, "yigit", "SECRET123"); err != nil {
		t.Fatal(err)
	}

	c, err := s.TOTP(ctx, "yigit")
	if err != nil {
		t.Fatal(err)
	}
	/*
	 * ⚠️ DOĞRULANMAMIŞ KAYIT HİÇBİR ŞEYİ YETKİLENDİRMEMELİ.
	 *
	 * QR'ı hiç okutmamış biri, telefonunda karşılığı olmayan bir
	 * "ikinci faktör" taşıyor sanılırsa, gerçekte kimse doğrulanamaz.
	 */
	if c.Confirmed {
		t.Error("kod girilmeden kayıt doğrulanmış sayıldı")
	}

	if err := s.ConfirmTOTP(ctx, "yigit", 100); err != nil {
		t.Fatal(err)
	}
	c, _ = s.TOTP(ctx, "yigit")
	if !c.Confirmed || c.ConfirmedAt.IsZero() {
		t.Fatalf("onaydan sonra doğrulanmamış görünüyor: %+v", c)
	}
}

/*
 * ⚠️ DOĞRULANMIŞ KAYDIN ÜZERİNE SESSİZCE YAZILAMAMALI.
 *
 * Yazılabilseydi, oturumu çalınan bir hesapta saldırgan kaydı sıfırlayıp
 * kendi telefonunu bağlar ve ikinci faktör el değiştirirdi — üstelik
 * kullanıcı hâlâ "ikinci faktörüm var" sanarak.
 */
func TestEnrolledTOTPCannotBeSilentlyReplaced(t *testing.T) {
	ctx := context.Background()
	s := newTOTPStore(t)
	seedTOTPUser(t, s)

	if err := s.BeginTOTP(ctx, "yigit", "ILK"); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmTOTP(ctx, "yigit", 1); err != nil {
		t.Fatal(err)
	}

	err := s.BeginTOTP(ctx, "yigit", "SALDIRGANIN")
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("doğrulanmış kayıt üzerine yazıldı: %v", err)
	}
	c, _ := s.TOTP(ctx, "yigit")
	if c.Secret != "ILK" {
		t.Fatalf("sır değişmiş: %q", c.Secret)
	}
}

// Doğrulanmamış kayıt YENİDEN başlatılabilmeli: QR'ı kaybeden kullanıcı
// baştan başlayabilsin.
func TestUnconfirmedTOTPCanBeRestarted(t *testing.T) {
	ctx := context.Background()
	s := newTOTPStore(t)
	seedTOTPUser(t, s)

	if err := s.BeginTOTP(ctx, "yigit", "BIR"); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginTOTP(ctx, "yigit", "IKI"); err != nil {
		t.Fatalf("doğrulanmamış kayıt yeniden başlatılamadı: %v", err)
	}
	c, _ := s.TOTP(ctx, "yigit")
	if c.Secret != "IKI" {
		t.Fatalf("sır = %q", c.Secret)
	}
}

/*
 * ⚠️ AYNI KOD İKİ KEZ KULLANILAMAMALI.
 *
 * Bir TOTP kodu 30 saniye geçerli. Omuz üstünden okuyan ya da araya
 * giren biri onu ikinci kez kullanabilir — ve bu bağlamda ikinci
 * kullanım "bir anahtar daha ekle" demek.
 */
func TestUsedTOTPStepIsRefusedASecondTime(t *testing.T) {
	ctx := context.Background()
	s := newTOTPStore(t)
	seedTOTPUser(t, s)

	if err := s.BeginTOTP(ctx, "yigit", "S"); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmTOTP(ctx, "yigit", 500); err != nil {
		t.Fatal(err)
	}

	if err := s.UseTOTPStep(ctx, "yigit", 501); err != nil {
		t.Fatalf("yeni adım reddedildi: %v", err)
	}
	if err := s.UseTOTPStep(ctx, "yigit", 501); !errors.Is(err, ErrConflict) {
		t.Fatalf("aynı adım ikinci kez kabul edildi: %v", err)
	}
	// Pencere içindeki DAHA ESKİ adım da ölmüş olmalı: kullanılan
	// koddan önceki kod hâlâ geçerliyken kabul edilirse, tekrar
	// koruması bir adım kayarak atlatılır.
	if err := s.UseTOTPStep(ctx, "yigit", 500); !errors.Is(err, ErrConflict) {
		t.Fatalf("daha eski adım kabul edildi: %v", err)
	}
}

/*
 * ⚠️ TEKRAR KORUMASI YARIŞ ALTINDA DA TUTMALI — ÖLÇÜLÜYOR.
 *
 * Önce okuyup sonra yazan bir uygulama, aynı kodla gönderilen iki
 * eşzamanlı isteğin İKİSİNİ de geçirir: ikisi de eski değeri okur.
 * Korumanın bütün anlamı o yarışı kapatmak, dolayısıyla test de yarışı
 * gerçekten kurmak zorunda.
 */
func TestConcurrentUseOfOneCodeSucceedsExactlyOnce(t *testing.T) {
	ctx := context.Background()
	s := newTOTPStore(t)
	seedTOTPUser(t, s)

	if err := s.BeginTOTP(ctx, "yigit", "S"); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmTOTP(ctx, "yigit", 1000); err != nil {
		t.Fatal(err)
	}

	const racers = 16
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make([]error, racers)

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i] = s.UseTOTPStep(ctx, "yigit", 1001)
		}(i)
	}
	close(start)
	wg.Wait()

	var ok int
	for _, err := range results {
		if err == nil {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("%d eşzamanlı istekten %d tanesi geçti, tam 1 olmalıydı — "+
			"tekrar koruması yarış altında tutmuyor", racers, ok)
	}
}

// Doğrulanmamış kayıt hiçbir adımı tüketemez: yetkilendirme yapamaz.
func TestUnconfirmedTOTPCannotAuthorise(t *testing.T) {
	ctx := context.Background()
	s := newTOTPStore(t)
	seedTOTPUser(t, s)

	if err := s.BeginTOTP(ctx, "yigit", "S"); err != nil {
		t.Fatal(err)
	}
	if err := s.UseTOTPStep(ctx, "yigit", 42); err == nil {
		t.Fatal("doğrulanmamış kayıt bir adımı tüketti — telefonunda " +
			"karşılığı olmayan bir faktör yetki verdi")
	}
}

func TestDisableTOTPRemovesIt(t *testing.T) {
	ctx := context.Background()
	s := newTOTPStore(t)
	seedTOTPUser(t, s)

	if err := s.BeginTOTP(ctx, "yigit", "S"); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmTOTP(ctx, "yigit", 1); err != nil {
		t.Fatal(err)
	}
	if err := s.DisableTOTP(ctx, "yigit"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TOTP(ctx, "yigit"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("kapatıldıktan sonra hâlâ var: %v", err)
	}
	// Kapatmaktan sonra yeniden kayıt mümkün olmalı: telefon değiştiren
	// kullanıcı yöneticiye gitmek zorunda kalmasın.
	if err := s.BeginTOTP(ctx, "yigit", "YENI"); err != nil {
		t.Fatalf("kapatıldıktan sonra yeniden kayıt olmadı: %v", err)
	}
}

// ---------------------------------------------------------------------
// Göç 033: sır mühürlenerek saklanıyor.
// ---------------------------------------------------------------------

// insertPlainTOTP, 033 ÖNCESİ bir satırı birebir taklit eder: düz metin sır,
// sealed=false. Yükseltme yolunu sınayan testler bununla başlıyor.
func insertPlainTOTP(t *testing.T, s *Store, username, secret string, confirmed bool) {
	t.Helper()
	ctx := context.Background()
	uid, err := s.userID(ctx, username)
	if err != nil {
		t.Fatal(err)
	}
	var confirmedAt any
	if confirmed {
		confirmedAt = int64(1)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO totp_credentials (user_id, secret, sealed, confirmed_at, created_at)
		VALUES ($1, $2, FALSE, $3, 1);`, uid, secret, confirmedAt)
	if err != nil {
		t.Fatalf("düz metin satır eklenemedi: %v", err)
	}
}

func TestTOTPSecretIsSealedAtRest(t *testing.T) {
	ctx := context.Background()
	s := newTOTPStore(t)
	seedTOTPUser(t, s)

	const plain = "JBSWY3DPEHPK3PXP"
	if err := s.BeginTOTP(ctx, "yigit", plain); err != nil {
		t.Fatal(err)
	}

	raw, sealed := rawTOTPSecret(t, s, "yigit")
	if !sealed {
		t.Error("satır sealed=false; yeni kayıt mühürlenmeliydi")
	}
	if raw == plain {
		t.Error("sır veritabanında DÜZ METİN duruyor — mühürleme yapılmamış")
	}
	if strings.Contains(raw, plain) {
		t.Error("mühürlü değer düz metin sırrı içeriyor")
	}

	// Okuma yolu aynı sırrı geri vermeli, yoksa kod üretilemez.
	c, err := s.TOTP(ctx, "yigit")
	if err != nil {
		t.Fatal(err)
	}
	if c.Secret != plain {
		t.Errorf("okunan sır = %q, %q bekleniyordu", c.Secret, plain)
	}
}

func TestBeginTOTPRefusedWithoutSecretKey(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t) // KUTU YOK — kasıtlı
	seedTOTPUser(t, s)

	err := s.BeginTOTP(ctx, "yigit", "JBSWY3DPEHPK3PXP")
	if err == nil {
		t.Fatal("anahtarsız kayıt kabul edildi; düz metin yazılmış olurdu")
	}
	// Hata operatöre ne yapacağını söylemeli; "not configured" tek başına
	// yetmiyor.
	if !strings.Contains(err.Error(), "postern secret init") {
		t.Errorf("hata düzeltmeyi adlandırmıyor: %v", err)
	}
	// Ve satır AÇILMAMIŞ olmalı — yarım kayıt bırakmak, kullanıcıyı
	// "zaten kayıtlısın" hatasına düşürürdü.
	if _, err := s.TOTP(ctx, "yigit"); !errors.Is(err, ErrNotFound) {
		t.Errorf("başarısız kayıt satır bırakmış: %v", err)
	}
}

func TestPreSealTOTPRowStillReads(t *testing.T) {
	ctx := context.Background()
	s := newTOTPStore(t)
	seedTOTPUser(t, s)

	const plain = "OLDPLAINSECRET42"
	insertPlainTOTP(t, s, "yigit", plain, true)

	// ⚠️ Yükseltme kimsenin ikinci faktörünü kaybettirmemeli.
	c, err := s.TOTP(ctx, "yigit")
	if err != nil {
		t.Fatalf("033 öncesi satır okunamadı: %v", err)
	}
	if c.Secret != plain {
		t.Errorf("okunan sır = %q, %q bekleniyordu", c.Secret, plain)
	}
}

func TestPlainTOTPRowIsSealedAfterSuccessfulUse(t *testing.T) {
	ctx := context.Background()
	s := newTOTPStore(t)
	seedTOTPUser(t, s)

	const plain = "OLDPLAINSECRET42"
	insertPlainTOTP(t, s, "yigit", plain, true)

	if _, sealed := rawTOTPSecret(t, s, "yigit"); sealed {
		t.Fatal("başlangıç durumu yanlış: satır zaten mühürlü")
	}

	if err := s.UseTOTPStep(ctx, "yigit", 100); err != nil {
		t.Fatal(err)
	}

	raw, sealed := rawTOTPSecret(t, s, "yigit")
	if !sealed {
		t.Fatal("başarılı kullanımdan sonra satır hâlâ düz metin")
	}
	if raw == plain {
		t.Error("sealed=true ama değer hâlâ düz metin")
	}

	// Ve mühürledikten sonra hâlâ AYNI sır okunmalı; yanlış mühürlemek
	// kullanıcıyı sessizce dışarıda bırakırdı.
	c, err := s.TOTP(ctx, "yigit")
	if err != nil {
		t.Fatal(err)
	}
	if c.Secret != plain {
		t.Errorf("mühürlemeden sonra sır değişti: %q, %q bekleniyordu", c.Secret, plain)
	}
}

func TestSealedTOTPWithoutKeyIsAnExplicitError(t *testing.T) {
	ctx := context.Background()
	s := newTOTPStore(t)
	seedTOTPUser(t, s)

	const plain = "JBSWY3DPEHPK3PXP"
	if err := s.BeginTOTP(ctx, "yigit", plain); err != nil {
		t.Fatal(err)
	}

	// Anahtar kaybolmuş bir kurulumu taklit et.
	s.UseSecretBox(nil)

	c, err := s.TOTP(ctx, "yigit")
	if err == nil {
		t.Fatalf("anahtarsız mühürlü satır okundu ve sır olarak %q döndü; "+
			"bu değerle üretilen kod hiçbir zaman tutmaz", c.Secret)
	}
	if !strings.Contains(err.Error(), "postern secret init") {
		t.Errorf("hata düzeltmeyi adlandırmıyor: %v", err)
	}
}
