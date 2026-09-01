package store

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func seedTOTPUser(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.CreateUser(context.Background(), "yigit", "", "yigit"); err != nil {
		t.Fatal(err)
	}
}

func TestTOTPEnrollConfirmAndRead(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
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
	s := newTestStore(t)
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
	s := newTestStore(t)
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
	s := newTestStore(t)
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
	s := newTestStore(t)
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
	s := newTestStore(t)
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
	s := newTestStore(t)
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
