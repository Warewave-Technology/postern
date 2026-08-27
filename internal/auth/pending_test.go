package auth

// S3.3 birim merdiveni — IdP'siz, ağsız, hızlı:
//
//	go test ./internal/auth/ -run TestOOB -v
//
// Exchange bu testlerde HİÇ yok: kayıt yalnızca eşzamanlılık bilir.
// Uçtan uca kanıt test/integration/oob_test.go'da.

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

func testLogins() *Logins { return NewLogins(testOIDC()) }

func TestOOBStartLinkAndCode(t *testing.T) {
	l := testLogins()

	a, err := l.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	b, err := l.Start()
	if err != nil {
		t.Fatal(err)
	}

	// Link, Begin'in ürettiği URL olmalı ve state'i Lookup ile bulunur olmalı.
	u, err := url.Parse(a.URL)
	if err != nil {
		t.Fatalf("URL parse: %v", err)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatal("URL'de state yok")
	}
	if _, ok := l.Lookup(state); !ok {
		t.Fatal("Start'ın kaydettiği state Lookup'ta bulunamadı")
	}

	// Kod: okunabilir uzunlukta, karışmayan alfabe, denemeler arasında taze.
	code := strings.ReplaceAll(a.UserCode, "-", "")
	if len(code) < 8 {
		t.Errorf("UserCode = %q, tire hariç en az 8 karakter bekleniyor", a.UserCode)
	}
	for _, r := range code {
		if strings.ContainsRune("0O1Il", r) {
			t.Errorf("UserCode %q karıştırılabilir karakter içeriyor (%c)", a.UserCode, r)
		}
	}
	if a.UserCode == b.UserCode {
		t.Error("iki deneme aynı güvenlik kodunu aldı")
	}
	if a.URL == b.URL {
		t.Error("iki deneme aynı URL'yi aldı — state paylaşılıyor olabilir")
	}
}

func TestOOBHappyPath(t *testing.T) {
	l := testLogins()

	a, err := l.Start()
	if err != nil {
		t.Fatal(err)
	}
	state := stateOf(t, a)

	// SSH tarafı önce beklemeye geçsin — gerçek sırada Wait her zaman
	// Confirm'den öncedir.
	type res struct {
		id  Identity
		err error
	}
	done := make(chan res, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		id, err := a.Wait(ctx)
		done <- res{id, err}
	}()

	if err := l.Park(state, Identity{Subject: "s-1", Email: "yigit@warewave.io"}); err != nil {
		t.Fatalf("Park: %v", err)
	}
	if err := l.Confirm(state, a.UserCode); err != nil {
		t.Fatalf("Confirm: %v", err)
	}

	r := <-done
	if r.err != nil {
		t.Fatalf("Wait: %v", r.err)
	}
	if r.id.Email != "yigit@warewave.io" {
		t.Errorf("Wait'in teslim aldığı kimlik = %+v", r.id)
	}

	// Sonuçlanan deneme kayıttan düşmüş olmalı.
	if _, ok := l.Lookup(state); ok {
		t.Error("teslim edilen deneme hâlâ Lookup'ta — tek kullanımlık değil")
	}
}

func TestOOBWaitTimesOutCleanly(t *testing.T) {
	l := testLogins()

	a, err := l.Start()
	if err != nil {
		t.Fatal(err)
	}
	state := stateOf(t, a)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if _, err := a.Wait(ctx); err == nil {
		t.Fatal("süre dolduğunda Wait hata dönmeli")
	}

	// SSH tarafı gitti; deneme artık KİMSEYE teslim edilemez. Sonradan
	// gelen Park boşluğa "başarılı" dememeli.
	if err := l.Park(state, Identity{Subject: "s"}); !errors.Is(err, ErrUnknownAttempt) {
		t.Fatalf("timeout sonrası Park = %v, beklenen ErrUnknownAttempt", err)
	}
}

func TestOOBWrongCodeBurnsTheAttempt(t *testing.T) {
	l := testLogins()

	a, err := l.Start()
	if err != nil {
		t.Fatal(err)
	}
	state := stateOf(t, a)

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := a.Wait(ctx)
		done <- err
	}()

	if err := l.Park(state, Identity{Subject: "s"}); err != nil {
		t.Fatal(err)
	}

	if err := l.Confirm(state, "YANLIS-KOD"); err == nil {
		t.Fatal("yanlış kod kabul edildi")
	}

	// Yanan denemenin Wait'i ErrLoginDenied ile uyanmalı — sessizce
	// sarkan bir SSH bağlantısı bırakmak yok.
	if err := <-done; !errors.Is(err, ErrLoginDenied) {
		t.Fatalf("Wait = %v, beklenen ErrLoginDenied", err)
	}

	// Ve DOĞRU kod artık işe yaramamalı: tekrar hakkı kaba kuvvete yarar.
	if err := l.Confirm(state, a.UserCode); !errors.Is(err, ErrUnknownAttempt) {
		t.Fatalf("yanan denemede Confirm = %v, beklenen ErrUnknownAttempt", err)
	}
}

func TestOOBParkIsSingleUse(t *testing.T) {
	l := testLogins()

	a, err := l.Start()
	if err != nil {
		t.Fatal(err)
	}
	state := stateOf(t, a)

	if err := l.Park(state, Identity{Subject: "ilk"}); err != nil {
		t.Fatal(err)
	}
	// Aynı callback'in ikinci oynatılışı: saldırı işareti, no-op değil.
	if err := l.Park(state, Identity{Subject: "ikinci"}); err == nil {
		t.Fatal("ikinci Park kabul edildi — callback tekrar oynatılabilir")
	}
}

func TestOOBConfirmBeforeParkRejected(t *testing.T) {
	l := testLogins()

	a, err := l.Start()
	if err != nil {
		t.Fatal(err)
	}
	// Callback'ten önce onay formu göndermek: parkta kimlik yok.
	if err := l.Confirm(stateOf(t, a), a.UserCode); err == nil {
		t.Fatal("kimlik parkta değilken Confirm kabul edildi")
	}
}

func stateOf(t *testing.T, a *Attempt) string {
	t.Helper()
	u, err := url.Parse(a.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("state")
}

// Bekleyen giriş kotası: dolduğunda reddetmeli, boşaldığında yeniden
// kabul etmeli.
//
// İkinci yarı olmadan test, kotanın MANDALLANDIĞINI (bir kez dolunca
// hep dolu kalması) fark edemezdi — ve o hâlde tek bir yük dalgası
// tarayıcı girişini kalıcı olarak kapatırdı.
func TestMaxPendingRefusesThenReleases(t *testing.T) {
	l := NewLogins(testOIDC())
	l.SetMaxPending(2)

	a1, err := l.Start()
	if err != nil {
		t.Fatalf("ilk deneme: %v", err)
	}
	if _, err := l.Start(); err != nil {
		t.Fatalf("ikinci deneme: %v", err)
	}

	if _, err := l.Start(); !errors.Is(err, ErrTooManyPending) {
		t.Errorf("üçüncü deneme = %v, ErrTooManyPending bekleniyordu", err)
	}

	l.Drop(a1)

	if _, err := l.Start(); err != nil {
		t.Errorf("yer açıldıktan sonra hâlâ reddediyor: %v", err)
	}
}

// Sınır 0 iken kota uygulanmamalı.
func TestMaxPendingZeroIsUnlimited(t *testing.T) {
	l := NewLogins(testOIDC())

	for i := 0; i < 50; i++ {
		if _, err := l.Start(); err != nil {
			t.Fatalf("%d. deneme reddedildi: %v", i, err)
		}
	}
}
