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
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

func testLogins() *Logins { return NewLogins(testHolder()) }

func TestOOBStartLinkAndCode(t *testing.T) {
	l := testLogins()

	a, err := l.Start("10.0.0.1:2222")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	b, err := l.Start("10.0.0.1:2222")
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

	a, err := l.Start("10.0.0.1:2222")
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

	a, err := l.Start("10.0.0.1:2222")
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

	a, err := l.Start("10.0.0.1:2222")
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

	a, err := l.Start("10.0.0.1:2222")
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

	a, err := l.Start("10.0.0.1:2222")
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
	l := NewLogins(testHolder())
	l.SetMaxPending(2)

	// FARKLI kaynaklar: sınanan şey KÜRESEL kota. Aynı adresten
	// gelseler kaynak başına pay devreye girerdi (bkz.
	// TestPerSourceQuotaLimitsOneAttacker).
	a1, err := l.Start("10.0.0.1:2222")
	if err != nil {
		t.Fatalf("ilk deneme: %v", err)
	}
	if _, err := l.Start("10.0.0.2:2222"); err != nil {
		t.Fatalf("ikinci deneme: %v", err)
	}

	if _, err := l.Start("10.0.0.3:2222"); !errors.Is(err, ErrTooManyPending) {
		t.Errorf("üçüncü deneme = %v, ErrTooManyPending bekleniyordu", err)
	}

	l.Drop(a1)

	if _, err := l.Start("10.0.0.3:2222"); err != nil {
		t.Errorf("yer açıldıktan sonra hâlâ reddediyor: %v", err)
	}
}

// Sınır 0 iken kota uygulanmamalı.
func TestMaxPendingZeroIsUnlimited(t *testing.T) {
	l := NewLogins(testHolder())

	for i := 0; i < 50; i++ {
		if _, err := l.Start(fmt.Sprintf("10.0.0.%d:2222", i)); err != nil {
			t.Fatalf("%d. deneme reddedildi: %v", i, err)
		}
	}
}

// Kod, kimlik PARK EDİLMEDEN tarayıcıya verilmemeli.
//
// ⚠️ Bu, device-code phishing düzeltmesinin bel kemiği. state'i bilen
// tek kişi denemeyi BAŞLATAN kişidir — yani saldırgan. Kod park
// edilmeden servis edilseydi, saldırgan Challenge'ı kendisi çağırıp
// kodu alır ve yön değişikliği hiçbir işe yaramazdı.
func TestChallengeIsNotServedBeforePark(t *testing.T) {
	l := NewLogins(testHolder())

	a, err := l.Start("203.0.113.7:52344")
	if err != nil {
		t.Fatal(err)
	}

	if _, _, ok := l.Challenge(a.State()); ok {
		t.Fatal("KOD PARK EDİLMEDEN VERİLDİ — saldırgan kodu kendisi çekebilir")
	}

	if err := l.Park(a.State(), Identity{Username: "yigit"}); err != nil {
		t.Fatal(err)
	}

	code, source, ok := l.Challenge(a.State())
	if !ok {
		t.Fatal("park edildikten sonra kod verilmedi")
	}
	if code != a.UserCode {
		t.Errorf("kod = %q, beklenen %q", code, a.UserCode)
	}
	// Kaynak adres kurbana gösterilecek: "bunu ben başlatmadım"
	// diyebilmesinin tek somut dayanağı.
	if source != "203.0.113.7:52344" {
		t.Errorf("kaynak = %q, SSH bağlantısının adresi olmalıydı", source)
	}
}

// Tarayıcı bitirmeden gelen kod denemeyi YAKMAMALI: kullanıcı erken
// ENTER'a basmış olabilir ve baştan başlamaya zorlanmamalı.
func TestEarlyConfirmDoesNotBurnTheAttempt(t *testing.T) {
	l := NewLogins(testHolder())

	a, err := l.Start("10.0.0.1:2222")
	if err != nil {
		t.Fatal(err)
	}

	if err := l.Confirm(a.State(), "ne-olursa"); !errors.Is(err, ErrNotReady) {
		t.Fatalf("erken onay = %v, ErrNotReady bekleniyordu", err)
	}

	// Deneme hâlâ yaşıyor olmalı.
	if err := l.Park(a.State(), Identity{Username: "yigit"}); err != nil {
		t.Fatalf("erken onay denemeyi yakmış: %v", err)
	}
	if err := l.Confirm(a.State(), a.UserCode); err != nil {
		t.Errorf("doğru kod reddedildi: %v", err)
	}
}

// Yanlış kod denemeyi YAKMALI: kaba kuvvet tek atışlık olmalı.
func TestWrongConfirmBurnsTheAttempt(t *testing.T) {
	l := NewLogins(testHolder())

	a, err := l.Start("10.0.0.1:2222")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Park(a.State(), Identity{Username: "yigit"}); err != nil {
		t.Fatal(err)
	}

	if err := l.Confirm(a.State(), "YANLIS-KOD"); !errors.Is(err, ErrLoginDenied) {
		t.Fatalf("yanlış kod = %v, ErrLoginDenied bekleniyordu", err)
	}
	// Artık doğru kod bile kabul edilmemeli.
	if err := l.Confirm(a.State(), a.UserCode); err == nil {
		t.Error("yanlış koddan sonra doğru kod kabul edildi — deneme yanmamış")
	}
}

// ⚠️ Tek bir kaynak, tarayıcı girişini HERKESE kapatamamalı.
//
// Kapatılan DoS: kota yalnızca küreseldi ve GET tarafı kimlik
// doğrulaması istemiyor. Bağlantı sınırının izin verdiği kadar deneme
// açan bir saldırgan (varsayılan IP başına 8), dört kaynaktan 32'lik
// kotayı doldurup SSO kapısını kapatabiliyordu.
func TestPerSourceQuotaLimitsOneAttacker(t *testing.T) {
	l := NewLogins(testHolder())
	l.SetMaxPending(8) // kaynak başına pay: 2

	// Saldırgan payını doldurur.
	for i := 0; i < 2; i++ {
		if _, err := l.Start("203.0.113.7:1000"); err != nil {
			t.Fatalf("saldırganın %d. denemesi: %v", i, err)
		}
	}
	if _, err := l.Start("203.0.113.7:1001"); !errors.Is(err, ErrTooManyPending) {
		t.Errorf("saldırgan payını aştı: %v", err)
	}

	// MEŞRU kullanıcı başka bir adresten hâlâ girebilmeli.
	if _, err := l.Start("10.0.0.5:2000"); err != nil {
		t.Errorf("başka kaynaktan meşru giriş engellendi: %v", err)
	}
}

// Küresel kota da yerinde durmalı.
func TestGlobalQuotaStillApplies(t *testing.T) {
	l := NewLogins(testHolder())
	l.SetMaxPending(4) // kaynak başına 1

	for i := 0; i < 4; i++ {
		src := fmt.Sprintf("10.0.0.%d:1000", i)
		if _, err := l.Start(src); err != nil {
			t.Fatalf("%d. deneme: %v", i, err)
		}
	}
	if _, err := l.Start("10.0.0.99:1000"); !errors.Is(err, ErrTooManyPending) {
		t.Errorf("küresel kota aşıldı: %v", err)
	}
}

// testHolder, testOIDC'yi çalışırken değiştirilebilir tutucuya sarar.
func testHolder() *OIDCHolder {
	h := NewOIDCHolder()
	h.Install(testOIDC())
	return h
}
