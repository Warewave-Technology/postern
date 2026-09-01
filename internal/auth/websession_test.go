package auth

// S4.1 birim merdiveni — ağsız, IdP'siz:
//
//	go test ./internal/auth/ -run TestWebSession -v

import (
	"errors"
	"testing"
	"time"
)

func TestWebSessionRoundTrip(t *testing.T) {
	w := NewWebSessions()

	tok, err := w.Create("yigit")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(tok) < 43 {
		t.Errorf("token %d karakter — 32 bayt entropi bekleniyor", len(tok))
	}

	tok2, err := w.Create("yigit")
	if err != nil {
		t.Fatal(err)
	}
	if tok == tok2 {
		t.Fatal("iki oturum aynı token'ı aldı")
	}

	name, err := w.Resolve(tok)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if name != "yigit" {
		t.Errorf("Resolve = %q, beklenen %q", name, "yigit")
	}
}

func TestWebSessionUnknownToken(t *testing.T) {
	w := NewWebSessions()
	if _, err := w.Resolve("hic-var-olmadi"); !errors.Is(err, ErrNoSession) {
		t.Fatalf("hata = %v, beklenen ErrNoSession", err)
	}
}

func TestWebSessionDestroy(t *testing.T) {
	w := NewWebSessions()

	tok, err := w.Create("yigit")
	if err != nil {
		t.Fatal(err)
	}

	w.Destroy(tok)
	if _, err := w.Resolve(tok); !errors.Is(err, ErrNoSession) {
		t.Fatalf("logout sonrası Resolve = %v, beklenen ErrNoSession", err)
	}

	// Çifte logout hata değil.
	w.Destroy(tok)
}

func TestWebSessionExpiry(t *testing.T) {
	w := NewWebSessions()

	// Sahte saat: süreyi bekleyerek değil, zamanı oynatarak sınıyoruz.
	current := time.Now()
	w.now = func() time.Time { return current }

	tok, err := w.Create("yigit")
	if err != nil {
		t.Fatal(err)
	}

	// Süre MUTLAK: son saniyede hâlâ geçerli...
	current = current.Add(webSessionTTL - time.Second)
	if _, err := w.Resolve(tok); err != nil {
		t.Fatalf("süre dolmadan reddedildi: %v", err)
	}

	// ...bir saniye sonrasında değil.
	current = current.Add(2 * time.Second)
	if _, err := w.Resolve(tok); !errors.Is(err, ErrNoSession) {
		t.Fatalf("süresi dolmuş token kabul edildi: %v", err)
	}

	// Ve aktivite süreyi UZATMAMALI (kayan pencere değil): yeni oturum
	// açıp yarı sürede dokunmak, kalan yarıyı değiştirmez.
	tok2, err := w.Create("yigit")
	if err != nil {
		t.Fatal(err)
	}
	current = current.Add(webSessionTTL / 2)
	if _, err := w.Resolve(tok2); err != nil {
		t.Fatal(err)
	}
	current = current.Add(webSessionTTL/2 + time.Second)
	if _, err := w.Resolve(tok2); !errors.Is(err, ErrNoSession) {
		t.Fatal("dokunulan oturumun süresi uzamış — kayan pencere istenmiyordu")
	}
}

/*
 * ⚠️ OTURUMUN VAR OLMASI, KİMLİĞİN AZ ÖNCE KANITLANMASI DEĞİLDİR.
 *
 * 12 saat yaşayan bir belirteci çalan biri, hesabın sahibi kadar "giriş
 * yapmış" görünüyor. İkinci faktör bağlamak gibi kalıcı sonuçlu adımlar
 * TAZE bir kanıt istiyor (httpapi/totp.go) ve tazeliğin ölçüsü burası.
 */
func TestSessionAgeGrowsWithTheClock(t *testing.T) {
	w := NewWebSessions()
	current := time.Now()
	w.now = func() time.Time { return current }

	token, err := w.Create("yigit")
	if err != nil {
		t.Fatal(err)
	}

	age, err := w.Age(token)
	if err != nil {
		t.Fatal(err)
	}
	if age != 0 {
		t.Fatalf("yeni oturumun yaşı = %v, 0 bekleniyordu", age)
	}

	current = current.Add(30 * time.Minute)
	age, err = w.Age(token)
	if err != nil {
		t.Fatal(err)
	}
	if age != 30*time.Minute {
		t.Fatalf("yaş = %v, 30dk bekleniyordu — bayat bir oturum taze "+
			"görünürse, çalınmış bir oturum ikinci faktör bağlayabilir", age)
	}
}

// Süresi dolmuş oturumun yaşı SORULAMAZ: "bilinmiyor"u "çok taze" diye
// okutmamak için hata dönüyor.
func TestExpiredSessionHasNoAge(t *testing.T) {
	w := NewWebSessions()
	current := time.Now()
	w.now = func() time.Time { return current }

	token, _ := w.Create("yigit")
	current = current.Add(webSessionTTL + time.Second)

	if _, err := w.Age(token); !errors.Is(err, ErrNoSession) {
		t.Fatalf("süresi dolmuş oturumun yaşı döndü: %v", err)
	}
}

func TestUnknownTokenHasNoAge(t *testing.T) {
	w := NewWebSessions()
	if _, err := w.Age("yok-boyle-bir-sey"); !errors.Is(err, ErrNoSession) {
		t.Fatalf("bilinmeyen belirteç için yaş döndü: %v", err)
	}
}
