package totp

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

/*
 * ⚠️ RFC 6238 EK B'NİN RESMÎ TEST VEKTÖRLERİ.
 *
 * Bu paket elle yazıldı. Elle yazılmış bir kimlik doğrulama
 * primitifinin "çalışıyor" iddiası, kendi ürettiğini kendi doğrulayan
 * bir testle kanıtlanamaz: yanlış bir uygulama kendi kendisiyle
 * mükemmel uyumludur ve testler yeşil kalır. Vektörler belirtimden
 * geliyor — kullanıcının telefonundaki uygulamanın ürettiği şeyle aynı
 * kaynaktan.
 *
 * RFC'nin tablosu 8 haneli; bu paket 6 hane üretiyor (uygulamaların
 * fiilen desteklediği tek biçim), o yüzden vektörün son 6 hanesi
 * karşılaştırılıyor.
 */
func TestRFC6238Vectors(t *testing.T) {
	// RFC 6238'in SHA-1 anahtarı: "12345678901234567890" ASCII.
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).
		EncodeToString([]byte("12345678901234567890"))

	cases := []struct {
		unix int64
		want string // RFC'deki 8 haneli değer
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}

	for _, c := range cases {
		got, err := Code(secret, time.Unix(c.unix, 0).UTC())
		if err != nil {
			t.Fatalf("t=%d: %v", c.unix, err)
		}
		want := c.want[len(c.want)-Digits:]
		if got != want {
			t.Errorf("t=%d: kod = %q, RFC 6238 %q diyor — bu paketin "+
				"ürettiği kod kullanıcının telefonundakiyle uyuşmaz",
				c.unix, got, want)
		}
	}
}

func TestVerifyAcceptsTheCurrentCode(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	code, err := Code(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	ok, at, err := Verify(secret, code, now)
	if err != nil || !ok {
		t.Fatalf("geçerli kod reddedildi: ok=%v err=%v", ok, err)
	}
	if at != StepAt(now) {
		t.Errorf("adım = %d, %d bekleniyordu", at, StepAt(now))
	}
}

/*
 * ⚠️ PENCERE ±1 ADIM, DAHA GENİŞ DEĞİL.
 *
 * Telefon saati birkaç saniye kayabildiği için tolerans şart. Ama
 * pencereyi genişletmek her kodun ömrünü uzatır: ±3 adım, çalınan bir
 * kodu 3,5 dakika kullanılabilir kılar.
 */
func TestVerifyWindowIsExactlyOneStep(t *testing.T) {
	secret, _ := NewSecret()
	now := time.Now()

	for _, d := range []int{-1, 0, 1} {
		at := now.Add(time.Duration(d) * Period)
		code, _ := Code(secret, at)
		if ok, _, _ := Verify(secret, code, now); !ok {
			t.Errorf("%d adım kayma reddedildi — saat kayması olan "+
				"telefonlar kilitlenir", d)
		}
	}
	for _, d := range []int{-2, 2, 5} {
		at := now.Add(time.Duration(d) * Period)
		code, _ := Code(secret, at)
		if ok, _, _ := Verify(secret, code, now); ok {
			t.Errorf("%d adım kayma kabul edildi — kodun ömrü "+
				"gereğinden uzun", d)
		}
	}
}

// Yanlış kod, bozuk kod ve yanlış uzunluk reddedilmeli.
func TestVerifyRejectsBadInput(t *testing.T) {
	secret, _ := NewSecret()
	now := time.Now()
	good, _ := Code(secret, now)

	bad := []string{"", "000000", "12345", "1234567", "abcdef", good + "0"}
	for _, c := range bad {
		if c == good {
			continue
		}
		if ok, _, _ := Verify(secret, c, now); ok {
			t.Errorf("%q kabul edildi", c)
		}
	}
}

// Sır elle girilebiliyor: boşluk ve küçük harf tolere edilmeli.
//
// Kullanıcı QR okutamayıp sırrı elle yazdığında, uygulamaların
// gösterdiği "abcd efgh ijkl" biçimi reddedilseydi, kurtarma yolu
// kapanırdı.
func TestSecretIsTolerantOfHowPeopleTypeIt(t *testing.T) {
	secret, _ := NewSecret()
	now := time.Now()
	code, _ := Code(secret, now)

	spaced := strings.ToLower(secret[:4] + " " + secret[4:8] + " " + secret[8:])
	ok, _, err := Verify(spaced, code, now)
	if err != nil || !ok {
		t.Fatalf("boşluklu/küçük harfli sır reddedildi: ok=%v err=%v", ok, err)
	}
}

func TestSecretsAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		s, err := NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		if seen[s] {
			t.Fatal("aynı sır iki kez üretildi")
		}
		seen[s] = true
		if len(s) != 32 {
			t.Fatalf("sır uzunluğu = %d, 32 bekleniyordu (160 bit)", len(s))
		}
	}
}

/*
 * ⚠️ otpauth BAĞLANTISI, ISSUER'I İKİ YERDE TAŞIMALI.
 *
 * Uygulamaların bir kısmı yoldaki ön eki, bir kısmı sorgu parametresini
 * okuyor. Yalnızca birini yazmak, hesabın telefonda issuer'sız
 * görünmesine yol açar; iki bastion kullanan biri hangi kodun
 * hangisine ait olduğunu ayırt edemez.
 */
func TestURICarriesIssuerWhereAppsLookForIt(t *testing.T) {
	u := URI("postern", "yigit", "ABCDEF")
	for _, want := range []string{
		"otpauth://totp/postern:yigit",
		"issuer=postern",
		"secret=ABCDEF",
		"algorithm=SHA1",
		"digits=6",
		"period=30",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("URI %q içermiyor: %s", want, u)
		}
	}
}

// Geçersiz sır hata dönmeli, panik değil: değer veritabanından geliyor
// ve orada bozulmuş olabilir.
func TestInvalidSecretIsAnErrorNotAPanic(t *testing.T) {
	for _, s := range []string{"", "!!!!", "1"} {
		if _, _, err := Verify(s, "123456", time.Now()); err == nil && s != "" {
			t.Errorf("%q için hata beklenirdi", s)
		}
	}
}
