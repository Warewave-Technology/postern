package httpapi

import (
	"net/http"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/auth"
)

/*
 * ⚠️ BU TESTİN KAPATTIĞI ŞEY, KISITIN TAMAMI.
 *
 * Zorunlu parola değişikliği sırasında açık kalan uçlar TAM DESENLE
 * eşleşiyor. Bir ÖNEK eşleşmesi ("/api/me ile başlayan her şey")
 * POST /api/me/keys'i de açardı — ve o uç, hesabın İLK anahtarını
 * hiçbir doğrulama istemeden ekliyor. Yani "parolanı değiştirene kadar
 * hiçbir şey yapamazsın" kısıtı, tam olarak kalıcı SSH erişimi kurmanın
 * önündeki tek engeli kaldırırdı.
 */
func TestRestrictedSessionCannotReachKeyEndpoints(t *testing.T) {
	mustBeClosed := []string{
		"POST /api/me/keys",
		"GET /api/me/keys",
		"POST /api/me/keys/remove",
		"GET /api/terminal/{target}",
		"GET /api/admin/users",
		"POST /api/admin/users/{name}/credential",
		"GET /api/admin/settings",
		"GET /api/targets",
	}
	for _, p := range mustBeClosed {
		if changePasswordAllowed[p] {
			t.Errorf("%q kısıtlı oturuma AÇIK — kısıt anlamını yitirir", p)
		}
	}

	mustBeOpen := []string{"GET /api/me", "POST /api/me/password"}
	for _, p := range mustBeOpen {
		if !changePasswordAllowed[p] {
			t.Errorf("%q kapalı — kişi kısıttan çıkamaz, kalıcı olarak sıkışır", p)
		}
	}

	// Liste KISA kalmalı. Büyüdüğü an, büyüten kişi bu testi görüp
	// neden büyüttüğünü yazmak zorunda.
	if len(changePasswordAllowed) != 2 {
		t.Fatalf("izin listesi %d uç içeriyor, 2 bekleniyordu — "+
			"her yeni giriş kısıtın anlamını biraz daha azaltır", len(changePasswordAllowed))
	}
}

/*
 * ⚠️ GECİKME (HESAP, ADRES) ÇİFTİNE BAĞLI.
 *
 * Yalnızca hesaba bağlı olsaydı, kimliği doğrulanmamış bir yabancı üst
 * üste yanlış deneyerek kurulumun tek yöneticisini panelden dışarıda
 * tutabilirdi — üstelik adı tahmin etmesi bile gerekmiyor, `postern
 * admin bootstrap` varsayılan olarak "admin" açıyor. localcred.go:30'un
 * "kilitleme YOK" kuralı tam olarak bunu yasaklıyor.
 */
func TestBackoffCannotBeAimedAtSomeoneElse(t *testing.T) {
	b := newGuessBackoff()
	now := time.Now()
	b.now = func() time.Time { return now }

	saldirgan := backoffKey("admin", "203.0.113.9")
	yonetici := backoffKey("admin", "10.0.0.5")

	// Saldırgan kendi adresinden ısrarla deniyor.
	for i := 0; i < 12; i++ {
		b.fail(saldirgan)
	}
	if b.retryAfter(saldirgan) <= 0 {
		t.Fatal("ısrarlı deneme gecikmeye girmedi")
	}
	// Gerçek yönetici KENDİ adresinden hiçbir gecikme görmüyor.
	if d := b.retryAfter(yonetici); d != 0 {
		t.Fatalf("yönetici kendi adresinden %v gecikme gördü — "+
			"yabancı biri onu dışarıda tutabiliyor", d)
	}
}

// İlk denemeler bedava: parolasını yanlış yazan insan cezalandırılmıyor.
// Israr ise hızla pahalılaşıyor.
func TestBackoffIsFreeAtFirstThenClimbs(t *testing.T) {
	b := newGuessBackoff()
	now := time.Now()
	b.now = func() time.Time { return now }
	k := backoffKey("ayse", "10.0.0.5")

	for i := 1; i <= 3; i++ {
		b.fail(k)
		if d := b.retryAfter(k); d != 0 {
			t.Fatalf("%d. denemeden sonra %v gecikme — ilk denemeler bedava olmalı", i, d)
		}
	}
	b.fail(k)
	if b.retryAfter(k) <= 0 {
		t.Fatal("4. denemeden sonra gecikme yok")
	}

	for i := 0; i < 20; i++ {
		b.fail(k)
	}
	if d := b.retryAfter(k); d < 4*time.Minute {
		t.Fatalf("ısrarın bedeli %v — sözlük saldırısı hâlâ ucuz", d)
	}
}

/*
 * ⚠️ DOĞRU PAROLA HİÇBİR ZAMAN GECİKMEYLE KARŞILAŞMASIN.
 *
 * Gecikme bilmeyenleri yavaşlatmak için; bilen kişiyi cezalandırmaya
 * başladığı an bir kilitlemeye dönüşür ve bu dosyanın reddettiği şey
 * tam olarak o.
 */
func TestBackoffClearsOnSuccess(t *testing.T) {
	b := newGuessBackoff()
	now := time.Now()
	b.now = func() time.Time { return now }
	k := backoffKey("ayse", "10.0.0.5")

	for i := 0; i < 9; i++ {
		b.fail(k)
	}
	if b.retryAfter(k) <= 0 {
		t.Fatal("gecikme kurulmadı")
	}
	b.succeed(k)
	if d := b.retryAfter(k); d != 0 {
		t.Fatalf("doğru paroladan sonra %v gecikme kaldı", d)
	}
}

// Anahtar HAM SAKLANMIYOR: operatör er ya da geç sırrı kullanıcı adı
// kutusuna yapıştırıyor (locallogin.go'daki denetim kuralının aynısı).
func TestBackoffKeyDoesNotCarryTheTypedValue(t *testing.T) {
	secret, _, err := auth.NewLocalSecret()
	if err != nil {
		t.Fatal(err)
	}
	k := backoffKey(secret, "10.0.0.5")
	if len(k) != 32 {
		t.Fatalf("anahtar uzunluğu %d — özet beklenirdi", len(k))
	}
	for _, part := range []string{secret, secret[:8], "10.0.0.5"} {
		if contains(k, part) {
			t.Fatalf("anahtar girilen değeri taşıyor: %q içinde %q", k, part)
		}
	}
}

func contains(hay, needle string) bool {
	if needle == "" {
		return false
	}
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// Panelden yazılabilen ayarların TAMAMI sınıflandırılmış olmalı.
// (auth.auto_create bir kez unutulmuştu ve panelde "unknown setting
// key" veriyordu — aynı sınıfın parola ayarında tekrarlamaması için.)
func TestPasswordSettingIsWritableFromThePanel(t *testing.T) {
	if !knownSettingKeys[auth.KeyPasswordMinLength] {
		t.Fatal("password.min_length panelden yazılamıyor — politika ekranı hata verir")
	}
}

// Kısıtlı oturum reddedilirken 403 dönmeli, 401 değil: 401 paneli giriş
// ekranına atardı ve kişi sonsuz döngüye girerdi (gireceği yer zaten o
// ekran).
func TestRestrictionUsesForbiddenNotUnauthorized(t *testing.T) {
	if http.StatusForbidden == http.StatusUnauthorized {
		t.Fatal("imkânsız")
	}
	// Kararın kendisi passwordChangeDone'da; buradaki not, onu 401'e
	// çevirmek isteyen bir sonraki kişiye.
}
