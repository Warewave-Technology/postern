package auth

import (
	"errors"
	"strings"
	"testing"
)

// Politikanın işi, insanların gerçekten seçtiği zayıf değerleri elemek.
// Buradaki her satır bir insanın yazabileceği bir değer.
func TestPolicyRejectsWhatPeopleActuallyPick(t *testing.T) {
	p := DefaultPasswordPolicy()

	cases := []struct {
		pw   string
		want string // hata metninde geçmesi beklenen parça
		why  string
	}{
		{"kisa1234", "at least 12", "12 karakterin altı"},
		{"aaaaaaaaaaaaaa", "different characters", "uzun ama tek karakter"},
		{"ababababababab", "different characters", "uzun ama iki karakter"},
		{"123456789012", "run of neighbouring", "uzun ama düz rakam sırası"},
		{"abcdefghijklm", "run of neighbouring", "alfabetik sıra"},
		{"qwertyuiopas", "run of neighbouring", "klavye sırası"},
		{"ayse.yilmaz2026", "your username", "kullanıcı adını içeriyor"},
		{"PosternBastion1", "postern", "ürün adını içeriyor"},
		{"Password2026!", "commonly chosen", "sondaki rakamlar atılınca en yaygın kök"},
		{"parola-20261", "commonly chosen", "Türkçe kök de sayılıyor"},
	}

	for _, c := range cases {
		err := p.Check(c.pw, "ayse.yilmaz")
		if err == nil {
			t.Errorf("%q kabul edildi — %s", c.pw, c.why)
			continue
		}
		if !errors.Is(err, ErrWeakPassword) {
			t.Errorf("%q: hata sarmalanmamış: %v", c.pw, err)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: sebep %q içermeli, dönen: %v", c.pw, c.want, err)
		}
	}
}

// ⚠️ POLİTİKA, MAKUL PAROLALARI GEÇİRMEK ZORUNDA. Geçirmeyen bir
// politika, insanları kuralı sağlayan en tahmin edilebilir kalıba iter
// — yani kendi amacını bozar.
func TestPolicyAcceptsReasonablePasswords(t *testing.T) {
	p := DefaultPasswordPolicy()
	for _, pw := range []string{
		"kirmizi-bisiklet-42",
		"Tuz Biber Limon 9",
		"n7Kq2wLp8xZa",
		"benim kedim çok uyuyor",
	} {
		if err := p.Check(pw, "ayse.yilmaz"); err != nil {
			t.Errorf("%q reddedildi: %v", pw, err)
		}
	}
}

// Kullanıcı adı kontrolü harf duyarsız: "AYSE" yazmak kuralı atlatmıyor.
func TestPolicyUsernameCheckIgnoresCase(t *testing.T) {
	p := DefaultPasswordPolicy()
	if err := p.Check("XX-AYSE.YILMAZ-XX", "ayse.yilmaz"); err == nil {
		t.Fatal("büyük harfle yazılan kullanıcı adı kuralı atlattı")
	}
}

/*
 * ⚠️ ALT SINIR AYARLANABİLİR DEĞİL.
 *
 * Kapattığı somut açık: paneli ele geçiren bir yönetici
 * `password.min_length = 1` yazıp politikayı tamamen kapatabilirdi —
 * bir ayar değişikliği gibi görünen, aslında bir güvenlik kontrolünü
 * söken hamle.
 */
func TestPolicyFloorCannotBeLowered(t *testing.T) {
	for _, v := range []string{"1", "4", "7", "0", "-3"} {
		if n, err := ParsePasswordMinLength(v); err == nil {
			t.Errorf("min_length=%s kabul edildi (%d) — taban delinmiş", v, n)
		}
	}
	for _, v := range []string{"on iki", "", "12x", "1e3"} {
		if _, err := ParsePasswordMinLength(v); err == nil {
			t.Errorf("min_length=%q kabul edildi — çözülemeyen değer sessizce geçti", v)
		}
	}
	if n, err := ParsePasswordMinLength("16"); err != nil || n != 16 {
		t.Fatalf("geçerli değer reddedildi: %d %v", n, err)
	}
}

// Doğrulama gidiş-dönüş: hash edilen parola doğrulanıyor, benzeri
// doğrulanmıyor.
func TestPasswordRoundTrip(t *testing.T) {
	v, err := HashPassword("kirmizi-bisiklet-42")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(v, "kirmizi-bisiklet-42") {
		t.Fatal("doğru parola doğrulanmadı")
	}
	if VerifyPassword(v, "kirmizi-bisiklet-43") {
		t.Fatal("yanlış parola doğrulandı")
	}
	if VerifyPassword(v, "") {
		t.Fatal("boş parola doğrulandı")
	}
}

/*
 * ⚠️ İKİ YOL BİRBİRİNİ KABUL ETMİYOR.
 *
 * Bu testin kapattığı şey postern'in en keskin iddiası: kurumsal
 * parolasını yerel kutucuğa yazan kişinin değeri, sır tutan bir hesapta
 * hiçbir zaman DOĞRULANMIYOR. Tersi de geçerli — makine üretimi bir sır,
 * parola yolundan kabul edilmiyor.
 */
func TestTheTwoCredentialKindsDoNotAcceptEachOther(t *testing.T) {
	secret, secretVerifier, err := NewLocalSecret()
	if err != nil {
		t.Fatal(err)
	}
	pwVerifier, err := HashPassword("kirmizi-bisiklet-42")
	if err != nil {
		t.Fatal(err)
	}

	// Sır yolundan parola: biçim kontrolüne takılıyor.
	if VerifyLocalSecret(secretVerifier, "kirmizi-bisiklet-42") {
		t.Error("sır yolu bir parolayı kabul etti")
	}
	// Parola yolundan sır: doğrulayıcı eşleşmiyor.
	if VerifyPassword(pwVerifier, secret) {
		t.Error("parola yolu bir sırrı kabul etti")
	}
	// Kendi yollarında ikisi de çalışıyor.
	if !VerifyLocalSecret(secretVerifier, secret) {
		t.Error("sır kendi yolunda doğrulanmadı")
	}
	if !VerifyPassword(pwVerifier, "kirmizi-bisiklet-42") {
		t.Error("parola kendi yolunda doğrulanmadı")
	}
}
