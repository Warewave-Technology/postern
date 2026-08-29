package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestLocalSecretRoundTrip(t *testing.T) {
	secret, verifier, err := NewLocalSecret()
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyLocalSecret(verifier, secret) {
		t.Fatal("üretilen sır kendi doğrulayıcısını geçmedi")
	}
	if strings.Contains(verifier, secret) {
		t.Fatal("doğrulayıcı sırrın kendisini içeriyor")
	}
	if !strings.HasPrefix(verifier, "argon2id$") {
		t.Fatalf("doğrulayıcı biçimi kendini tanımlamıyor: %q", verifier)
	}
}

// İki üretim asla aynı olmamalı — ne sır ne de tuz.
func TestLocalSecretIsUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 25 {
		s, v, err := NewLocalSecret()
		if err != nil {
			t.Fatal(err)
		}
		if seen[s] {
			t.Fatal("aynı sır iki kez üretildi")
		}
		if seen[v] {
			t.Fatal("aynı doğrulayıcı iki kez üretildi — tuz sabit olabilir")
		}
		seen[s], seen[v] = true, true
	}
}

/*
 * ⚠️ EN ÖNEMLİ TEST: postern'in üretemeyeceği bir değer KDF'e HİÇ
 * ulaşmamalı.
 *
 * Somut faydası şu: giriş kutucuğuna kurumsal parolasını yazan bir
 * operatörün parolası hash'lenmiyor, karşılaştırmaya girmiyor ve
 * hiçbir biçimde saklanmıyor — yalnızca biçimi tutmadığı için
 * reddediliyor. "Yerel parolanı AD parolan yapma" demek bir rica;
 * bunu kabul edecek bir yol bırakmamak bir özellik.
 */
func TestNormalizeRefusesAnythingNotMachineGenerated(t *testing.T) {
	bad := []string{
		"",
		"hunter2",
		"Kurumsal-Parolam-2026!",
		"kisa",
		strings.Repeat("A", 25), // bir eksik
		strings.Repeat("A", 27), // bir fazla
		strings.Repeat("1", 26), // base32'de 1 yok
		"AAAA-AAAA-AAAA-AAAA-AAAA-AA!",
	}
	for _, in := range bad {
		if _, err := NormalizeSecret(in); !errors.Is(err, ErrMalformedSecret) {
			t.Errorf("makine üretimi olmayan %q kabul edildi", in)
		}
	}
}

// Ayraçlar ve harf büyüklüğü doğrulamayı bozmamalı: sır ekrandan
// kopyalanabilir de, elle yazılabilir de.
func TestSecretAcceptsHumanTypedForms(t *testing.T) {
	secret, verifier, err := NewLocalSecret()
	if err != nil {
		t.Fatal(err)
	}
	plain := strings.ReplaceAll(secret, "-", "")

	for _, form := range []string{
		secret,
		plain,
		strings.ToLower(secret),
		strings.ToLower(plain),
		" " + secret + "\n",
		strings.ReplaceAll(secret, "-", " "),
	} {
		if !VerifyLocalSecret(verifier, form) {
			t.Errorf("elle yazılabilir biçim reddedildi: %q", form)
		}
	}
}

// Yanlış sır geçmemeli, ve bozuk bir doğrulayıcı "her şey geçer"e
// dönüşmemeli.
func TestVerifyRefusesWrongSecretAndBrokenVerifier(t *testing.T) {
	_, verifier, err := NewLocalSecret()
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := NewLocalSecret()
	if err != nil {
		t.Fatal(err)
	}
	if VerifyLocalSecret(verifier, other) {
		t.Fatal("başka bir sır kabul edildi")
	}

	valid, _, err := NewLocalSecret()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{
		"", "argon2id", "argon2id$v=19$m=1,t=1,p=1$@@@$@@@",
		"bcrypt$v=19$m=19456,t=2,p=1$AAAA$AAAA",
		strings.Repeat("x", 40),
	} {
		if VerifyLocalSecret(v, valid) {
			t.Errorf("bozuk doğrulayıcı %q ile giriş kabul edildi", v)
		}
	}
}
