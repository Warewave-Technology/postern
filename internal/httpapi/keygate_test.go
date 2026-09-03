package httpapi

import (
	"crypto/dsa" //nolint:staticcheck // testin konusu tam olarak DSA'nın reddi
	"crypto/ed25519"
	"crypto/rand"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/ssh"
)

/*
 * ⚠️ HTTP YAZMA YOLU DA HİÇ ÇALIŞMAYACAK ANAHTARI REDDETMELİ.
 *
 * sshalg.UnusableKeyType için saf bir birim testi vardı ama kuralın
 * KABLOSUNU hiçbir şey ölçmüyordu — üç anahtar-ekleme kapısından biri
 * (CLI) kapıyı atlıyordu. parseAuthorizedKey, hem adminAddKey hem
 * handleMyKeys uçlarının kullandığı ortak gate; bu test onun bir DSA
 * anahtarını reddettiğini doğruluyor. CLI kapısı ayrı test edildi
 * (cmd/postern: TestUserAddRefusesUnusableKey).
 */
func TestParseAuthorizedKeyRefusesUnusableKey(t *testing.T) {
	var params dsa.Parameters
	if err := dsa.GenerateParameters(&params, rand.Reader, dsa.L1024N160); err != nil {
		t.Fatal(err)
	}
	key := &dsa.PrivateKey{PublicKey: dsa.PublicKey{Parameters: params}}
	if err := dsa.GenerateKey(key, rand.Reader); err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Skipf("x/crypto DSA public key üretmiyor: %v", err)
	}
	line := string(ssh.MarshalAuthorizedKey(pub))

	w := httptest.NewRecorder()
	_, _, ok := parseAuthorizedKey(w, line)
	if ok {
		t.Error("HTTP yazma yolu DSA anahtarını kabul etti — hiç çalışamayacak bir anahtar")
	}
	if w.Code != 400 {
		t.Errorf("durum = %d, 400 bekleniyordu", w.Code)
	}

	// Karşı taraf: geçerli ed25519 anahtarı GEÇMELİ (kapı her şeyi
	// reddeden bir düzeltme olmamalı).
	_, edpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edpub, err := ssh.NewPublicKey(edpriv.Public())
	if err != nil {
		t.Fatal(err)
	}
	w2 := httptest.NewRecorder()
	if _, _, ok := parseAuthorizedKey(w2, string(ssh.MarshalAuthorizedKey(edpub))); !ok {
		t.Errorf("geçerli ed25519 anahtarı reddedildi: %d", w2.Code)
	}
}
