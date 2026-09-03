package httpapi

import (
	"bytes"
	"crypto/dsa" //nolint:staticcheck // testin konusu tam olarak DSA'nın reddi
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
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

/*
 * ⚠️ HOST ANAHTARI KAPISI, PANEL/API TARAFINDA DA OLMALI.
 *
 * Kapalı küme kontrolü (sshalg.HostKeyAlgorithmsFor) CLI'ye eklenmişti,
 * bu kapıya eklenmemişti. Ölçüldü: bir host SERTİFİKASI satırı — yani
 * /etc/ssh/ssh_host_ed25519_key-cert.pub'dan yapılan gerçekçi bir
 * yapıştırma — 200 ile kabul ediliyor, target.create olarak
 * denetleniyor ve hedef HİÇ aranamıyor: her oturum dial'da, TCP
 * denemesi bile yapılmadan düşüyor.
 *
 * Aynı alan için iki kapının iki farklı kural uygulaması, kabul edilmiş
 * ama asla çalışamayacak bir kayıt üretiyordu — kapalı kümenin var olma
 * sebebi tam olarak bu.
 */
func TestCreateTargetRefusesAHostKeyThatCanNeverDial(t *testing.T) {
	s, _ := dbServer(t)

	post := func(name, hostKey string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{
			"name": name, "host": "10.0.0.9", "port": 22, "host_key": hostKey,
		})
		r := httptest.NewRequest("POST", "/api/admin/targets", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.adminCreateTarget(w, r)
		return w
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	// Gerçekçi yapıştırma: hedefin kendi host SERTİFİKASI satırı.
	cert := &ssh.Certificate{
		Key:         signer.PublicKey(),
		CertType:    ssh.HostCert,
		KeyId:       "web01",
		ValidBefore: ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	certLine := string(ssh.MarshalAuthorizedKey(cert))
	if w := post("web01", certLine); w.Code != 400 {
		t.Errorf("host sertifikası satırı %d ile kabul edildi — kaydedilen "+
			"ama hiçbir zaman aranamayacak bir hedef; gövde: %s",
			w.Code, w.Body.String())
	}

	// Karşı taraf: düz ed25519 host anahtarı GEÇMELİ — kapı her şeyi
	// reddeden bir düzeltme olmamalı.
	plain := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	if w := post("web02", plain); w.Code != 200 {
		t.Errorf("geçerli ed25519 host anahtarı reddedildi: %d %s",
			w.Code, w.Body.String())
	}
}
