package main

import (
	"crypto/dsa" //nolint:staticcheck // testin konusu tam olarak DSA'nın reddi
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// writeDSAPub, geçici bir ssh-dss açık anahtar dosyası yazar ve yolunu döner.
func writeDSAPub(t *testing.T) string {
	t.Helper()
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
	path := filepath.Join(t.TempDir(), "dsa.pub")
	if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(pub), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

/*
 * ⚠️ CLI DE HİÇ ÇALIŞMAYACAK BİR ANAHTAR EKLEMEMELİ.
 *
 * HTTP uçları DSA anahtarını reddediyordu (sshalg.UnusableKeyType) ama
 * `postern user add --key` bu kapıyı atlıyordu: CLI, DSA'yı sessizce
 * saklıyor ve o anahtar hiçbir koşulda kimlik doğrulayamıyordu — sahibi
 * bastion'ı arızalı sanır. İki yazma yolu aynı kuralı uygulamalı.
 */
func TestUserAddRefusesUnusableKey(t *testing.T) {
	e := newEnv(t)
	dsaPub := writeDSAPub(t)

	_, err := e.run(t, newRootCmd(), "user", "add",
		"--name", "ayse", "--os-user", "ayse", "--key", dsaPub)
	if err == nil {
		t.Fatal("CLI DSA anahtarını kabul etti — hiç çalışamayacak bir anahtar saklandı")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "dsa") {
		t.Errorf("hata sebebi anlaşılmıyor: %v", err)
	}
}

/*
 * ⚠️ CLI, MÜZAKERE EDİLEMEYECEK BİR HOST ANAHTARI PİNLEMEMELİ.
 *
 * `target add --host-key-file` bir ssh-dss host anahtarını saklıyordu;
 * o hedef hiç bağlanamaz (dial reddeder). Tarama yolu (ScanHostKey)
 * böyle bir türü zaten sunmuyor; CLI'ın da aynı davranması gerekiyor.
 */
func TestTargetAddRefusesUnusableHostKey(t *testing.T) {
	e := newEnv(t)
	dsaPub := writeDSAPub(t)

	_, err := e.run(t, newRootCmd(), "target", "add",
		"--name", "eski01", "--host", "10.0.0.9", "--port", "22",
		"--host-key-file", dsaPub)
	if err == nil {
		t.Fatal("CLI ssh-dss host anahtarını pinledi — hedef hiç bağlanamaz")
	}
}
