package sshd

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

/*
 * ⚠️ HOST KEY KISITLAMASI MEŞRU BİR KURULUMU DIŞARIDA BIRAKMAMALI.
 *
 * Host anahtarının imza algoritmaları artık AÇILIŞTA kısıtlanıyor
 * (sshalg.HostKeyAlgorithmsFor kapalı bir küme ve kabul etmediği türde
 * hata dönüyor). O kapalı kümenin yanlış tarafa kayması, bugün çalışan
 * bir bastion'ın yükseltmeden sonra HİÇ AÇILMAMASI demek — ve bunu ilk
 * fark eden, bakım penceresinde kalan operatör olur.
 *
 * Bu test kısıtlamanın maliyetini ölçüyor: ssh.ParsePrivateKey'in
 * üretebildiği ve gerçek kurulumlarda görülen her tür açılışı geçmeli.
 * Kalan tek dışlanan tür DSA ve o bilinçli (SHA-2 varyantı yok).
 *
 * ⚠️ KARŞI İDDİA BURADA DEĞİL: "kısıtlama gerçekten uygulanıyor mu"
 * sorusunu TestServerHostKeyRefusesSHA1 ölçüyor (RSA host key + yalnızca
 * ssh-rsa sunan istemci → ortak algoritma yok). DSA'yı burada
 * sınamıyoruz çünkü x/crypto DSA özel anahtarı YAZAMIYOR — atlayan bir
 * test hiçbir şey korumaz; reddin kendisi sshalg'da ölçülüyor
 * (TestHostKeyAlgorithmsForRejectsDSS).
 */
func TestEveryReasonableHostKeyTypeStarts(t *testing.T) {
	write := func(t *testing.T, key any, name string) string {
		t.Helper()
		block, err := ssh.MarshalPrivateKey(key, "")
		if err != nil {
			t.Skipf("%s: MarshalPrivateKey desteklemiyor: %v", name, err)
		}
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

	cases := []struct {
		name string
		key  any
	}{
		{"ed25519", edPriv},
		{"rsa2048", rsaKey},
		{"ecdsa-p256", p256},
		{"ecdsa-p384", p384},
		{"ecdsa-p521", p521},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := testConfigNoDB(t)
			cfg.HostKey = write(t, c.key, "host_"+c.name)
			if _, err := New(cfg, nil, testLogger()); err != nil {
				t.Errorf("%s host key ile sunucu KURULAMADI: %v", c.name, err)
			}
		})
	}
}
