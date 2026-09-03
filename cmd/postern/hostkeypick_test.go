package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func pubLine(t *testing.T, k any) string {
	t.Helper()
	pub, err := ssh.NewPublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(pub))
}

/*
 * ⚠️ ssh-keyscan ÇIKTISINDAN "İLKİ" ALINMAMALI.
 *
 * Belgeler `ssh-keyscan host > web-01.pub` ile `target add
 * --host-key-file web-01.pub` çiftini veriyor. ssh-keyscan üç anahtar
 * türünü PARALEL soruyor, yani çıktı sırası VARIŞ sırası — ölçümde
 * sekiz koşuda ilk sıra rsa/ecdsa/rsa/rsa/ed25519/ecdsa/ecdsa/rsa
 * çıktı. İlkini almak, aynı makineyi aynı iki komutla kaydetmenin her
 * seferinde BAŞKA bir anahtar pinlemesi demekti.
 *
 * Pinlenen tür sonradan postern'in müzakere edeceği tür olduğu için
 * (upstream.hostKeyCallback algoları pinlenmiş anahtardan türetiyor),
 * rastgele RSA'ya düşmek her oturumu hedefin RSA anahtarını korumasına
 * bağlıyordu.
 */
func TestHostKeyPickIsDeterministicAndPrefersEd25519(t *testing.T) {
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ed := pubLine(t, edPriv.Public())
	rsaLine := pubLine(t, &rsaKey.PublicKey)
	ec := pubLine(t, &ecKey.PublicKey)

	// ssh-keyscan'in üretebileceği her sıra AYNI anahtarı vermeli.
	orders := [][]string{
		{rsaLine, ec, ed},
		{ec, rsaLine, ed},
		{ed, rsaLine, ec},
		{rsaLine, ed, ec},
	}
	var first string
	for i, o := range orders {
		// Yorum satırları da var: ssh-keyscan afiş satırları yazıyor.
		data := []byte("# 127.0.0.1:22 SSH-2.0-OpenSSH_9.7\n" + strings.Join(o, ""))
		pub, berr := bestHostKey(data)
		if berr != nil {
			t.Fatalf("%d. sıra: %v", i, berr)
		}
		fp := ssh.FingerprintSHA256(pub)
		if pub.Type() != ssh.KeyAlgoED25519 {
			t.Errorf("%d. sıra %s seçti — tercih sırasının başı ed25519 olmalı",
				i, pub.Type())
		}
		if first == "" {
			first = fp
		} else if fp != first {
			t.Errorf("%d. sıra farklı bir anahtar pinledi (%s ≠ %s) — aynı "+
				"makine iki kayıtta iki farklı anahtara bağlanıyor", i, fp, first)
		}
	}
}

// ed25519 yoksa sıradaki tercih alınmalı — düzeltme "yalnızca ed25519"
// olmamalı, yoksa yalnızca ECDSA sunan hedefler kaydedilemezdi.
func TestHostKeyPickFallsBackWhenEd25519IsAbsent(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := bestHostKey([]byte(pubLine(t, &ecKey.PublicKey)))
	if err != nil {
		t.Fatalf("yalnızca ECDSA sunan hedef reddedildi: %v", err)
	}
	if pub.Type() != ssh.KeyAlgoECDSA256 {
		t.Errorf("tür = %s", pub.Type())
	}
}

// Müzakere edilemeyen tek anahtar: hata BULUNANLARI saymalı, yoksa
// operatör dosyadaki hangi satırın konu olduğunu bilemiyor.
func TestHostKeyPickNamesWhatItFound(t *testing.T) {
	_, err := bestHostKey([]byte("ssh-dss AAAAB3NzaC1kc3MAAACBAJ deneme\n"))
	if err == nil {
		t.Fatal("müzakere edilemeyen anahtar kabul edildi")
	}
	if !strings.Contains(err.Error(), "no public key") &&
		!strings.Contains(err.Error(), "found") {
		t.Errorf("hata ne bulunduğunu söylemiyor: %v", err)
	}
}
