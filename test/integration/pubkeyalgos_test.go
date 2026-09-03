//go:build integration

package integration

import (
	"context"
	"crypto/dsa" //nolint:staticcheck // testin konusu tam olarak DSA'nın reddi
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

/*
 * ⚠️ KAPIDA SHA-1 VE DSA KABUL EDİLİYORDU.
 *
 * Taşıma katmanı (KEX/şifre/MAC) açıkça ayarlanmıştı ve SHA-1'i
 * reddediyordu. Kimlik kanıtının İMZASI ise ayrı pazarlanıyor ve
 * ayarlanmamıştı — x/crypto o alanı boş görünce kendi varsayılanına
 * düşüyor ve o varsayılan ssh-rsa (SHA-1) ile ssh-dss taşıyor.
 *
 * ÖLÇÜLDÜ, düzeltmeden önce, gerçek bastion'a karşı: ikisiyle de
 * kimlik doğrulandı (err=<nil>). Yani "SHA-1 yok" diyen bir sunucu,
 * kimlik kanıtını SHA-1 ile kabul ediyordu.
 *
 * Test üç şeyi birden ölçüyor, çünkü düzeltmenin doğru olması için
 * üçünün de doğru olması gerekiyor: SHA-1 reddediliyor mu, DSA
 * reddediliyor mu, ve AYNI RSA anahtarı hâlâ çalışıyor mu.
 */
func TestInboundPublicKeyAlgorithms(t *testing.T) {
	caKeyPath, caAuthorizedKey := newTestCA(t)
	tgt := startCertTarget(t, caAuthorizedKey)
	tc := tgt.target()
	tc.Name = "web01"

	addr, hostPub, _, db := testServerWithDB(t, caKeyPath, tc)
	ctx := context.Background()

	// Kullanıcının RSA anahtarı: aynı anahtar hem SHA-1 hem SHA-2 ile
	// imzalayabiliyor — fark tam olarak burada.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaSigner, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddPublicKey(ctx, "yigit", rsaSigner.PublicKey().Marshal(), "rsa"); err != nil {
		t.Fatal(err)
	}

	dial := func(t *testing.T, signer ssh.Signer) error {
		t.Helper()
		c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
			User:            "yigit:web01",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: ssh.FixedHostKey(hostPub),
			Timeout:         15 * time.Second,
		})
		if err == nil {
			c.Close()
		}
		return err
	}

	// ⚠️ ÖNCE ÇALIŞTIĞINI GÖSTER. Bu olmadan aşağıdaki iki ret,
	// anahtarın hiç tanınmamasından da gelebilirdi ve test yanlış
	// şeyi ölçerdi.
	t.Run("ayni RSA anahtari SHA-2 ile calisiyor", func(t *testing.T) {
		if err := dial(t, rsaSigner); err != nil {
			t.Fatalf("RSA anahtarı reddedildi: %v — düzeltme kullanıcıları "+
				"anahtarlarından etti", err)
		}
	})

	t.Run("ssh-rsa (SHA-1) reddediliyor", func(t *testing.T) {
		pinned, err := ssh.NewSignerWithAlgorithms(
			rsaSigner.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSA})
		if err != nil {
			t.Fatal(err)
		}
		if err := dial(t, pinned); err == nil {
			t.Error("SHA-1 imzayla kimlik doğrulandı — taşımada reddedilen " +
				"özet, kimlik kanıtında kabul ediliyor")
		}
	})

	t.Run("ssh-dss reddediliyor", func(t *testing.T) {
		var params dsa.Parameters
		if err := dsa.GenerateParameters(&params, rand.Reader, dsa.L1024N160); err != nil {
			t.Fatal(err)
		}
		dsaKey := &dsa.PrivateKey{PublicKey: dsa.PublicKey{Parameters: params}}
		if err := dsa.GenerateKey(dsaKey, rand.Reader); err != nil {
			t.Fatal(err)
		}
		dsaSigner, err := ssh.NewSignerFromKey(dsaKey)
		if err != nil {
			t.Skipf("x/crypto DSA imzalayıcı üretmiyor: %v", err)
		}
		if err := db.AddPublicKey(ctx, "yigit", dsaSigner.PublicKey().Marshal(), "dsa"); err != nil {
			t.Fatal(err)
		}
		if err := dial(t, dsaSigner); err == nil {
			t.Error("ssh-dss ile kimlik doğrulandı — DSA'nın SHA-2 varyantı " +
				"yok, yani bu anahtar hiçbir koşulda kabul edilmemeli")
		}
	})
}
