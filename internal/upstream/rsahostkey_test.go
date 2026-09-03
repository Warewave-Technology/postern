package upstream

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/model"
)

// rsaHostSigner, RSA bir sunucu anahtarı üretir.
func rsaHostSigner(t *testing.T) ssh.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

/*
 * rsaTarget, RSA host key'li bir SSH sunucusu açar ve hangi imza
 * algoritmalarını sunacağını çağırana bıraktırır.
 *
 * ⚠️ ALGORİTMA KISITLAMASI OPENSSH 8.8+'İ BİREBİR TAKLİT EDİYOR:
 * x/crypto sunucu tarafında anahtarın tel formatından türettiği listeyi
 * MultiAlgorithmSigner.Algorithms() ile süzüyor, sshd de tam olarak
 * bunu yapıyor (8.8 ssh-rsa'yı varsayılanda kapattı).
 */
func rsaTarget(t *testing.T, hk ssh.Signer, algos []string) (model.Target, ssh.Signer) {
	t.Helper()

	signer := hk
	if algos != nil {
		ms, err := ssh.NewSignerWithAlgorithms(hk.(ssh.AlgorithmSigner), algos)
		if err != nil {
			t.Fatal(err)
		}
		signer = ms
	}

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(signer)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					c.Close()
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					nc.Reject(ssh.Prohibited, "test")
				}
				sc.Close()
			}()
		}
	}()

	// ⚠️ PIN, ANAHTARIN TEL FORMATINDA: "ssh-rsa AAAAB3..." — operatör
	// bunu ancak böyle yazabiliyor, ParseAuthorizedKey "rsa-sha2-512"
	// ile başlayan bir satırı reddediyor.
	return targetAt(t, l, hk.PublicKey()), hk
}

/*
 * ⚠️ RSA HOST KEY'İ PİNLENMİŞ MODERN BİR HEDEFE BAĞLANILABİLMELİ.
 *
 * ÖLÇÜLEN ARIZA: pin'in tel formatı ("ssh-rsa") doğrudan müzakere
 * listesi olarak veriliyordu. OpenSSH 8.8 ssh-rsa'yı varsayılanda
 * kapattığı için böyle her hedef ERİŞİLEMEZ oluyordu:
 *
 *     ssh: no common algorithm for host key;
 *     we offered: ["ssh-rsa"], peer offered: ["rsa-sha2-256" "rsa-sha2-512"]
 *
 * Yani Debian 12+, Ubuntu 22.04+, RHEL 9+ üzerinde RSA host key'li
 * hedeflerin tamamı. Üstelik tarama sihirbazı onları kaydedebiliyor,
 * çünkü tarama zaten SHA-2 sunuyor — kaydedilip hiç bağlanılamayan
 * hedef.
 */
func TestRSAPinnedTargetIsReachable(t *testing.T) {
	shortDialTimeout(t, 10*time.Second)

	hk := rsaHostSigner(t)
	// Modern sshd: SHA-1 YOK.
	tg, _ := rsaTarget(t, hk, []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256})

	conn, err := dialer(context.Background(), tg, "ayse", hostSigner(t))
	if err != nil {
		t.Fatalf("RSA host key'i pinlenmiş modern hedefe bağlanılamadı: %v\n"+
			"Bu, OpenSSH 8.8+ çalıştıran her RSA hedefin erişilemez olması demek",
			err)
	}
	defer conn.Close()
}

/*
 * ⚠️ VE BAĞLANIRKEN SHA-1'E DÜŞMEMELİ.
 *
 * Arızanın sessiz yarısı buydu: ssh-rsa'yı hâlâ sunan eski bir hedefte
 * el sıkışma TAMAMLANIYOR, ama host key imzası SHA-1 ile doğrulanıyor.
 * KEX ve MAC listelerinden SHA-1'i çıkarmış bir taşıma katmanının tek
 * istisnası olurdu ve hiçbir yerde görünmezdi.
 */
func TestRSAPinnedTargetDoesNotNegotiateSHA1(t *testing.T) {
	shortDialTimeout(t, 10*time.Second)

	hk := rsaHostSigner(t)
	// Eski sshd: her şeyi sunuyor, ssh-rsa dahil. Seçim bizde.
	tg, _ := rsaTarget(t, hk, []string{
		ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA,
	})

	conn, err := dialer(context.Background(), tg, "ayse", hostSigner(t))
	if err != nil {
		t.Fatalf("bağlanılamadı: %v", err)
	}
	defer conn.Close()

	meta, ok := conn.client.Conn.(ssh.AlgorithmsConnMetadata)
	if !ok {
		t.Skip("x/crypto müzakere edilen algoritmaları bildirmiyor")
	}
	if got := meta.Algorithms().HostKey; got == ssh.KeyAlgoRSA {
		t.Errorf("host key algoritması %q — SHA-1 ile doğrulandı, "+
			"oysa KEX ve MAC listelerinden SHA-1 çıkarılmış durumda", got)
	}
}

/*
 * ⚠️ SHA-1'İ SUNAN TEK BAŞINA BİR HEDEF ARTIK REDDEDİLİYOR — bilinçli.
 *
 * Kaybedilen küme: yalnızca ssh-rsa sunan bir sshd (OpenSSH < 7.2 ya da
 * elle `HostKeyAlgorithms ssh-rsa` yazılmış bir kurulum). O hedef zaten
 * tarama akışından geçemiyor — tarama da SHA-2 sunuyor — yani ancak
 * elle pinlenmiş olabilir.
 *
 * Test bunun SESSİZ değil, açık bir ret olduğunu ölçüyor: operatör
 * hedefin neden erişilemez olduğunu hata metninden görebilmeli.
 */
func TestSHA1OnlyTargetIsRefusedLoudly(t *testing.T) {
	shortDialTimeout(t, 10*time.Second)

	hk := rsaHostSigner(t)
	tg, _ := rsaTarget(t, hk, []string{ssh.KeyAlgoRSA})

	_, err := dialer(context.Background(), tg, "ayse", hostSigner(t))
	if err == nil {
		t.Fatal("yalnızca SHA-1 sunan hedefe bağlanıldı")
	}
	if !strings.Contains(err.Error(), "host key") {
		t.Errorf("hata sebebi anlaşılmıyor: %v — operatör hedefin neden "+
			"erişilemez olduğunu okuyabilmeli", err)
	}
}
