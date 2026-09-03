package upstream

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/model"
)

// fakeTarget, verilen sunucu yapılandırmasıyla bir SSH sunucusu açar.
// serve nil ise bağlantı kabul edilip HİÇBİR ŞEY yapılmaz (susan hedef).
func fakeTarget(t *testing.T, hk ssh.Signer, cfg *ssh.ServerConfig, serve func(net.Conn)) model.Target {
	t.Helper()

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
				if serve != nil {
					serve(c)
					return
				}
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

	return targetAt(t, l, hk.PublicKey())
}

/*
 * ⚠️ HER EL SIKIŞMA HATASI "REDDEDİLDİ" DEĞİL.
 *
 * Sınıflandırıcı, host anahtarı uyuşmazlığı dışındaki her şeyi
 * ErrRefused sayıyordu ve paneldeki karşılığı tek bir cümleydi:
 * "hedef bu bastion'ın sertifikasını reddetti — CA'ya güvenmesi
 * gerekiyor". ÖLÇÜLDÜ: sekiz arıza biçiminden altısı yanlış
 * sınıflanıyordu — algoritma uyuşmazlıkları, susan hedef, SSH
 * konuşmayan port.
 *
 * Bedeli operatörün saatleri: cümle onu hedefteki TrustedUserCAKeys'e
 * bakmaya gönderiyor, oysa sorun ağda ya da sshd'nin algoritma
 * yapılandırmasında ve orada bakacak bir şey yok.
 */
func TestHandshakeFailuresAreNotAllRefusals(t *testing.T) {
	shortDialTimeout(t, 600*time.Millisecond)
	hk := hostSigner(t)

	accept := func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
		return &ssh.Permissions{}, nil
	}
	withCfg := func(c ssh.Config) *ssh.ServerConfig {
		s := &ssh.ServerConfig{PublicKeyCallback: accept, Config: c}
		s.AddHostKey(hk)
		return s
	}

	cases := []struct {
		name  string
		build func() model.Target
	}{
		{"kex uyusmazligi", func() model.Target {
			return fakeTarget(t, hk, withCfg(ssh.Config{
				KeyExchanges: []string{"diffie-hellman-group16-sha512"},
			}), nil)
		}},
		{"sifre uyusmazligi", func() model.Target {
			return fakeTarget(t, hk, withCfg(ssh.Config{
				Ciphers: []string{"aes128-cbc"},
			}), nil)
		}},
		{"susan hedef", func() model.Target {
			return fakeTarget(t, hk, nil, func(c net.Conn) {
				time.Sleep(30 * time.Second)
				c.Close()
			})
		}},
		{"ssh konusmayan port", func() model.Target {
			return fakeTarget(t, hk, nil, func(c net.Conn) {
				c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
				time.Sleep(30 * time.Second)
				c.Close()
			})
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := dialer(context.Background(), tc.build(), "ayse", hostSigner(t))
			if err == nil {
				t.Fatal("bağlantı başarılı sayıldı")
			}
			if errors.Is(err, ErrRefused) {
				t.Errorf("RET olarak sınıflandı: %v\n"+
					"Operatör hedefteki TrustedUserCAKeys'e bakmaya gönderilir "+
					"ve orada bakacak bir şey yoktur", err)
			}
			if !errors.Is(err, ErrHandshake) {
				t.Errorf("el sıkışma arızası olarak sınıflanmadı: %v", err)
			}
		})
	}
}

/*
 * ⚠️ GERÇEK RET HÂLÂ RET.
 *
 * Aşırı düzeltmeye karşı koruma: fazla geniş bir kural, operatöre
 * "hedefe CA'yı tanıt" diyen TEK cümleyi sessizce elinden alırdı ve o
 * cümle doğru olduğu yerde gerçekten işe yarıyor.
 */
func TestGenuineRefusalIsStillARefusal(t *testing.T) {
	shortDialTimeout(t, 5*time.Second)
	hk := hostSigner(t)

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, errors.New("certificate not trusted")
		},
	}
	cfg.AddHostKey(hk)

	_, err := dialer(context.Background(), fakeTarget(t, hk, cfg, nil), "ayse", hostSigner(t))
	if err == nil {
		t.Fatal("reddeden hedefe bağlanıldı")
	}
	if !errors.Is(err, ErrRefused) {
		t.Errorf("gerçek ret, ret sayılmadı: %v — operatör CA'yı tanıtması "+
			"gerektiğini söyleyen cümleyi göremez", err)
	}
	if errors.Is(err, ErrHandshake) {
		t.Error("gerçek ret el sıkışma arızası sayıldı")
	}
}

/*
 * Host anahtarı uyuşmazlığı kendi sınıfında kalmalı: sabitlenmiş
 * anahtarın tutmaması araya girme de olabilir ve o cümle diğer
 * ikisinin altında kaybolmamalı.
 */
func TestHostKeyMismatchIsNotAHandshakeFailure(t *testing.T) {
	shortDialTimeout(t, 5*time.Second)
	hk := hostSigner(t)

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(hk)
	tg := fakeTarget(t, hk, cfg, nil)

	// BAŞKA bir anahtar pinle.
	tg.HostKey = string(ssh.MarshalAuthorizedKey(hostSigner(t).PublicKey()))

	_, err := dialer(context.Background(), tg, "ayse", hostSigner(t))
	if err == nil {
		t.Fatal("yanlış anahtarla bağlanıldı")
	}
	if !errors.Is(err, ErrHostKeyMismatch) {
		t.Errorf("uyuşmazlık kendi sınıfında değil: %v", err)
	}
	if errors.Is(err, ErrHandshake) || errors.Is(err, ErrRefused) {
		t.Errorf("uyuşmazlık başka bir sınıfa da düştü: %v", err)
	}
}
