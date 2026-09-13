package provision

/*
 * SSHRunner, GERÇEK bir bağlantı üzerinden — süreç içi bir SSH sunucusuyla.
 *
 * ⚠️ BU TESTİN İLK HÂLİ ÖLÇTÜĞÜNÜ SANDIĞI ŞEYİ ÖLÇMÜYORDU. Sahte Runner,
 * cevabı `answer()` fonksiyonundan kendisi geçiriyordu; yani
 * SSHRunner.Exec'ten `answer` çağrısı silinse test yeşil kalırdı. Bir
 * incelemede mutasyonla görüldü. Artık bağlantı Connect ile, komut da
 * SSHRunner.Exec ile gidiyor: üretimin yolu.
 */

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/ca"
	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/upstream"
)

/*
 * script, sahte hedefin bir exec isteğine ne yapacağı. answered false ise
 * kanal çıkış kodu gönderilmeden kapanıyor (cevapsızlık).
 */
type script func(cmd, stdin string) (stdout, stderr string, status int, answered bool)

// answerRefuse: komut koşuyor, sıfırdan farklı kodla bitiyor — bir CEVAP.
func answerRefuse(string, string) (string, string, int, bool) {
	return "", "visudo: parse error\n", 1, true
}

// answerSilence: kanal çıkış kodu gönderilmeden kapanıyor — cevapsızlık.
func answerSilence(string, string) (string, string, int, bool) { return "", "", 0, false }

// hostAnswers, komut→stdout tablosu; tabloda olmayan komut 127 ile dönüyor
// (busybox/dash "not found" gibi), yani "yok" cevabı.
func hostAnswers(table map[string]string) script {
	return func(cmd, _ string) (string, string, int, bool) {
		if out, ok := table[cmd]; ok {
			return out, "", 0, true
		}
		return "", cmd + ": not found\n", 127, true
	}
}

/*
 * managedTarget, yönetim hesabını rolün kurduğu gibi taklit eden bir
 * sunucu açar: "postern" hesabı, yalnızca "postern-manage" principal'ı,
 * yalnızca verilen CA.
 */
func managedTarget(t *testing.T, authority *ca.CA, run script) model.Target {
	t.Helper()

	_, hostPriv, err := ed25519Key()
	if err != nil {
		t.Fatal(err)
	}
	hk, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), authority.PublicKey().Marshal())
		},
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			cert, ok := key.(*ssh.Certificate)
			if !ok || c.User() != model.ManagementAccount ||
				!checker.IsUserAuthority(cert.SignatureKey) {
				return nil, errors.New("refused")
			}
			if err := checker.CheckCert(model.ManagementPrincipal, cert); err != nil {
				return nil, err
			}
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(hk)

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
			go serve(c, cfg, run)
		}
	}()

	host, p, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(p)

	return model.Target{
		Name: "sahte", Host: host, Port: port,
		HostKey: string(ssh.MarshalAuthorizedKey(hk.PublicKey())),
	}
}

func serve(c net.Conn, cfg *ssh.ServerConfig, run script) {
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		c.Close()
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)

	for nc := range chans {
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			for req := range creqs {
				if req.Type != "exec" {
					_ = req.Reply(false, nil)
					continue
				}
				var p struct{ Command string }
				_ = ssh.Unmarshal(req.Payload, &p)
				_ = req.Reply(true, nil)
				stdin, _ := io.ReadAll(ch)
				out, errOut, status, answered := run(p.Command, string(stdin))
				_, _ = ch.Write([]byte(out))
				_, _ = ch.Stderr().Write([]byte(errOut))
				if answered {
					_, _ = ch.SendRequest("exit-status", false,
						ssh.Marshal(struct{ Status uint32 }{uint32(status)})) // #nosec G115 -- test
				}
				return
			}
		}()
	}
}

func runnerFor(t *testing.T, run script) *SSHRunner {
	t.Helper()

	authority, err := ca.Init(t.TempDir() + "/ca")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	r, err := Connect(ctx, managedTarget(t, authority, run), authority, "test", "runner test")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })

	return r
}

/*
 * ⚠️ HEDEFİN REDDİ "BAŞARISIZ", CEVAPSIZLIK "DOĞRULANMADI" OLARAK
 * RAPORLANMALI — Apply'ın gerçek bir bağlantıdan gelen hatayı doğru
 * kovaya koyabildiği tek yer SSHRunner.Exec'teki çeviri.
 *
 * Üç yönde de yanlış gidilebiliyor: sudoers doğrulaması düşen bir
 * makineyi "ulaşılamadı" demek tekrar denetir (aynı ret gelir); cevapsız
 * kalan bir adımı "başarısız" demek hedefin günlüklerine baktırır; onu
 * "ulaşılamadı" demek ise root'ta bitmiş olabilecek bir komutu "hiçbir
 * şey olmadı" diye anlatır.
 */
func TestRunnerSortsAnswersFromSilence(t *testing.T) {
	step := []Step{{Kind: StepSudoCheck, Command: "sudo -n visudo -cf /etc/sudoers.d/postern-dba.staged"}}

	rep := Apply(context.Background(), runnerFor(t, answerRefuse), step)
	if rep.Failed() != 1 || rep.Unreachable() != 0 {
		t.Errorf("hedefin reddi yanlış sınıflandı: %s", rep.Summary())
	}
	var cmdErr *upstream.CommandError
	if !errors.As(rep.FirstError(), &cmdErr) || cmdErr.Status != 1 {
		t.Errorf("reddin sebebi kayboldu: %v", rep.FirstError())
	}

	rep = Apply(context.Background(), runnerFor(t, answerSilence), step)
	if rep.Unconfirmed() != 1 || rep.Failed() != 0 || rep.Unreachable() != 0 {
		t.Errorf("cevapsızlık yanlış sınıflandı: %s", rep.Summary())
	}
	if rep.OK() {
		t.Error("doğrulanmamış adımla koşu başarılı sayıldı")
	}
	// upstream'in sınıfı zincirde kalmalı: panel sebebi oradan okuyor.
	if !errors.Is(rep.FirstError(), upstream.ErrNoAnswer) {
		t.Errorf("upstream sınıfı kayboldu: %v", rep.FirstError())
	}
}

// Bağlantısız bir Runner'dan gelen hata ulaşılamazlık olmalı, panik değil.
func TestRunnerWithoutAConnectionIsUnreachable(t *testing.T) {
	var r *SSHRunner
	if _, err := r.Exec(context.Background(), "true", ""); !errors.Is(err, ErrUnreachable) {
		t.Errorf("err = %v, ErrUnreachable bekleniyordu", err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// ed25519Key, testlik bir sunucu anahtar çifti.
func ed25519Key() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}
