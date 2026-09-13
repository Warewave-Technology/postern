package upstream

/*
 * Yönetim bağlantısı ve hedefte komut çalıştırma — ağ ya da Docker
 * olmadan, süreç içi bir SSH sunucusuyla.
 *
 * ⚠️ SUNUCU, HEDEFİN PRINCIPAL KURALINI TAKLİT EDİYOR. x/crypto'nun
 * CertChecker.Authenticate'i "giriş adı principal listesinde olmalı"
 * diyor — AuthorizedPrincipalsFile'ı OLMAYAN bir sshd'nin davranışı.
 * Rolün kurduğu hedef başka: giriş adı hangi dosyanın okunacağını
 * seçiyor, principal o dosyada yazmalı. Yönetim sertifikasının ölçülmesi
 * gereken şey tam olarak bu fark, o yüzden kural burada elle kuruluyor.
 */

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/ca"
	"github.com/Warewave-Technology/postern/internal/model"
)

// script, sunucunun bir exec isteğine ne yapacağı. sendStatus false ise
// kanal çıkış kodu gönderilmeden kapanıyor.
type script func(cmd, stdin string, ch ssh.Channel) (status int, sendStatus bool)

// managedServer, gördüklerini kaydeden sahte hedef.
type managedServer struct {
	mu    sync.Mutex
	users []string
	certs []*ssh.Certificate
	conns atomic.Int32
}

func (m *managedServer) saw(user string, cert *ssh.Certificate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users = append(m.users, user)
	m.certs = append(m.certs, cert)
}

func (m *managedServer) last(t *testing.T) (string, *ssh.Certificate) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.certs) == 0 {
		t.Fatal("sunucu hiçbir sertifika görmedi")
	}

	return m.users[len(m.users)-1], m.certs[len(m.certs)-1]
}

func testAuthority(t *testing.T) *ca.CA {
	t.Helper()
	authority, err := ca.Init(t.TempDir() + "/ca")
	if err != nil {
		t.Fatal(err)
	}

	return authority
}

/*
 * managedTarget, rolün kurduğu hedefi taklit eden bir sunucu açar:
 * "postern" hesabı yalnızca "postern-manage" principal'ıyla, "deploy"
 * hesabı yalnızca "deploy" principal'ıyla açılıyor.
 */
func managedTarget(t *testing.T, authority *ca.CA, run script) (model.Target, *managedServer) {
	t.Helper()

	return managedTargetWith(t, authority, run, true)
}

// managedTargetWith, openChannels false ise el sıkışmayı bitirip kanal
// açılışına HİÇ cevap vermeyen bir hedef kurar.
func managedTargetWith(t *testing.T, authority *ca.CA, run script, openChannels bool) (model.Target, *managedServer) {
	t.Helper()

	srv := &managedServer{}
	principalsFile := map[string][]string{
		model.ManagementAccount: {model.ManagementPrincipal},
		"deploy":                {"deploy"},
	}
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), authority.PublicKey().Marshal())
		},
	}

	hk := hostSigner(t)
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			cert, ok := key.(*ssh.Certificate)
			if !ok {
				return nil, errors.New("certificates only")
			}
			srv.saw(conn.User(), cert)
			// ⚠️ CA güveni ayrıca: CheckCert onu sormuyor (httpapi/manage_test.go'da
			// ölçülüp yazıldı). Sormayan sahte hedef her CA'yı kabul ederdi.
			if !checker.IsUserAuthority(cert.SignatureKey) {
				return nil, errors.New("certificate signed by an authority this host does not trust")
			}
			for _, p := range principalsFile[conn.User()] {
				if err := checker.CheckCert(p, cert); err == nil {
					return &ssh.Permissions{}, nil
				}
			}

			return nil, errors.New("no principal in this account's file")
		},
	}
	cfg.AddHostKey(hk)

	serve := func(c net.Conn) {
		srv.conns.Add(1)
		sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
		if err != nil {
			c.Close()
			return
		}
		defer sc.Close()
		go ssh.DiscardRequests(reqs)

		if !openChannels {
			// chans hiç okunmuyor: istemcinin OpenChannel çağrısı cevap bekler.
			_ = sc.Wait()
			return
		}

		for nc := range chans {
			if nc.ChannelType() != "session" {
				_ = nc.Reject(ssh.UnknownChannelType, "session only")
				continue
			}
			ch, creqs, err := nc.Accept()
			if err != nil {
				continue
			}
			go serveSession(ch, creqs, run)
		}
	}

	return fakeTarget(t, hk, cfg, serve), srv
}

func serveSession(ch ssh.Channel, reqs <-chan *ssh.Request, run script) {
	defer ch.Close()

	for req := range reqs {
		if req.Type != "exec" {
			_ = req.Reply(false, nil)
			continue
		}
		var p struct{ Command string }
		if err := ssh.Unmarshal(req.Payload, &p); err != nil {
			_ = req.Reply(false, nil)
			return
		}
		if p.Command == "refuse-exec" {
			_ = req.Reply(false, nil)
			continue
		}
		_ = req.Reply(true, nil)

		stdin, _ := io.ReadAll(ch)
		status, send := run(p.Command, string(stdin), ch)
		if send {
			_, _ = ch.SendRequest("exit-status", false,
				ssh.Marshal(struct{ Status uint32 }{uint32(status)}))
		}

		return
	}
}

func noop(string, string, ssh.Channel) (int, bool) { return 0, true }

/*
 * ⚠️ YÖNETİM SERTİFİKASI TAM OLARAK BİR HESABI AÇMALI VE FAZLASINI
 * TAŞIMAMALI.
 *
 * Ölçülenler, hedefte parolasız root tutan bir kimliğin sınırları: giriş
 * adı "postern", principal yalnızca "postern-manage", PTY izni yok (bu
 * fonksiyonun ilk hâli PTY'nin kapalı olduğunu iddia ediyordu ve ca.Sign
 * onu koşulsuz ekliyordu), KeyID'de düğmeye basan kişi ve sebep var, ömür
 * iki dakikayı aşmıyor.
 */
func TestManagementCertificateOpensOnlyTheManagementAccount(t *testing.T) {
	authority := testAuthority(t)
	tgt, srv := managedTarget(t, authority, noop)

	conn, err := DialManagement(context.Background(), tgt, authority, "ayse", "check management access")
	if err != nil {
		t.Fatalf("DialManagement: %v", err)
	}
	defer conn.Close()

	user, cert := srv.last(t)
	if user != model.ManagementAccount {
		t.Errorf("giriş adı = %q, %q bekleniyordu", user, model.ManagementAccount)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != model.ManagementPrincipal {
		t.Errorf("principal'lar = %v, yalnızca %q bekleniyordu", cert.ValidPrincipals, model.ManagementPrincipal)
	}
	if _, ok := cert.Permissions.Extensions["permit-pty"]; ok {
		t.Error("yönetim sertifikası permit-pty taşıyor")
	}
	for _, ext := range []string{"permit-port-forwarding", "permit-agent-forwarding", "permit-X11-forwarding", "permit-user-rc"} {
		if _, ok := cert.Permissions.Extensions[ext]; ok {
			t.Errorf("yönetim sertifikası %s taşıyor", ext)
		}
	}
	for _, want := range []string{model.ManagementPrincipal, "ayse", "check management access"} {
		if !strings.Contains(cert.KeyId, want) {
			t.Errorf("KeyID %q içinde %q yok — hedefin günlüğü düğmeye kimin bastığını söylemiyor", cert.KeyId, want)
		}
	}
	if life := time.Duration(cert.ValidBefore-cert.ValidAfter) * time.Second; life > 2*time.Minute {
		t.Errorf("sertifika ömrü %v, en fazla 2m bekleniyordu", life)
	}
}

/*
 * ⚠️ SIRADAN KAPI YÖNETİM HESABINA HİÇ BAĞLANMIYOR — hedefe gitmeden.
 *
 * Bağlantı sayacı sıfır kalmalı: reddin hedefte değil postern'de olduğu
 * ölçülüyor. Hedefin principal dosyası gevşek olsaydı (elle kurulmuş bir
 * makine), orada reddedilmeyi beklemek savunmayı hedefe bırakmak olurdu.
 */
func TestOrdinaryDialNeverReachesTheManagementAccount(t *testing.T) {
	authority := testAuthority(t)
	tgt, srv := managedTarget(t, authority, noop)

	for _, name := range []string{model.ManagementAccount, model.ManagementPrincipal} {
		conn, err := DialWithCert(context.Background(), tgt, Identity{
			PosternUser: "ayse", OSUser: name,
		}, authority)
		if err == nil {
			conn.Close()
			t.Errorf("sıradan kapı %q için bağlandı", name)
		}
	}
	if n := srv.conns.Load(); n != 0 {
		t.Errorf("hedefe %d bağlantı açıldı; ret postern'de olmalıydı", n)
	}

	// Karşı örnek: aynı sunucuda sıradan hesap açılıyor. Aksi hâlde
	// yukarıdaki retler sunucunun her şeyi reddetmesinden gelebilirdi.
	conn, err := DialWithCert(context.Background(), tgt, Identity{PosternUser: "ayse", OSUser: "deploy"}, authority)
	if err != nil {
		t.Fatalf("sıradan hesap açılmadı — retler yanlış sebepten geliyor olabilir: %v", err)
	}
	conn.Close()
}

// Kişi ve sebep boşsa hedefe hiç gidilmiyor: günlükte açıklanamayan bir
// root girişi bırakılmıyor.
func TestManagementDialNeedsAPersonAndAReason(t *testing.T) {
	authority := testAuthority(t)
	tgt, srv := managedTarget(t, authority, noop)

	for _, tc := range []struct{ actor, reason string }{
		{"", "check"}, {"ayse", ""}, {"  ", "check"}, {"\n", "\t"},
	} {
		if conn, err := DialManagement(context.Background(), tgt, authority, tc.actor, tc.reason); err == nil {
			conn.Close()
			t.Errorf("kişi=%q sebep=%q ile bağlandı", tc.actor, tc.reason)
		}
	}
	if _, err := DialManagement(context.Background(), tgt, nil, "ayse", "check"); err == nil {
		t.Error("CA olmadan bağlandı")
	}
	if n := srv.conns.Load(); n != 0 {
		t.Errorf("hedefe %d bağlantı açıldı", n)
	}
}

// dialed, test sunucusuna yönetim bağlantısı açar.
func dialed(t *testing.T, run script) *Conn {
	t.Helper()
	authority := testAuthority(t)
	tgt, _ := managedTarget(t, authority, run)
	conn, err := DialManagement(context.Background(), tgt, authority, "ayse", "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	return conn
}

/*
 * ⚠️ STDOUT UYARILARLA KİRLENMEMELİ.
 *
 * Dönen dize VERİ: plan hedefteki sudoers dosyasını okuyup yazacağıyla
 * bayt bayt karşılaştırıyor. Bu makinelerde sık görülen
 * "sudo: unable to resolve host" stderr'e düşüyor; stdout'a karışsaydı
 * dosyalar hiç eşleşmez ve plan her koşuda aynı dosyayı yeniden yazardı.
 */
func TestExecKeepsStdoutFreeOfWarnings(t *testing.T) {
	conn := dialed(t, func(_, _ string, ch ssh.Channel) (int, bool) {
		_, _ = ch.Stderr().Write([]byte("sudo: unable to resolve host web01\n"))
		_, _ = ch.Write([]byte("%dba ALL=(root) /usr/bin/nginx -t\n"))
		return 0, true
	})

	out, err := conn.Exec(context.Background(), "sudo -n cat /etc/sudoers.d/postern-dba", "")
	if err != nil {
		t.Fatal(err)
	}
	if out != "%dba ALL=(root) /usr/bin/nginx -t\n" {
		t.Errorf("stdout = %q", out)
	}
}

// İçerik stdin'den bayt bayt gitmeli ve stdin kapanmalı; kapanmasa tee
// hiç çıkmazdı.
func TestExecDeliversContentOnStdinExactly(t *testing.T) {
	content := "# group dba — written by postern\n%dba ALL=(root) /usr/bin/nginx -t\n"
	conn := dialed(t, func(_, stdin string, ch ssh.Channel) (int, bool) {
		_, _ = ch.Write([]byte(stdin))
		return 0, true
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := conn.Exec(ctx, "sudo -n tee /etc/sudoers.d/postern-dba.staged", content)
	if err != nil {
		t.Fatal(err)
	}
	if out != content {
		t.Errorf("hedefe giden içerik = %q, %q bekleniyordu", out, content)
	}
}

/*
 * ⚠️ SIFIRDAN FARKLI ÇIKIŞ BİR CEVAP — ARIZA DEĞİL — VE SEBEBİ TAŞIYOR.
 */
func TestNonZeroExitIsAnAnswerThatCarriesTheReason(t *testing.T) {
	conn := dialed(t, func(_, _ string, ch ssh.Channel) (int, bool) {
		_, _ = ch.Stderr().Write([]byte("useradd: group 'dba' does not exist\n"))
		return 6, true
	})

	_, err := conn.Exec(context.Background(), "sudo -n useradd -G dba ayse", "")
	var cmdErr *CommandError
	if !errors.As(err, &cmdErr) {
		t.Fatalf("err = %v, CommandError bekleniyordu", err)
	}
	if cmdErr.Status != 6 || !strings.Contains(cmdErr.Error(), "does not exist") {
		t.Errorf("CommandError = %+v", cmdErr)
	}
	if errors.Is(err, ErrNoAnswer) {
		t.Error("hedefin cevabı 'cevap yok' diye sınıflandı")
	}
}

/*
 * ⚠️ ÇIKIŞ KODU GELMEDİYSE KOMUT BAŞARILI SAYILMAMALI. Uygulanıp
 * uygulanmadığını bilmediğimiz bir adımın üzerine sonraki adım kurulurdu.
 * Exec isteğini açıkça reddeden hedef de aynı sınıfta: komut çalışmadı,
 * ama "bağlantı koptu" demek yanlış olurdu.
 */
func TestMissingExitStatusIsNeverSuccess(t *testing.T) {
	conn := dialed(t, func(string, string, ssh.Channel) (int, bool) { return 0, false })

	for _, cmd := range []string{"vanish", "refuse-exec"} {
		_, err := conn.Exec(context.Background(), cmd, "")
		if !errors.Is(err, ErrNoAnswer) {
			t.Errorf("%s: err = %v, ErrNoAnswer bekleniyordu", cmd, err)
		}
	}
}

// Susan bir komut çağıranı sonsuza dek tutmamalı.
func TestExecStopsWhenTheContextEnds(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	conn := dialed(t, func(string, string, ssh.Channel) (int, bool) {
		<-release
		return 0, true
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	// ⚠️ Bekleme bir goroutine'de: bağlam dalı kaldırıldığında test paket
	// zaman aşımına kadar asılı kalmak yerine kendi cümlesiyle düşmeli.
	done := make(chan error, 1)
	go func() {
		_, err := conn.Exec(ctx, "hang", "")
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, ErrNoAnswer) {
			t.Errorf("err = %v, ErrNoAnswer bekleniyordu", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("susan komut Exec'i bağlam dolduktan sonra da tuttu")
	}
}

/*
 * ⚠️ BULUNAN ARAÇLAR, EKSİK BİR ARACIN ÇIKIŞ KODUYLA ÇÖPE GİTMEMELİ.
 *
 * `command -v` döngüsünün çıkış kodu SON komutunki. visudo'suz bir
 * makinede döngü 1 ile bitiyor; ilk hâl hata alınca çıktının tamamını
 * atıyordu ve rapor, makinede olan useradd'i, groupadd'i, usermod'u da
 * "eksik" listeliyordu. Karar doğru çıkıyordu (visudo gerçekten yok) ama
 * operatöre verilen sebep yanlıştı.
 */
func TestCapabilitiesKeepsToolsFoundBeforeAMissingOne(t *testing.T) {
	conn := dialed(t, func(cmd, _ string, ch ssh.Channel) (int, bool) {
		switch {
		case cmd == "sudo -n -l":
			_, _ = ch.Write([]byte("User postern may run the following commands on web01:\n    (ALL) NOPASSWD: ALL\n"))
			return 0, true
		case strings.HasPrefix(cmd, "for n in"):
			_, _ = ch.Write([]byte("/usr/sbin/useradd\n/usr/sbin/groupadd\n/usr/sbin/usermod\n"))
			return 1, true
		case cmd == "cat /etc/os-release":
			_, _ = ch.Write([]byte("ID=debian\n"))
			return 0, true
		}
		return 127, true
	})

	caps, err := conn.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if caps.AddUser == "" || caps.AddGroup == "" || caps.ModUser == "" {
		t.Errorf("bulunan araçlar kayboldu: %+v", caps)
	}
	if len(caps.Missing) != 1 || caps.Missing[0] != "visudo" {
		t.Errorf("eksikler = %v, yalnızca visudo bekleniyordu", caps.Missing)
	}
}

/*
 * ⚠️ CEVAPSIZLIK "YÖNETİLEMEZ" DEĞİL, HATA.
 *
 * Fonksiyonun başındaki yorum bunu söylüyordu ve kod tersini yapıyordu:
 * kopan bir bağlantı "sudo yok, useradd yok, visudo yok" diye hatasız
 * dönüyordu. Ölçmediğimiz bir sonucu ölçülmüş gibi göstermek, panele
 * kalıcı ve yanlış bir hüküm yazardı.
 */
func TestCapabilitiesReportsNoAnswerAsAnError(t *testing.T) {
	conn := dialed(t, func(cmd, _ string, ch ssh.Channel) (int, bool) {
		if strings.HasPrefix(cmd, "for n in") {
			return 0, false
		}
		return 0, true
	})

	caps, err := conn.Capabilities(context.Background())
	if err == nil {
		t.Fatalf("cevapsız yoklama hatasız döndü: %s", caps.Summary())
	}
	if !errors.Is(err, ErrNoAnswer) {
		t.Errorf("err = %v, ErrNoAnswer bekleniyordu", err)
	}
}

/*
 * ⚠️ KANAL AÇMAYAN HEDEF DE ÇAĞIRANI TUTMAMALI — VE BU AYRI BİR SINIR.
 *
 * dial.go'da ölçülüp yazılmış: el sıkışmayı bitirip susan bir hedef kanal
 * açılışını süresiz tutuyor, çünkü NewSession ne bağlam alıyor ne de
 * süresi var. Yukarıdaki test komutun Run'da asıldığı durumu ölçüyor;
 * probe.go'daki desen tam da bu yüzden yetmiyordu — NewSession select'in
 * DIŞINDA çağrılıyordu.
 */
func TestExecDoesNotHangWhenTheTargetNeverOpensAChannel(t *testing.T) {
	authority := testAuthority(t)
	tgt, _ := managedTargetWith(t, authority, noop, false)

	conn, err := DialManagement(context.Background(), tgt, authority, "ayse", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := conn.Exec(ctx, "id -un", "")
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, ErrNoAnswer) {
			t.Errorf("err = %v, ErrNoAnswer bekleniyordu", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("kanal açmayan hedef Exec'i süresiz tuttu")
	}
}

/*
 * Sahte hedef, güvenmediği CA'nın yönetim sertifikasını reddetmeli. Bu test
 * üretim kodunu değil TEST HEDEFİNİN KENDİSİNİ tutuyor: CA'yı sormayan bir
 * sahte hedef, bu dosyadaki her "bağlandı" sonucunu anlamsız kılardı —
 * httpapi'deki eşinde tam olarak böyle olmuştu.
 */
func TestTheFakeTargetOnlyTrustsItsOwnCA(t *testing.T) {
	trusted := testAuthority(t)
	tgt, _ := managedTarget(t, trusted, noop)

	if conn, err := DialManagement(context.Background(), tgt, testAuthority(t), "ayse", "test"); err == nil {
		conn.Close()
		t.Fatal("sahte hedef başka bir CA'nın sertifikasını kabul etti")
	}

	conn, err := DialManagement(context.Background(), tgt, trusted, "ayse", "test")
	if err != nil {
		t.Fatalf("güvenilen CA reddedildi — yukarıdaki ret yanlış sebepten olabilir: %v", err)
	}
	conn.Close()
}
