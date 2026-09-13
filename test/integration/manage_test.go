//go:build integration

package integration

/*
 * postern bir hedefi KENDİ sertifikasıyla yönetiyor — gerçek OpenSSH,
 * gerçek sudo, gerçek visudo üzerinde.
 *
 * ⚠️ BU TEST, CANLI TESTİN (internal/provision/livecheck_test.go) CI'daki
 * KARŞILIĞI. Canlı test bir laboratuvar makinesi istiyor ve CI'da hiç
 * koşmuyor; o yüzden "plan gerçekten çalışıyor mu" sorusunun cevabı
 * ancak birisi elle koştuğunda ölçülüyordu. Fikstür, Ansible rolünün
 * postern_manage_host: true ile hedefe eklediğinin aynısını taşıyor
 * (testdata/certtarget/Dockerfile).
 *
 * ⚠️ HİÇBİR İNSANIN ELİNDE SERTİFİKA YOK. Bağlantıyı postern kuruyor;
 * sertifika bellekte, iki dakikalık, "postern-manage" principal'ıyla.
 */

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/ca"
	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/provision"
	"github.com/Warewave-Technology/postern/internal/sudoers"
	"github.com/Warewave-Technology/postern/internal/upstream"
)

// managed, fikstüre yönetim bağlantısı açar.
func managed(t *testing.T, ctx context.Context, tgt certTarget, authority *ca.CA) *provision.SSHRunner {
	t.Helper()
	r, err := provision.Connect(ctx, tgt.target(), authority, "yigit", "integration test")
	if err != nil {
		t.Fatalf("yönetim bağlantısı kurulamadı: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })

	return r
}

// observed, hedefin durumunu okur; cevapsızlığı "yok" saymaz.
func observed(t *testing.T, ctx context.Context, r *provision.SSHRunner, d provision.Desired) provision.Observed {
	t.Helper()
	o := provision.Observed{
		Groups: map[string]bool{}, Users: map[string][]string{},
		PosternSudoers: map[string]string{},
	}
	missing := func(err error) bool {
		if err == nil {
			return false
		}
		var cmdErr *upstream.CommandError
		if errors.As(err, &cmdErr) {
			return true
		}
		t.Fatalf("hedef cevap vermedi: %v", err)
		return false
	}

	for _, g := range d.Groups {
		if _, err := r.Exec(ctx, "getent group "+g.Name, ""); !missing(err) {
			o.Groups[g.Name] = true
		}
		if out, err := r.Exec(ctx, "sudo -n cat "+provision.SudoPath(g.Name), ""); !missing(err) {
			o.PosternSudoers[provision.SudoPath(g.Name)] = out
		}
	}
	for _, u := range d.Users {
		out, err := r.Exec(ctx, "id -Gn "+u.Name, "")
		if missing(err) {
			continue
		}
		o.Users[u.Name] = strings.Fields(strings.TrimSpace(out))
	}

	return o
}

func TestPosternManagesATargetWithItsOwnCertificate(t *testing.T) {
	authority := testAuthority(t)
	tgt := startCertTarget(t, authority.AuthorizedKey())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	r := managed(t, ctx, tgt, authority)

	// Hedefe gerçekten yönetim hesabıyla düşüldü.
	who, err := r.Exec(ctx, "id -un", "")
	if err != nil || strings.TrimSpace(who) != model.ManagementAccount {
		t.Fatalf("hedefteki hesap = %q (%v), %q bekleniyordu", who, err, model.ManagementAccount)
	}

	caps, err := r.Conn().Capabilities(ctx)
	if err != nil {
		t.Fatalf("yetenek ölçülemedi: %v", err)
	}
	if !caps.Manageable() {
		t.Fatalf("hedef yönetilemez göründü: %s", caps.Summary())
	}
	if caps.Family != "alpine" {
		t.Errorf("aile = %q, alpine bekleniyordu", caps.Family)
	}

	d := provision.Desired{
		Groups: []provision.Group{{Name: "yayilim", Sudo: sudoers.Rule{
			Commands: []sudoers.Command{{Path: "/usr/bin/nginx", Args: []string{"-t"}}},
		}}},
		Users: []provision.User{{Name: "suheda", Groups: []string{"yayilim"}}},
	}

	steps, err := provision.Plan(caps, d, observed(t, ctx, r, d))
	if err != nil {
		t.Fatal(err)
	}
	rep := provision.Apply(ctx, r, steps)
	for _, res := range rep.Results {
		if res.Outcome != provision.OutcomeDone {
			t.Errorf("%s %s: %v — %s", res.Step.Kind, res.Outcome, res.Err, res.Output)
		}
	}
	if !rep.OK() {
		t.Fatalf("plan uygulanamadı: %s", rep.Summary())
	}

	/*
	 * ⚠️ RAPORA DEĞİL MAKİNEYE SORULUYOR. "Uygulandı" diyen bir rapor,
	 * yönlendirmesi yanlış bir komutun sessizce hiçbir şey yazmadığını
	 * göstermezdi — bu pakette tam olarak böyle bir hata yaşandı
	 * (`sudo -n cat >` yetkisiz kabukta açılıyordu).
	 */
	groups, err := r.Exec(ctx, "id -Gn suheda", "")
	if err != nil || !strings.Contains(" "+strings.TrimSpace(groups)+" ", " yayilim ") {
		t.Errorf("suheda yayilim grubunda değil: %q (%v)", groups, err)
	}
	rule, err := r.Exec(ctx, "sudo -n -l -U suheda", "")
	if err != nil || !strings.Contains(rule, "/usr/bin/nginx -t") {
		t.Errorf("sudo, kuralı suheda için okumuyor: %q (%v)", rule, err)
	}
	/*
	 * ⚠️ sudo İLE, VE HATA "TEMİZ" DEĞİL — ÖLÇÜLDÜ. Bu kontrol önceden
	 * `ls /etc/sudoers.d`i yönetim hesabıyla, sudo'suz koşuyordu; dizin
	 * 0750 root olduğu için ls "Permission denied" ile düşüyor, hata
	 * `_` ile yutuluyor ve boş çıktıda ".staged" aranmıyordu. Kurulum
	 * adımından `rm -f <staged>` silindiğinde test yine yeşildi:
	 * artığı yakalayacak tek satır hiçbir şeyi göremiyordu.
	 */
	staged, err := r.Exec(ctx, "sudo -n ls /etc/sudoers.d", "")
	if err != nil {
		t.Fatalf("sudoers.d listelenemedi, artık kontrolü bir şey ölçmüyor: %v", err)
	}
	if strings.Contains(staged, ".staged") {
		t.Errorf("doğrulama öncesi dosya geride kaldı: %q", staged)
	}

	// İkinci koşu hiçbir iş üretmemeli: durum makinenin kendisinden okunuyor.
	again, err := provision.Plan(caps, d, observed(t, ctx, r, d))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range again {
		t.Errorf("ikinci koşu iş üretti: %s — %s", s.Kind, s.Command)
	}
}

/*
 * ⚠️ YÖNETİM HESABINI İKİ AYRI SAVUNMA KORUYOR VE İKİSİ AYRI ÖLÇÜLÜYOR.
 *
 * 1. postern: sıradan kapı (DialWithCert) "postern" için hedefe hiç
 *    gitmiyor.
 * 2. Hedef: postern'i atlayıp CA ile doğrudan "postern" principal'lı bir
 *    sertifika basan biri bile hesabı açamıyor, çünkü principal dosyasında
 *    yalnızca "postern-manage" yazıyor.
 *
 * İkincisi fikstürün kendisini de sınıyor: AuthorizedPrincipalsFile
 * etkin değilse sshd giriş adını principal listesinde arar ve bu sertifika
 * KABUL edilir. Rol trustedusercakeys'in etkin olduğunu doğruluyor ama
 * principal dosyasınınkini doğrulamıyordu.
 */
func TestManagementAccountIsClosedToAnyoneButPostern(t *testing.T) {
	authority := testAuthority(t)
	tgt := startCertTarget(t, authority.AuthorizedKey())

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	for _, name := range []string{model.ManagementAccount, model.ManagementPrincipal} {
		conn, err := upstream.DialWithCert(ctx, tgt.target(), upstream.Identity{
			PosternUser: "yigit", OSUser: name,
		}, authority)
		if err == nil {
			conn.Close()
			t.Errorf("sıradan kapı %q için bağlandı", name)
		}
	}

	/*
	 * postern'i atlayan biri: CA'yla doğrudan "postern" principal'ı basıp
	 * yönetim hesabına giriş deniyor.
	 *
	 * ⚠️ BU KONTROLÜN İLK HÂLİ YANLIŞ SEBEPTEN GEÇİYORDU — ÖLÇÜLDÜ. Ham
	 * ssh.Dial HostKeyAlgorithms vermiyordu; sunucu sabitlenenden başka
	 * türde bir host anahtarı sunuyor, FixedHostKey reddediyor ve test bunu
	 * "hedef sertifikayı reddetti" sanıyordu. Principal dosyası kaldırılmış
	 * bir imajla bu sertifika hesabı AÇMASI gerekirken test yine yeşildi.
	 * Şimdi aynı mekanizma doğru principal'la da deneniyor: o açılmıyorsa
	 * ölçülen şey kimlik değil, bağlantının kendisi.
	 */
	hostPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(tgt.target().HostKey))
	if err != nil {
		t.Fatal(err)
	}
	rawDial := func(principal string) error {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := authority.Sign(ca.CertRequest{
			PublicKey: signer.PublicKey(), KeyID: "atlatma denemesi",
			Principals: []string{principal}, ValidFor: 5 * time.Minute,
		})
		if err != nil {
			t.Fatal(err)
		}
		certSigner, err := ssh.NewCertSigner(cert, signer)
		if err != nil {
			t.Fatal(err)
		}
		client, err := ssh.Dial("tcp", net.JoinHostPort(tgt.host, strconv.Itoa(tgt.port)), &ssh.ClientConfig{
			User:              model.ManagementAccount,
			Auth:              []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
			HostKeyCallback:   ssh.FixedHostKey(hostPub),
			HostKeyAlgorithms: []string{hostPub.Type()},
			Timeout:           20 * time.Second,
		})
		if err == nil {
			client.Close()
		}
		return err
	}

	// Önce atlatma: principal dosyası etkin değilse burada AÇILIR.
	if err := rawDial(model.ManagementAccount); err == nil {
		t.Fatal("principal'ı \"postern\" olan sertifika yönetim hesabını AÇTI — " +
			"hedefin principal dosyası etkin değil")
	}
	// Sonra aynı mekanizma doğru principal'la: açılmıyorsa yukarıdaki ret
	// kimlikten değil bağlantıdan geliyordu.
	if err := rawDial(model.ManagementPrincipal); err != nil {
		t.Fatalf("ham bağlantı doğru principal'la da açılmadı — atlatma kontrolü "+
			"bir şey ölçmüyor: %v", err)
	}

	// Karşı örnek: aynı hedefte ürünün kendi yolu açılıyor. Aksi hâlde
	// yukarıdaki retler hedefin her şeyi reddetmesinden gelebilirdi.
	r := managed(t, ctx, tgt, authority)
	if who, err := r.Exec(ctx, "id -un", ""); err != nil || strings.TrimSpace(who) != model.ManagementAccount {
		t.Fatalf("yönetim bağlantısı açılmadı — retler yanlış sebepten geliyor olabilir: %q %v", who, err)
	}
}
