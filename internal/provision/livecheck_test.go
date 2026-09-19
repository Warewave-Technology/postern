package provision

/*
 * Planı GERÇEK bir makinede, ürünün kendi yoluyla koşturan testler.
 *
 * ⚠️ YALNIZCA POSTERN_LIVE_TARGET ve POSTERN_LIVE_CA verildiğinde koşuyor.
 * CI'da bir hedef yok; testin varlık sebebi, planın ürettiği komutların
 * kâğıt üzerinde değil makinede çalıştığını görmek.
 *
 * ⚠️ İNSANIN ELİNDE SERTİFİKA YOK. Bu dosyanın ilk hâli `ssh -i <anahtar>`
 * ile bağlanıyordu ve bir insanın "postern-manage" için imzalatılmış bir
 * sertifika taşımasını istiyordu — ürünün hiç yapmadığı, yapmaması gereken
 * bir şey. Artık bağlantıyı postern kuruyor: CA anahtarından bellekte iki
 * dakikalık bir sertifika üretiyor, tıpkı panelin yapacağı gibi. Ölçülen
 * yol, ürünün yolu.
 *
 *   POSTERN_LIVE_TARGET=192.168.1.81 \
 *   POSTERN_LIVE_CA=deploy/quickstart/.state/keys/ca_ed25519 \
 *   go test -count=1 -run TestApplyAgainstARealTarget -v ./internal/provision/
 *
 * POSTERN_LIVE_CA, hedefin /etc/ssh/postern_ca.pub'ına YAZILAN açık
 * anahtarın özel yarısı olmalı. Test kullandığı CA'yı yazdırıyor; hedefin
 * reddi neredeyse her zaman bu ikisinin eşleşmemesi.
 */

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/v2/internal/ca"
	"github.com/Warewave-Technology/postern/v2/internal/model"
	"github.com/Warewave-Technology/postern/v2/internal/sudoers"
	"github.com/Warewave-Technology/postern/v2/internal/upstream"
)

// liveRunner, ortam değişkenlerinden gerçek hedefe yönetim bağlantısı kurar.
func liveRunner(t *testing.T) *SSHRunner {
	t.Helper()

	host := os.Getenv("POSTERN_LIVE_TARGET")
	caPath := os.Getenv("POSTERN_LIVE_CA")
	if host == "" || caPath == "" {
		t.Skip("POSTERN_LIVE_TARGET ve POSTERN_LIVE_CA verilmedi")
	}
	port := 22
	if p := os.Getenv("POSTERN_LIVE_PORT"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			t.Fatalf("POSTERN_LIVE_PORT sayı değil: %q", p)
		}
		port = n
	}

	authority, err := ca.Load(caPath)
	if err != nil {
		t.Fatalf("CA yüklenemedi: %v", err)
	}
	t.Logf("kullanılan CA: %s", strings.TrimSpace(authority.AuthorizedKey()))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	/*
	 * ⚠️ HOST ANAHTARI: VERİLDİYSE PİNLENİYOR, VERİLMEDİYSE İLK GÖRÜŞTE
	 * KABUL — ve bu yalnızca bir laboratuvar testinde kabul edilebilir.
	 * Ürün hedefi eklerken anahtarı tarayıp operatöre onaylatıyor;
	 * burada onaylayacak kimse yok, o yüzden parmak izi yazdırılıyor.
	 */
	hostKey := os.Getenv("POSTERN_LIVE_HOSTKEY")
	if hostKey == "" {
		pub, serr := upstream.ScanHostKey(ctx, host, port)
		if serr != nil {
			t.Fatalf("host anahtarı okunamadı: %v", serr)
		}
		hostKey = string(ssh.MarshalAuthorizedKey(pub))
		t.Logf("host anahtarı ilk görüşte kabul edildi: %s", ssh.FingerprintSHA256(pub))
	}

	r, err := Connect(ctx, model.Target{Name: host, Host: host, Port: port, HostKey: hostKey},
		authority, "livecheck", "provision live test")
	if err != nil {
		if errors.Is(err, upstream.ErrRefused) {
			t.Fatalf("hedef yönetim sertifikasını reddetti: %v\n\n"+
				"İki olası sebep: (1) hedefin /etc/ssh/postern_ca.pub dosyası yukarıda "+
				"yazan CA DEĞİL — grubu bu CA'nın açık anahtarıyla yeniden koşun; "+
				"(2) rol postern_manage_host: true ile koşmadı, /etc/ssh/auth_principals/postern "+
				"yok ya da içinde %q yazmıyor. Yönetim hesabında authorized_keys yok ve "+
				"olmamalı: oraya anahtar eklemek ürünün kaldırdığı şeyi geri koymak.",
				err, model.ManagementPrincipal)
		}
		t.Fatalf("hedefe bağlanılamadı: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })

	return r
}

// liveCaps, hedefin yeteneğini GERÇEKTEN ölçer — elle yazılmış yollar değil.
func liveCaps(t *testing.T, r *SSHRunner) upstream.ManageCapabilities {
	t.Helper()

	caps, err := r.Conn().Capabilities(context.Background())
	if err != nil {
		t.Fatalf("yetenek ölçülemedi: %v", err)
	}
	t.Logf("yetenek: %s (aile %q)", caps.Summary(), caps.Family)
	if !caps.Manageable() {
		t.Fatalf("hedef yönetilemez: %s", caps.Summary())
	}

	return caps
}

func TestApplyAgainstARealTarget(t *testing.T) {
	r := liveRunner(t)
	caps := liveCaps(t, r)

	d := Desired{
		Groups: []Group{{Name: "yayilim", Sudo: sudoers.Rule{
			Commands: []sudoers.Command{{Path: "/usr/bin/nginx", Args: []string{"-t"}}},
		}}},
		Users: []User{{Name: "suheda", Groups: []string{"yayilim"}}},
	}

	obs, err := Observe(context.Background(), r, d)
	if err != nil {
		t.Fatalf("hedef okunamadı: %v", err)
	}
	steps, err := Plan(caps, d, obs)
	if err != nil {
		t.Fatal(err)
	}

	rep := Apply(context.Background(), r, steps)
	t.Logf("ilk koşu: %s", rep.Summary())
	for _, res := range rep.Results {
		if res.Outcome != OutcomeDone {
			t.Errorf("%s %s: %v — %s", res.Step.Kind, res.Outcome, res.Err, res.Output)
		}
	}
	if !rep.OK() {
		t.Fatal("gerçek hedefte plan uygulanamadı")
	}

	/*
	 * ⚠️ İKİNCİ KOŞU, İDEMPOTENSLİĞİN GERÇEK ÖLÇÜSÜ. Birim testi
	 * gözlenen durumu ELLE veriyor; burada durumu makinenin kendisi
	 * söylüyor.
	 */
	obs, err = Observe(context.Background(), r, d)
	if err != nil {
		t.Fatalf("hedef ikinci kez okunamadı: %v", err)
	}
	again, err := Plan(caps, d, obs)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range again {
		t.Errorf("ikinci koşu iş üretti: %s — %s", s.Kind, s.Command)
	}
}

/*
 * TestRevokeAgainstARealTarget, sökme planını gerçek makinede koşturur.
 *
 * ⚠️ BU ADIMLAR YIKICI VE BU YÜZDEN YALNIZCA AÇIKÇA VERİLEN BİR HEDEFTE
 * VE HESAPTA KOŞUYOR.
 *
 * ⚠️ JIT ÜYELİĞİ ÖLÇÜLÜYOR, VARSAYILMIYOR. İlk hâli InJITGroup'u elle
 * true veriyordu; oysa bu şart "postern bu hesabı kendisi açtı" demenin
 * tek kanıtı ve silmenin önündeki tek kapı. Üyeliği yalnızca JIT planı
 * kuruyor (User.JIT); TestApplyAgainstARealTarget'ın açtığı "suheda" JIT
 * değil, dolayısıyla burada atlanır — silmek için önce JIT olarak açılmış
 * bir hesap adı verilmeli.
 */
func TestRevokeAgainstARealTarget(t *testing.T) {
	user := os.Getenv("POSTERN_LIVE_REVOKE_USER")
	if user == "" {
		t.Skip("POSTERN_LIVE_REVOKE_USER verilmedi")
	}
	r := liveRunner(t)
	caps := liveCaps(t, r)
	ctx := context.Background()

	facts, err := Account(ctx, r, user)
	if err != nil {
		t.Fatalf("hesap okunamadı: %v", err)
	}
	if !facts.Exists {
		t.Fatalf("hedefte %q yok", user)
	}
	if !facts.InJITGroup() {
		t.Skipf("%q, %s grubunda değil; postern yalnızca kendi açtığı hesabı siler", user, JITGroup)
	}

	steps, err := RevokePlan(caps, Revoke{
		User: user, Mode: ModeDelete, UID: facts.UID, CreatedByPostern: facts.CreatedByPostern(),
		Home:      facts.Home,
		SudoFiles: []string{UserSudoPath(user)},
	})
	if err != nil {
		t.Fatal(err)
	}

	rep := Apply(ctx, r, steps)
	t.Logf("sökme: %s", rep.Summary())
	for _, res := range rep.Results {
		if res.Outcome != OutcomeDone {
			t.Errorf("%s %s: %v — %s", res.Step.Kind, res.Outcome, res.Err, res.Output)
		}
		if res.Step.Kind == StepReportOwned {
			t.Logf("kalan dosyalar:\n%s", res.Output)
		}
	}

	// Hesap gerçekten gitmiş olmalı — "cevap yok" da "gitti" sayılmıyor.
	after, err := Account(ctx, r, user)
	if err != nil {
		t.Fatalf("hesap sökmeden sonra okunamadı: %v", err)
	}
	if after.Exists {
		t.Errorf("HESAP DURUYOR: uid %d", after.UID)
	}
}
