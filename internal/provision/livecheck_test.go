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

	"github.com/Warewave-Technology/postern/internal/ca"
	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/sudoers"
	"github.com/Warewave-Technology/postern/internal/upstream"
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
				"yazan CA DEĞİL — rolü bu CA'nın açık anahtarıyla yeniden koşun; "+
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

/*
 * absent, komutun "yok" cevabını cevapsızlıktan ayırır.
 *
 * ⚠️ err != nil "yok" DEMEK DEĞİL. İlk hâli öyle sayıyordu: bağlantı
 * koptuğunda grup "yok" görünüyor, plan onu yeniden yaratmaya kalkıyor ve
 * idempotenslik testi yanlış sebepten düşüyordu — ya da daha kötüsü,
 * silinmemiş bir hesap "gitti" görünüyordu.
 */
func absent(t *testing.T, err error) bool {
	t.Helper()
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

func TestApplyAgainstARealTarget(t *testing.T) {
	r := liveRunner(t)
	caps := liveCaps(t, r)

	d := Desired{
		Groups: []Group{{Name: "yayilim", Sudo: sudoers.Rule{
			Commands: []sudoers.Command{{Path: "/usr/bin/nginx", Args: []string{"-t"}}},
		}}},
		Users: []User{{Name: "suheda", Groups: []string{"yayilim"}}},
	}

	steps, err := Plan(caps, d, observe(t, r, d))
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
	again, err := Plan(caps, d, observe(t, r, d))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range again {
		t.Errorf("ikinci koşu iş üretti: %s — %s", s.Kind, s.Command)
	}
}

// observe, hedefin şu anki durumunu okur.
func observe(t *testing.T, r *SSHRunner, d Desired) Observed {
	t.Helper()
	ctx := context.Background()
	o := Observed{
		Groups: map[string]bool{}, Users: map[string][]string{},
		PosternSudoers: map[string]string{},
	}

	for _, g := range d.Groups {
		if _, err := r.Exec(ctx, "getent group "+g.Name, ""); !absent(t, err) {
			o.Groups[g.Name] = true
		}
		if out, err := r.Exec(ctx, "sudo -n cat "+SudoPath(g.Name), ""); !absent(t, err) {
			o.PosternSudoers[SudoPath(g.Name)] = out
		}
	}
	for _, u := range d.Users {
		out, err := r.Exec(ctx, "id -Gn "+u.Name, "")
		if absent(t, err) {
			continue
		}
		o.Users[u.Name] = strings.Fields(strings.TrimSpace(out))
	}

	return o
}

/*
 * TestRevokeAgainstARealTarget, sökme planını gerçek makinede koşturur.
 *
 * ⚠️ BU ADIMLAR YIKICI VE BU YÜZDEN YALNIZCA AÇIKÇA VERİLEN BİR HEDEFTE
 * VE HESAPTA KOŞUYOR.
 *
 * ⚠️ JIT ÜYELİĞİ ÖLÇÜLÜYOR, VARSAYILMIYOR. İlk hâli InJITGroup'u elle
 * true veriyordu; oysa bu şart "postern bu hesabı kendisi açtı" demenin
 * tek kanıtı ve silmenin önündeki tek kapı. Bugün hiçbir plan hesabı
 * postern-jit grubuna eklemiyor (JIT yaşam döngüsü henüz yok), yani
 * doğru davranış silmeyi REDDETMEK — test de bunu söyleyerek duruyor.
 */
func TestRevokeAgainstARealTarget(t *testing.T) {
	user := os.Getenv("POSTERN_LIVE_REVOKE_USER")
	if user == "" {
		t.Skip("POSTERN_LIVE_REVOKE_USER verilmedi")
	}
	r := liveRunner(t)
	caps := liveCaps(t, r)
	ctx := context.Background()

	uidOut, err := r.Exec(ctx, "id -u "+user, "")
	if absent(t, err) {
		t.Fatalf("hedefte %q yok", user)
	}
	uid, err := strconv.Atoi(strings.TrimSpace(uidOut))
	if err != nil {
		t.Fatalf("uid sayı değil: %q", uidOut)
	}

	groups, err := r.Exec(ctx, "id -Gn "+user, "")
	if absent(t, err) {
		t.Fatalf("%q için gruplar okunamadı", user)
	}
	inJIT := false
	for _, g := range strings.Fields(groups) {
		if g == JITGroup {
			inJIT = true
		}
	}
	if !inJIT {
		t.Skipf("%q, %s grubunda değil; postern yalnızca kendi açtığı hesabı siler "+
			"ve bugün hiçbir plan bu üyeliği kurmuyor", user, JITGroup)
	}

	// Ev dizini hedeften okunuyor: "/home/<ad>" varsaymak, farklı evi olan
	// bir hesapta karalama yolu kontrolünü yanlış yere baktırırdı.
	passwd, err := r.Exec(ctx, "getent passwd "+user, "")
	if absent(t, err) {
		t.Fatalf("%q için passwd satırı okunamadı", user)
	}
	fields := strings.Split(strings.TrimSpace(passwd), ":")
	if len(fields) < 7 {
		t.Fatalf("passwd satırı beklenmedik: %q", passwd)
	}

	steps, err := RevokePlan(caps, Revoke{
		User: user, Mode: ModeDelete, UID: uid, InJITGroup: inJIT,
		Home:      fields[5],
		SudoFiles: []string{"/etc/sudoers.d/postern-yayilim"},
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
	if out, err := r.Exec(ctx, "id "+user, ""); !absent(t, err) {
		t.Errorf("HESAP DURUYOR: %s", out)
	}
}
