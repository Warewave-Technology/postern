//go:build integration

package integration

/*
 * Geçici erişimin yaşam döngüsü — gerçek OpenSSH, sudo ve visudo üzerinde:
 * hesap açılıyor, kural yazılıyor, süre dolunca süpürücü hesabı ve
 * dosyalarını söküyor. Birim testleri bu yolu hiç koşturmuyor; koşturan
 * tek yer burası.
 */

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/ca"
	"github.com/Warewave-Technology/postern/internal/jit"
	"github.com/Warewave-Technology/postern/internal/provision"
	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/sudoers"
	"github.com/Warewave-Technology/postern/internal/testdb"
	"github.com/Warewave-Technology/postern/internal/upstream"
)

// jitFixture, hedefi, veritabanını ve hizmeti birlikte kurar.
func jitFixture(t *testing.T) (*jit.Service, *store.Store, certTarget, *provision.SSHRunner, *ca.CA) {
	t.Helper()
	ctx := context.Background()

	authority := testAuthority(t)
	tgt := startCertTarget(t, authority.AuthorizedKey())

	db, err := store.Open(ctx, testdb.DSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser(ctx, "ayse", "ayse@warewave.io", "jitayse"); err != nil {
		t.Fatal(err)
	}
	target := tgt.target()
	target.Name = "cert-target"
	if _, err := db.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}

	svc := jit.New(db, authority, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Hedefi doğrudan okumak için ayrı bir yönetim bağlantısı: test,
	// hizmetin raporuna değil makineye soruyor.
	r, err := provision.Connect(ctx, target, authority, "test", "jit integration")
	if err != nil {
		t.Fatalf("test bağlantısı: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })

	return svc, db, tgt, r, authority
}

func TestATemporaryAccountIsCreatedAndTakenAwayAgain(t *testing.T) {
	svc, db, _, r, authority := jitFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	/*
	 * ⚠️ İKİ AYRI SUDO KAYNAĞI, İKİ AYRI DOSYA. Rolün kuralı grubun
	 * dosyasına (`%yayilim`), hakkın kuralı hesabın dosyasına yazılıyor.
	 * Kullanıcının tasarımı bu: yetki gruba tanımlanıyor, kişi üyelikten
	 * çekiyor; hak sırasında verilen ek yetki yalnızca o hesaba ait.
	 */
	if _, err := db.CreateRole(ctx, "yayilim"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetRoleSudo(ctx, "yayilim", sudoers.Rule{Commands: []sudoers.Command{
		{Path: "/usr/sbin/nginx", Args: []string{"-s", "reload"}},
	}}, "ops"); err != nil {
		t.Fatal(err)
	}

	rule := &sudoers.Rule{Commands: []sudoers.Command{{Path: "/usr/bin/nginx", Args: []string{"-t"}}}}
	out, err := svc.Grant(ctx, jit.Request{
		Username: "ayse", Target: "cert-target", Groups: []string{"yayilim", "gecici"},
		Sudo: rule, Duration: time.Hour, CleanupGroups: true,
	}, "ops")
	if err != nil {
		t.Fatalf("Grant: %v\n%s", err, describe(out.Report))
	}
	if !out.Report.OK() {
		t.Fatalf("rapor OK değil: %s\n%s", out.Report.Summary(), describe(out.Report))
	}

	// ⚠️ MAKİNEYE SORULUYOR, RAPORA DEĞİL.
	facts, err := provision.Account(ctx, r, "jitayse")
	if err != nil || !facts.Exists {
		t.Fatalf("hesap hedefte yok: %+v (%v)", facts, err)
	}
	if !facts.InJITGroup() {
		t.Errorf("hesap %s grubunda değil: %v — süresi dolunca silinemez", provision.JITGroup, facts.Groups)
	}
	if !contains(facts.Groups, "yayilim") || !contains(facts.Groups, "gecici") {
		t.Errorf("istenen gruplara girmemiş: %v", facts.Groups)
	}
	/*
	 * ⚠️ İKİ GRUP DA POSTERN AÇTI; birini geri almadan önce başka bir hesap
	 * (deploy, imajda hazır) kullanmaya başlıyor. Geri alma açtığını
	 * silmeli — ama yalnızca boş kalanı: yayilim kalır, gecici gider.
	 */
	if _, err := r.Exec(ctx, "sudo -n usermod -a -G yayilim deploy", ""); err != nil {
		t.Fatalf("deploy yayilim grubuna alınamadı: %v", err)
	}
	if list, err := r.Exec(ctx, "sudo -n -l -U jitayse", ""); err != nil ||
		!strings.Contains(list, "/usr/bin/nginx -t") ||
		!strings.Contains(list, "/usr/sbin/nginx -s reload") {
		t.Errorf("sudo kuralları hedefte etkin değil: %q (%v)", list, err)
	}
	// Rolün kuralı GRUBUN dosyasında, hesabınkinden ayrı.
	if body, err := r.Exec(ctx, "sudo -n cat "+provision.SudoPath("yayilim"), ""); err != nil ||
		!strings.Contains(body, "%yayilim") || !strings.Contains(body, "/usr/sbin/nginx -s reload") {
		t.Errorf("rolün kuralı grubun dosyasında değil: %q (%v)", body, err)
	}
	// Yedek süre yazılmış olmalı: chage -l ya da shadow'un 8. alanı.
	if shadow, err := r.Exec(ctx, "sudo -n getent shadow jitayse", ""); err != nil || strings.Split(strings.TrimSpace(shadow), ":")[7] == "" {
		t.Errorf("useradd -e yedek süresi yazılmamış: %q (%v)", shadow, err)
	}

	/*
	 * ⚠️ ASIL KANIT: SERTİFİKA HESABI AÇIYOR. Hesap var, gruplar doğru,
	 * sudo kuralı yerinde — ama bunların hiçbiri kişinin girebildiğini
	 * söylemiyor. Hedefin sshd'si AuthorizedPrincipalsFile ile kurulu ve
	 * dosya yokken sertifika reddediliyor; bu satır olmadan test yeşil
	 * kalırken hak kullanılamazdı (öyle de kaldı, bu satır yazılana dek).
	 */
	tgtModel, err := db.Target(ctx, "cert-target")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := upstream.DialWithCert(ctx, tgtModel, upstream.Identity{PosternUser: "ayse", OSUser: "jitayse"}, authority)
	if err != nil {
		t.Fatalf("geçici hesap sertifikayla AÇILAMADI: %v", err)
	}
	who, err := conn.Exec(ctx, "id -un", "")
	_ = conn.Close()
	if err != nil || strings.TrimSpace(who) != "jitayse" {
		t.Fatalf("sertifikayla giren hesap %q (%v), jitayse bekleniyordu", who, err)
	}

	/*
	 * ⚠️ DOSYANIN İZNİ ÖLÇÜLÜYOR, UMASK'A GÜVENİLMİYOR. İçerik o hesabı
	 * kimin açabileceğini söylüyor; izni hedefin ayarına bırakan bir
	 * yazma, umask 000 ile açılmış bir kök kabuğunda dünyaya yazılabilir
	 * bir dosya bırakırdı.
	 */
	if mode, merr := r.Exec(ctx, "sudo -n stat -c %a /etc/ssh/auth_principals/jitayse", ""); merr != nil ||
		strings.TrimSpace(mode) != "644" {
		t.Errorf("principals dosyasının izni %q (%v), 644 bekleniyordu", strings.TrimSpace(mode), merr)
	}

	g, err := db.JITGrant(ctx, out.Grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if g.AppliedAt.IsZero() || !g.Active() {
		t.Errorf("kayıt uygulanmış görünmüyor: %+v", g)
	}
	if !contains(g.CreatedGroups, "yayilim") || !contains(g.CreatedGroups, "gecici") {
		t.Errorf("açılan gruplar kayıtta yok: %v", g.CreatedGroups)
	}

	// Geri alma: hesap, evi ve kural gidiyor; kayıt kapanıyor.
	rout, err := svc.Revoke(ctx, g.ID, "ops", "web")
	if err != nil {
		t.Fatalf("Revoke: %v\n%s", err, describe(rout.Report))
	}
	after, err := provision.Account(ctx, r, "jitayse")
	if err != nil {
		t.Fatal(err)
	}
	if after.Exists {
		t.Errorf("HESAP DURUYOR: %+v", after)
	}
	if home, _ := r.Exec(ctx, "sudo -n test -e /home/jitayse && echo VAR || echo YOK", ""); strings.TrimSpace(home) != "YOK" {
		t.Errorf("ev dizini duruyor")
	}
	if f, _ := r.Exec(ctx, "sudo -n test -e "+provision.UserSudoPath("jitayse")+" && echo VAR || echo YOK", ""); strings.TrimSpace(f) != "YOK" {
		t.Errorf("sudo dosyası duruyor")
	}
	/*
	 * ⚠️ ROLÜN DOSYASI KALIYOR — hakka değil ROLE ait. Geri alma hakkı
	 * kaldırıyor; rolün yetkisini kaldırmak ayrı ve bilinçli bir iş
	 * (rolün kuralını silmek). Hesap gittiği için kimse o kuralı
	 * çekmiyor: yetki üyelikten geliyor.
	 */
	if f, _ := r.Exec(ctx, "sudo -n test -e "+provision.SudoPath("yayilim")+" && echo VAR || echo YOK", ""); strings.TrimSpace(f) != "VAR" {
		t.Errorf("rolün sudo dosyası geri almada silindi")
	}
	if f, _ := r.Exec(ctx, "sudo -n test -e /etc/ssh/auth_principals/jitayse && echo VAR || echo YOK", ""); strings.TrimSpace(f) != "YOK" {
		t.Errorf("principals dosyası duruyor")
	}
	if kept, _ := r.Exec(ctx, "getent group yayilim | cut -d: -f4", ""); !strings.Contains(kept, "deploy") {
		t.Errorf("BAŞKASININ KULLANDIĞI GRUP SİLİNDİ ya da üyesi düştü: %q", kept)
	}
	if gone, _ := r.Exec(ctx, "getent group gecici && echo VAR || echo YOK", ""); !strings.Contains(gone, "YOK") {
		t.Errorf("postern'in açtığı boş grup duruyor: %q", gone)
	}
	// Geri alınan hak sertifikayla da açılmıyor.
	if c, err := upstream.DialWithCert(ctx, tgtModel, upstream.Identity{PosternUser: "ayse", OSUser: "jitayse"}, authority); err == nil {
		_ = c.Close()
		t.Error("GERİ ALINAN HESAP SERTİFİKAYLA HÂLÂ AÇILIYOR")
	}
	g, _ = db.JITGrant(ctx, g.ID)
	if g.Active() || g.RevokeReport == "" {
		t.Errorf("kayıt geri alınmış görünmüyor: %+v", g)
	}
	if _, err := svc.Revoke(ctx, g.ID, "ops", "web"); !errors.Is(err, jit.ErrRevoked) {
		t.Errorf("ikinci geri alma: err = %v, ErrRevoked bekleniyordu", err)
	}
}

/*
 * ⚠️ SÜPÜRÜCÜ SÜRESİ DOLANI ALIYOR, DOLMAYANA DOKUNMUYOR. Saat ileri
 * alınmadan önce süpürme hiçbir şey yapmamalı; alındıktan sonra hesap
 * gitmeli.
 */
func TestTheSweeperRevokesWhatHasExpired(t *testing.T) {
	svc, db, _, r, _ := jitFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Temizleme izni verilmemiş bir hak: açtığı grup geri almada kalıyor.
	out, err := svc.Grant(ctx, jit.Request{
		Username: "ayse", Target: "cert-target", Duration: time.Hour,
		Groups: []string{"kalici"}, CleanupGroups: false,
	}, "ops")
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}

	if revoked, failed := svc.Sweep(ctx); revoked != 0 || failed != 0 {
		t.Fatalf("vadesi gelmemiş hak süpürüldü: revoked=%d failed=%d", revoked, failed)
	}

	// Vadeyi şimdiye çek: elle sonlandırmanın yaptığı şey.
	if err := db.ExpireJITGrant(ctx, out.Grant.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if revoked, failed := svc.Sweep(ctx); revoked != 1 || failed != 0 {
		g, _ := db.JITGrant(ctx, out.Grant.ID)
		t.Fatalf("süpürücü vadesi dolanı almadı: revoked=%d failed=%d — kayıttaki sebep: %q",
			revoked, failed, g.RevokeError)
	}
	after, _ := provision.Account(ctx, r, "jitayse")
	if after.Exists {
		t.Error("süpürücü hesabı silmedi")
	}
	if kept, _ := r.Exec(ctx, "getent group kalici && echo VAR || echo YOK", ""); !strings.Contains(kept, "VAR") {
		t.Errorf("temizleme izni yokken grup silindi: %q", kept)
	}
}

/*
 * ⚠️ VAR OLAN BİR HESAP GEÇİCİ HESABA ÇEVRİLMİYOR — VE KAYIT DA YAZILMIYOR.
 * "deploy" fikstürde postern'den önce var; süresi dolunca silinecek bir
 * hakka bağlanamaz. Hedefe dokunulmadığı için defterde bir hak da yok.
 */
func TestAnExistingAccountIsNeverTurnedIntoATemporaryOne(t *testing.T) {
	svc, db, _, r, _ := jitFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if _, err := db.CreateUser(ctx, "veli", "", "deploy"); err != nil {
		t.Fatal(err)
	}
	_, err := svc.Grant(ctx, jit.Request{Username: "veli", Target: "cert-target", Duration: time.Hour}, "ops")
	if err == nil {
		t.Fatal("var olan hesap geçici hakka bağlandı")
	}
	if grants, _ := db.JITGrantsForTarget(ctx, "cert-target", 10); len(grants) != 0 {
		t.Errorf("reddedilen hak kaydedildi: %+v", grants)
	}
	if facts, _ := provision.Account(ctx, r, "deploy"); !facts.Exists || facts.InJITGroup() {
		t.Errorf("var olan hesaba dokunuldu: %+v", facts)
	}
}

func describe(rep provision.Report) string {
	var b strings.Builder
	for _, res := range rep.Results {
		b.WriteString(string(res.Step.Kind) + " " + string(res.Outcome))
		if res.Err != nil {
			b.WriteString(": " + res.Err.Error())
		}
		b.WriteString("\n")
	}

	return b.String()
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}

	return false
}
