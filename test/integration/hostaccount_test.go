//go:build integration

package integration

/*
 * Bağlanma anında hesap açma ve group kaybında kapatma — gerçek sshd,
 * gerçek sudo, gerçek passwd.
 *
 * ⚠️ BURADA ÖLÇÜLEN ŞEY BİRİM TESTİN ÖLÇEMEDİĞİ: hesabın gerçekten
 * açıldığı, grubun gerçekten kurulduğu, kuralın gerçekten etkin olduğu ve
 * kilitten sonra girişin gerçekten reddedildiği. Taklit bir hedef bunların
 * hiçbirini söyleyemiyor.
 */

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/hostacct"
	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/provision"
	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/testdb"
)

func hostAcctFixture(t *testing.T) (*store.Store, model.Target, *provision.SSHRunner, func(context.Context, model.User, model.Target) error, *hostacct.Worker) {
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
	if _, err := db.CreateUser(ctx, "ayse", "ayse@warewave.io", "acctayse"); err != nil {
		t.Fatal(err)
	}
	target := tgt.target()
	target.Name = "acct-target"
	if _, err := db.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateGroup(ctx, "dba"); err != nil {
		t.Fatal(err)
	}
	if err := db.GrantTarget(ctx, "dba", target.Name); err != nil {
		t.Fatal(err)
	}
	if err := db.AssignGroup(ctx, "ayse", "dba", time.Time{}); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	hook := hostacct.Hook(db, authority, logger)
	worker := hostacct.NewLockWorker(db, authority, logger, time.Minute)

	r, err := provision.Connect(ctx, target, authority, "test", "host account integration")
	if err != nil {
		t.Fatalf("test bağlantısı: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })

	return db, target, r, hook, worker
}

func ask(t *testing.T, r *provision.SSHRunner, cmd string) string {
	t.Helper()
	out, err := r.Exec(context.Background(), cmd, "")

	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

/*
 * ⚠️ İLK BAĞLANTI HESABI AÇIYOR, İKİNCİSİ HEDEFE HİÇ DOKUNMUYOR.
 *
 * İkinci iddia, özelliğin yaşama şartı: fingerprint tutuyorsa yönetim
 * bağlantısı açılmamalı. Ölçüsü sayaç — hedefin kabul ettiği bağlantı
 * sayısı ikinci çağrıda ARTMAMALI. "Sonuç doğru" demek yetmiyor; doğru
 * sonuca her seferinde bir SSH el sıkışması ödeyerek varmak, özelliği
 * kullanılamaz yapar.
 */
func TestAnAccountIsCreatedOnTheFirstConnectAndSkippedOnTheSecond(t *testing.T) {
	db, target, r, hook, _ := hostAcctFixture(t)
	ctx := context.Background()

	u, err := db.User(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}

	if err := hook(ctx, u, target); err != nil {
		t.Fatalf("ilk hazırlama: %v", err)
	}

	// Makineye soruluyor, rapora değil.
	if got := ask(t, r, "getent passwd acctayse"); got == "" {
		t.Fatal("hesap açılmadı")
	}
	if got := ask(t, r, "id -Gn acctayse"); !strings.Contains(got, "postern-dba") {
		t.Errorf("group üyeliği kurulmadı: %q", got)
	}
	if got := ask(t, r, "sudo -n cat /etc/sudoers.d/postern-dba"); got != "" {
		t.Logf("grup sudoers dosyası: %q", got)
	}

	row, err := db.HostAccountFor(ctx, target.Name, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if row.Origin != store.OriginCreated || row.State != store.HostAccountActive {
		t.Errorf("satır: %+v", row)
	}

	// İKİNCİ ÇAĞRI: hedefe hiç bağlanılmamalı.
	before := ask(t, r, "sudo -n grep -c 'Accepted publickey' /var/log/auth.log")
	if err := hook(ctx, u, target); err != nil {
		t.Fatalf("ikinci hazırlama: %v", err)
	}
	after := ask(t, r, "sudo -n grep -c 'Accepted publickey' /var/log/auth.log")
	if before != "" && after != "" && before != after {
		t.Errorf("fingerprint tutarken hedefe bağlanıldı: %s → %s", before, after)
	}
}

/*
 * ⚠️ VAR OLAN HESAP DEVRALINIYOR: UID'si ve kabuğu DEĞİŞMİYOR.
 *
 * Var olan bir Ansible filosunun altına kayabilmemizin tek yolu bu. UID
 * değişseydi, o kişinin makinedeki bütün dosyalarının sahipliği bir anda
 * kopardı.
 */
func TestAnExistingAccountKeepsItsUIDAndShell(t *testing.T) {
	db, target, r, hook, _ := hostAcctFixture(t)
	ctx := context.Background()

	// Hesabı POSTERN'DEN ÖNCE, başka bir araç açmış gibi kur.
	if _, err := r.Exec(ctx, "sudo -n useradd -m -u 4242 -s /bin/sh acctayse", ""); err != nil {
		t.Fatalf("hazırlık hesabı açılamadı: %v", err)
	}
	beforeUID := ask(t, r, "id -u acctayse")
	beforeShell := ask(t, r, "getent passwd acctayse")

	u, err := db.User(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if err := hook(ctx, u, target); err != nil {
		t.Fatalf("hazırlama: %v", err)
	}

	if got := ask(t, r, "id -u acctayse"); got != beforeUID {
		t.Errorf("UID değişti: %s → %s", beforeUID, got)
	}
	if got := ask(t, r, "getent passwd acctayse"); got != beforeShell {
		t.Errorf("passwd satırı değişti:\n%s\n%s", beforeShell, got)
	}
	row, _ := db.HostAccountFor(ctx, target.Name, "ayse")
	if row.Origin != store.OriginAdopted {
		t.Errorf("kaynak = %q, devralma bekleniyordu", row.Origin)
	}
}

/*
 * ⚠️ GROUP GİDİNCE HESAP KİLİTLENİYOR VE GİRİŞ REDDEDİLİYOR.
 *
 * Kilidin ölçüsü satırdaki durum değil, MAKİNENİN cevabı: hesabın süresi
 * dolmuş olmalı ve principals satırı gitmiş olmalı. Satıra bakmak,
 * postern'in kendi iddiasını kendisiyle doğrulamak olurdu.
 */
func TestLosingTheLastGroupLocksTheAccountOnTheHost(t *testing.T) {
	db, target, r, hook, worker := hostAcctFixture(t)
	ctx := context.Background()

	u, err := db.User(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if err := hook(ctx, u, target); err != nil {
		t.Fatalf("hazırlama: %v", err)
	}
	if got := ask(t, r, "getent passwd acctayse"); got == "" {
		t.Fatal("hesap açılmadı")
	}

	// Group gidiyor: artık hiçbir group bu hedefi vermiyor.
	if err := db.RevokeGroup(ctx, "ayse", "dba"); err != nil {
		t.Fatal(err)
	}

	worker.Tick(ctx)

	row, err := db.HostAccountFor(ctx, target.Name, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if row.State != store.HostAccountLocked {
		t.Fatalf("satır kilitli değil: %+v", row)
	}
	if !row.AwaitingDecision {
		t.Error("karar bekleyen olarak işaretlenmedi")
	}

	// ⚠️ MAKİNEYE SORULUYOR: hesabın süresi dolmuş mu?
	shadow := ask(t, r, "sudo -n getent shadow acctayse")
	fields := strings.Split(shadow, ":")
	if len(fields) < 8 || strings.TrimSpace(fields[7]) == "" {
		t.Errorf("hesabın süresi doldurulmamış: %q", shadow)
	}

	// Ev dizini DURUYOR: kilit geri alınabilir olmak zorunda.
	if got := ask(t, r, "sudo -n test -d /home/acctayse && echo var"); got != "var" {
		t.Errorf("ev dizini silinmiş — kilit geri alınamaz hâle geldi")
	}
}
