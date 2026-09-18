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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/hostacct"
	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/provision"
	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/sudoers"
	"github.com/Warewave-Technology/postern/internal/testdb"
)

func hostAcctFixture(t *testing.T) (*store.Store, model.Target, *provision.SSHRunner,
	func(context.Context, model.User, model.Target) error, *hostacct.Worker, *hostacct.Sweeper,
) {
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
	hook := hostacct.Hook(db, authority, logger, 60000, 64999)
	worker := hostacct.NewLockWorker(db, authority, logger, time.Minute)
	// Önden açma AÇIK: süpürmenin iki işi de tek kurulumda ölçülebilsin.
	sweeper := hostacct.NewSweepWorker(db, authority, logger, time.Hour, true, 60000, 64999)

	r, err := provision.Connect(ctx, target, authority, "test", "host account integration")
	if err != nil {
		t.Fatalf("test bağlantısı: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })

	return db, target, r, hook, worker, sweeper
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
	db, target, r, hook, _, _ := hostAcctFixture(t)
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
	if got := ask(t, r, "sudo -n cat "+provision.SudoPath("postern-dba")); got != "" {
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
	db, target, r, hook, _, _ := hostAcctFixture(t)
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
	db, target, r, hook, worker, _ := hostAcctFixture(t)
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

/*
 * ⚠️ AÇILAN HESAP HAVUZUN NUMARASINI TAŞIYOR — MAKİNEDE.
 *
 * Numaranın veritabanında doğru durması bir şey ifade etmiyor; ölçülecek
 * olan hedefteki hesabın gerçekten o numarayla açılmış olması. Aradaki
 * fark, `useradd -u`'nun hiç geçilmemesi kadar sessiz bir hatayla kapanır
 * ve sonucu ancak ikinci bir makinede, dosya sahipliği tutmayınca görülür.
 */
func TestACreatedAccountCarriesTheFleetNumber(t *testing.T) {
	db, target, r, hook, _, _ := hostAcctFixture(t)
	ctx := context.Background()

	u, err := db.User(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if err := hook(ctx, u, target); err != nil {
		t.Fatalf("hazırlama: %v", err)
	}

	reserved, err := db.UIDFor(ctx, "ayse")
	if err != nil {
		t.Fatalf("numara ayrılmadı: %v", err)
	}
	if got := ask(t, r, "id -u acctayse"); got != strconv.Itoa(reserved.UID) {
		t.Errorf("makinedeki numara %q, ayrılan %d", got, reserved.UID)
	}
	if reserved.UID < 60000 || reserved.UID > 64999 {
		t.Errorf("numara havuz dışında: %d", reserved.UID)
	}
}

/*
 * ⚠️ DOLU NUMARA ZORLANMIYOR — VE HESAP YİNE DE AÇILIYOR.
 *
 * Zorlamak, o numaraya ait bütün dosyaların sahipliğini yeni hesaba
 * devretmek olurdu: eski sahibin evi, log'ları, anahtarları. Kişinin o
 * makinede filo numarasını taşımaması bunun yanında küçük bir zarar;
 * kapıyı kapatmak ise K6'ya aykırı olurdu.
 */
func TestATakenNumberIsNotForcedOnTheHost(t *testing.T) {
	db, target, r, hook, _, _ := hostAcctFixture(t)
	ctx := context.Background()

	// Havuzun ilk vereceği numarayı postern'den önce başkası tutuyor.
	if _, err := r.Exec(ctx, "sudo -n useradd -m -u 60000 -s /bin/sh squatter", ""); err != nil {
		t.Fatalf("hazırlık hesabı açılamadı: %v", err)
	}

	u, err := db.User(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if err := hook(ctx, u, target); err != nil {
		t.Fatalf("hazırlama: %v", err)
	}

	reserved, err := db.UIDFor(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if reserved.UID != 60000 {
		t.Fatalf("test varsayımı bozuldu: havuz %d verdi, 60000 bekleniyordu", reserved.UID)
	}
	if got := ask(t, r, "id -u squatter"); got != "60000" {
		t.Errorf("numara başkasından alındı: squatter = %q", got)
	}
	got := ask(t, r, "id -u acctayse")
	if got == "" {
		t.Fatal("çakışma yüzünden hesap hiç açılmadı")
	}
	if got == "60000" {
		t.Errorf("dolu numara zorlandı: acctayse = %q", got)
	}
}

/*
 * ⚠️ AYNI MAKİNEDE İKİNCİ KİŞİ DE HESAP ALABİLMELİ.
 *
 * İlk kişi postern-managed grubunu açıyor. İkincisi için istenen durum
 * aynı grubu yeniden istiyor; o grubun hedefte ZATEN VAR olduğu
 * görülmezse plan bir `groupadd` daha üretir, hedef "grup var" diye
 * reddeder ve ikinci kişi o makinede hiç hesap alamaz — geri çekilmeyle,
 * sonsuza kadar.
 */
func TestASecondPersonAlsoGetsAnAccountOnTheSameHost(t *testing.T) {
	db, target, r, hook, _, _ := hostAcctFixture(t)
	ctx := context.Background()

	if _, err := db.CreateUser(ctx, "veli", "veli@warewave.io", "acctveli"); err != nil {
		t.Fatal(err)
	}
	if err := db.AssignGroup(ctx, "veli", "dba", time.Time{}); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"ayse", "veli"} {
		u, err := db.User(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		if err := hook(ctx, u, target); err != nil {
			t.Fatalf("%s hazırlanamadı: %v", name, err)
		}
	}

	for _, acct := range []string{"acctayse", "acctveli"} {
		if got := ask(t, r, "getent passwd "+acct); got == "" {
			t.Errorf("%s açılmadı", acct)
		}
		if got := ask(t, r, "id -Gn "+acct); !strings.Contains(got, "postern-managed") {
			t.Errorf("%s marker grubunda değil: %q", acct, got)
		}
	}
}

/*
 * ⚠️ SÜPÜRMENİN ASIL BULGUSU: postern'in grubuna ELLE EKLENEN HESAP.
 *
 * O hesap, postern'in o gruba yazdığı sudo kuralını alıyor ve postern'in
 * hiçbir kaydında görünmüyor — yani postern'in verdiği yetki, postern'in
 * bilmediği birinde. Ne sıcak yol ne itme yolu bunu görebiliyor: biri
 * yalnızca kişi bağlandığında koşuyor, öbürü yalnızca postern'in kendi
 * kaydına bakıyor. Ölçü makinenin cevabı: `id -Gn`.
 */
func TestTheSweepTakesAHandAddedAccountOutOfPosternsGroup(t *testing.T) {
	db, target, r, hook, _, sweeper := hostAcctFixture(t)
	ctx := context.Background()

	u, err := db.User(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if err := hook(ctx, u, target); err != nil {
		t.Fatalf("hazırlama: %v", err)
	}

	// Başka biri, elle, postern'in grubuna giriyor.
	if _, err := r.Exec(ctx, "sudo -n useradd -m -s /bin/sh sizan", ""); err != nil {
		t.Fatalf("hazırlık hesabı: %v", err)
	}
	if _, err := r.Exec(ctx, "sudo -n usermod -a -G postern-dba sizan", ""); err != nil {
		t.Fatalf("elle ekleme: %v", err)
	}
	if got := ask(t, r, "id -Gn sizan"); !strings.Contains(got, "postern-dba") {
		t.Fatalf("test varsayımı bozuldu, elle ekleme tutmadı: %q", got)
	}

	sweeper.Tick(ctx)

	if got := ask(t, r, "id -Gn sizan"); strings.Contains(got, "postern-dba") {
		t.Errorf("elle eklenen hesap grupta kaldı: %q", got)
	}
	// Hesabın kendisine dokunulmuyor: giden tek şey postern'in yetkisi.
	if got := ask(t, r, "getent passwd sizan"); got == "" {
		t.Error("süpürme hesabı sildi; yalnızca üyeliği kaldırmalıydı")
	}
	// Meşru üye yerinde.
	if got := ask(t, r, "id -Gn acctayse"); !strings.Contains(got, "postern-dba") {
		t.Errorf("meşru üye de atıldı: %q", got)
	}
}

/*
 * ⚠️ SİLİNEN SUDOERS DOSYASI GERİ GELİYOR.
 *
 * Sıcak yol bunu göremez: parmak izi postern'in İSTEDİĞİ durumdan
 * türüyor ve hedefte elle silinen bir dosya o izi değiştirmiyor — yani
 * kişi bağlansa bile hızlı şerit hedefe hiç uğramaz ve yetki sessizce
 * kaybolmuş kalır.
 */
func TestTheSweepPutsBackASudoersFileSomebodyDeleted(t *testing.T) {
	db, target, r, hook, _, sweeper := hostAcctFixture(t)
	ctx := context.Background()

	if err := db.SetGroupSudo(ctx, "dba", sudoers.Rule{
		Commands: []sudoers.Command{{Path: "/usr/bin/uptime"}},
	}, "test"); err != nil {
		t.Fatal(err)
	}
	u, err := db.User(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if err := hook(ctx, u, target); err != nil {
		t.Fatalf("hazırlama: %v", err)
	}
	// Yol provision'dan: SudoPath öneki kendisi ekliyor ve elle yazılan
	// bir yol, testi hep "dosya yok" gösterirdi.
	path := provision.SudoPath("postern-dba")
	if got := ask(t, r, "sudo -n cat "+path); got == "" {
		t.Fatalf("test varsayımı bozuldu: %s hiç yazılmadı", path)
	}

	if _, err := r.Exec(ctx, "sudo -n rm -f "+path, ""); err != nil {
		t.Fatalf("silme: %v", err)
	}

	sweeper.Tick(ctx)

	if got := ask(t, r, "sudo -n cat "+path); got == "" {
		t.Errorf("süpürme silinen %s dosyasını geri getirmedi", path)
	}
}

/*
 * ⚠️ ÖNDEN AÇMA: KİŞİ HİÇ BAĞLANMADAN HESAP AÇILIYOR.
 *
 * Varsayılan değil ve olmaması bilinçli ("hesap kullanıldığı yerde
 * vardır"), ama açıldığında gerçekten açması gerekiyor — dosya
 * sahipliği, cron ve mail bunu isteyen kurumların sebebi.
 */
func TestTheSweepCanOpenAnAccountBeforeAnybodyConnects(t *testing.T) {
	db, _, r, _, _, sweeper := hostAcctFixture(t)
	ctx := context.Background()

	if _, err := db.CreateUser(ctx, "veli", "veli@warewave.io", "acctveli"); err != nil {
		t.Fatal(err)
	}
	if err := db.AssignGroup(ctx, "veli", "dba", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if got := ask(t, r, "getent passwd acctveli"); got != "" {
		t.Fatalf("test varsayımı bozuldu: hesap zaten var (%q)", got)
	}

	sweeper.Tick(ctx)

	if got := ask(t, r, "getent passwd acctveli"); got == "" {
		t.Fatal("önden açma hesabı açmadı")
	}
	if got := ask(t, r, "id -Gn acctveli"); !strings.Contains(got, "postern-dba") {
		t.Errorf("grup üyeliği kurulmadı: %q", got)
	}
}
