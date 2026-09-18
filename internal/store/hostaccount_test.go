package store

import (
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/model"
)

func hostAcctEnv(t *testing.T) (*Store, string) {
	t.Helper()
	s := newTestStore(t)
	ctx := t.Context()
	for _, n := range []string{"ayse", "veli"} {
		if _, err := s.CreateUser(ctx, n, "", n); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.CreateTarget(ctx, model.Target{
		Name: "web01", Host: "10.0.0.1", Port: 22, HostKey: "ssh-ed25519 AAAA",
	}); err != nil {
		t.Fatal(err)
	}

	return s, "web01"
}

/*
 * ⚠️ SATIR (hedef, kişi) ÇİFTİNDE TEK. İkinci bir satır, aynı makinede
 * aynı kişi için iki farklı "en son ne yaptık" kaydı demek; hangisinin
 * doğru olduğunu söyleyecek bir şey olmadığı için sıcak yol yanlış parmak
 * izine bakar — ya hedefe boşuna bağlanır ya da gerekliyken bağlanmaz.
 */
func TestAHostAccountRowIsUniquePerTargetAndUser(t *testing.T) {
	s, target := hostAcctEnv(t)
	ctx := t.Context()

	now := time.Now()
	row := HostAccount{
		TargetName: target, Username: "ayse", OSUser: "ayse",
		Origin: OriginCreated, State: HostAccountActive,
		DesiredFP: "fp1", AppliedFP: "fp1", AppliedAt: now,
		FirstSeen: now, UpdatedAt: now,
	}
	if err := s.SaveHostAccount(ctx, row); err != nil {
		t.Fatal(err)
	}

	// İkinci yazma aynı satırı GÜNCELLER.
	row.AppliedFP = "fp2"
	row.State = HostAccountLocked
	if err := s.SaveHostAccount(ctx, row); err != nil {
		t.Fatal(err)
	}

	got, err := s.HostAccountFor(ctx, target, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if got.AppliedFP != "fp2" || got.State != HostAccountLocked {
		t.Errorf("güncelleme uygulanmadı: %+v", got)
	}

	/*
	 * ⚠️ origin İLK YAZMADA SABİTLENİYOR. Hesabı postern'in mi açtığı
	 * yoksa devraldığı mı sorusu makineye bakarak cevaplanamıyor; sonraki
	 * bir yazmanın onu ezmesi, silme diyaloğunun "bu hesabı biz açtık"
	 * diyebilmesini imkânsız kılardı.
	 */
	row.Origin = OriginAdopted
	if err := s.SaveHostAccount(ctx, row); err != nil {
		t.Fatal(err)
	}
	got, _ = s.HostAccountFor(ctx, target, "ayse")
	if got.Origin != OriginCreated {
		t.Errorf("origin ezildi: %q — hesabı kimin açtığı sonradan öğrenilemez", got.Origin)
	}

	all, err := s.HostAccountsForUser(ctx, "ayse")
	if err != nil || len(all) != 1 {
		t.Errorf("kişinin satırları: %v %+v", err, all)
	}
}

/*
 * ⚠️ KARAR BEKLEYENLER AYRI SORGU. Panel bu listeyi her açılışta okuyor;
 * bütün satırları çekip Go'da süzmek, on bin hesaplı bir kurulumda
 * paneli yavaşlatır — ve listenin kısa olması onu ucuz sanmaya yol açar.
 */
func TestOnlyRowsAwaitingADecisionAreListed(t *testing.T) {
	s, target := hostAcctEnv(t)
	ctx := t.Context()

	now := time.Now()
	base := HostAccount{
		TargetName: target, OSUser: "x", Origin: OriginCreated,
		State: HostAccountLocked, FirstSeen: now, UpdatedAt: now,
	}
	base.Username = "ayse"
	base.AwaitingDecision = true
	if err := s.SaveHostAccount(ctx, base); err != nil {
		t.Fatal(err)
	}
	base.Username = "veli"
	base.AwaitingDecision = false
	if err := s.SaveHostAccount(ctx, base); err != nil {
		t.Fatal(err)
	}

	waiting, err := s.HostAccountsAwaitingDecision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(waiting) != 1 || waiting[0].Username != "ayse" {
		t.Errorf("bekleyenler: %+v", waiting)
	}
}

/* Olmayan satır ErrNotFound: "hiç hazırlanmadı" ile "hazırlandı ve boş"
 * ayrı cevaplar ve sıcak yol ikisini ayırmak zorunda. */
func TestAMissingRowIsNotFound(t *testing.T) {
	s, target := hostAcctEnv(t)
	if _, err := s.HostAccountFor(t.Context(), target, "ayse"); err == nil {
		t.Error("olmayan satır hata vermedi")
	}
}

/*
 * ⚠️ İŞ, İŞARET SÜTUNUNDAN DEĞİL DURUMDAN TÜRÜYOR.
 *
 * Bir `pending` bayrağı olsaydı, onu yazmayı unutan her yeni yazma yolu
 * sessiz bir boşluk açardı — ve bu tam olarak "group'u düşen kişi
 * makinede açık kaldı" boşluğu olurdu. Bu test, group üyeliği
 * kaldırıldığı anda hiçbir şey işaretlenmeden işin GÖRÜNDÜĞÜNÜ ölçüyor.
 */
func TestALockIsOwedAsSoonAsTheLastGroupGoes(t *testing.T) {
	s, target := hostAcctEnv(t)
	ctx := t.Context()
	now := time.Now()

	if _, err := s.CreateGroup(ctx, "dba"); err != nil {
		t.Fatal(err)
	}
	if err := s.GrantTarget(ctx, "dba", target); err != nil {
		t.Fatal(err)
	}
	if err := s.AssignGroup(ctx, "ayse", "dba", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveHostAccount(ctx, HostAccount{
		TargetName: target, Username: "ayse", OSUser: "ayse",
		Origin: OriginCreated, State: HostAccountActive,
		FirstSeen: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	owed, err := s.HostAccountsOwedALock(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(owed) != 0 {
		t.Fatalf("erişimi duran hesap borçlu göründü: %+v", owed)
	}

	// Group gidince, HİÇBİR ŞEY İŞARETLENMEDEN iş görünür oluyor.
	if err := s.RevokeGroup(ctx, "ayse", "dba"); err != nil {
		t.Fatal(err)
	}
	owed, err = s.HostAccountsOwedALock(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(owed) != 1 || owed[0].Username != "ayse" {
		t.Errorf("group kaybından sonra borçlu liste: %+v", owed)
	}
}

/*
 * ⚠️ SÜRESİ DOLMUŞ ÜYELİK ERİŞİM DEĞİL. Süreli bir group'un süresi
 * dolduğunda erişim biter; onu saymak süreyi anlamsız kılardı ve süreli
 * verilen bir yetki makinede kalıcı olurdu.
 */
func TestAnExpiredMembershipDoesNotCountAsAccess(t *testing.T) {
	s, target := hostAcctEnv(t)
	ctx := t.Context()
	now := time.Now()

	if _, err := s.CreateGroup(ctx, "dba"); err != nil {
		t.Fatal(err)
	}
	if err := s.GrantTarget(ctx, "dba", target); err != nil {
		t.Fatal(err)
	}
	if err := s.AssignGroup(ctx, "ayse", "dba", now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveHostAccount(ctx, HostAccount{
		TargetName: target, Username: "ayse", OSUser: "ayse",
		Origin: OriginCreated, State: HostAccountActive,
		FirstSeen: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	owed, err := s.HostAccountsOwedALock(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(owed) != 1 {
		t.Errorf("süresi dolmuş üyelik erişim sayıldı: %+v", owed)
	}
}

/* Zaten kilitli satır yeniden kilitlenmiyor. */
func TestALockedRowIsNotOwedAnotherLock(t *testing.T) {
	s, target := hostAcctEnv(t)
	ctx := t.Context()
	now := time.Now()

	if err := s.SaveHostAccount(ctx, HostAccount{
		TargetName: target, Username: "ayse", OSUser: "ayse",
		Origin: OriginCreated, State: HostAccountLocked,
		FirstSeen: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	owed, err := s.HostAccountsOwedALock(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(owed) != 0 {
		t.Errorf("kilitli satır yeniden borçlu: %+v", owed)
	}
}
