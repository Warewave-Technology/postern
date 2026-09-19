package store

import (
	"context"
	"errors"
	"testing"

	"github.com/Warewave-Technology/postern/v2/internal/sudoers"
)

// restartRule, kaçış riski taşımayan bir kural. systemctl BİLEREK
// kullanılmıyor: doğrulayıcı onu kaçış yolu sayıyor (`systemctl edit`
// bir editör açıyor) ve bu testin konusu o ret değil.
func restartRule() sudoers.Rule {
	return sudoers.Rule{Commands: []sudoers.Command{
		{Path: "/usr/sbin/nginx", Args: []string{"-t"}},
	}}
}

/*
 * ⚠️ KURAL ROLE AİT VE ROL ADIYLA OKUNUYOR. Hak verme akışı grupların
 * hangisinin grup olduğunu bu haritadan öğreniyor; grup adları harf
 * duyarsız tekil olduğu için okuma da öyle.
 */
func TestGroupSudoRuleRoundTripsByGroupName(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if _, err := s.CreateGroup(ctx, "dba"); err != nil {
		t.Fatal(err)
	}

	if _, err := s.GroupSudoRule(ctx, "dba"); !errors.Is(err, ErrNotFound) {
		t.Errorf("kuralsız grup: err = %v, ErrNotFound bekleniyordu", err)
	}
	if err := s.SetGroupSudo(ctx, "dba", restartRule(), "yigit"); err != nil {
		t.Fatal(err)
	}

	got, err := s.GroupSudoRule(ctx, "DBA")
	if err != nil {
		t.Fatalf("harf duyarsız okuma: %v", err)
	}
	if got.Group != "dba" || got.UpdatedBy != "yigit" || len(got.Rule.Commands) != 1 ||
		got.Rule.Commands[0].Path != "/usr/sbin/nginx" ||
		len(got.Rule.Commands[0].Args) != 1 || got.UpdatedAt.IsZero() {
		t.Fatalf("kural geri okunmadı: %+v", got)
	}

	// Üzerine yazma: ikinci kural birincinin yerini alıyor, satır çoğalmıyor.
	second := sudoers.Rule{RunAs: "postgres", Commands: []sudoers.Command{
		{Path: "/usr/bin/pg_ctl", Args: []string{"reload"}},
	}}
	if err := s.SetGroupSudo(ctx, "dba", second, "ayse"); err != nil {
		t.Fatal(err)
	}
	all, err := s.GroupSudoRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all["dba"].Rule.RunAs != "postgres" || all["dba"].UpdatedBy != "ayse" {
		t.Fatalf("üzerine yazma: %+v", all)
	}

	if err := s.DeleteGroupSudo(ctx, "dba"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroupSudo(ctx, "dba"); !errors.Is(err, ErrNotFound) {
		t.Errorf("ikinci silme: err = %v, ErrNotFound bekleniyordu", err)
	}
	if err := s.SetGroupSudo(ctx, "yokrol", restartRule(), "yigit"); !errors.Is(err, ErrNotFound) {
		t.Errorf("olmayan grup: err = %v, ErrNotFound bekleniyordu", err)
	}
}

/*
 * ⚠️ KAÇIŞ RİSKİ TAŞIYAN KURAL VERİTABANINDA BEKLEMİYOR. Kabul edilseydi
 * ret, kural hedefe yazılırken (render) gelirdi: kaydedilmiş ama
 * uygulanamayan bir kural, operatörün "verdim" sandığı bir yetki demek.
 * Onaylanan kural yazılıyor — karar operatörün, ama açıkça.
 */
func TestGroupSudoRefusesAWayOutToRootUnlessAcknowledged(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if _, err := s.CreateGroup(ctx, "ops"); err != nil {
		t.Fatal(err)
	}

	escape := sudoers.Rule{Commands: []sudoers.Command{{Path: "/usr/bin/vim"}}}
	err := s.SetGroupSudo(ctx, "ops", escape, "yigit")
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("kaçış kuralı kabul edildi: %v", err)
	}
	if _, rerr := s.GroupSudoRule(ctx, "ops"); !errors.Is(rerr, ErrNotFound) {
		t.Errorf("reddedilen kural yine de yazıldı: %v", rerr)
	}

	escape.Acknowledged = true
	if err := s.SetGroupSudo(ctx, "ops", escape, "yigit"); err != nil {
		t.Fatalf("onaylanan kaçış kuralı reddedildi: %v", err)
	}
	got, err := s.GroupSudoRule(ctx, "ops")
	if err != nil || !got.Rule.Acknowledged {
		t.Errorf("onay bayrağı kaybedildi: %+v (%v)", got, err)
	}

	// Komutsuz kural hiçbir şey vermiyor; onu yazmak sessiz bir boşluk olurdu.
	if err := s.SetGroupSudo(ctx, "ops", sudoers.Rule{}, "yigit"); !errors.Is(err, ErrInvalid) {
		t.Errorf("komutsuz kural: err = %v, ErrInvalid bekleniyordu", err)
	}
}

/*
 * ⚠️ ROL SİLİNİNCE KURALI DA GİDİYOR (ON DELETE CASCADE). Kalsaydı aynı
 * adla açılan yeni bir grup, kimsenin yazmadığı bir sudo kuralıyla
 * doğardı.
 */
func TestDeletingAGroupTakesItsSudoRuleWithIt(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if _, err := s.CreateGroup(ctx, "gecici"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupSudo(ctx, "gecici", restartRule(), "yigit"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroup(ctx, "gecici"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateGroup(ctx, "gecici"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GroupSudoRule(ctx, "gecici"); !errors.Is(err, ErrNotFound) {
		t.Errorf("silinen grubun kuralı yeni group miras kaldı: %v", err)
	}
}
