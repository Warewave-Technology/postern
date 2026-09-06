package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

/*
 * Yol kuralları kullanıcının rolleriyle birlikte GERİ OKUNUYOR.
 *
 * ⚠️ NEDEN AYRI TEST: kurallar rollerle aynı JOIN'de gelmiyor (o JOIN
 * hedefler × kurallar kartezyeni üretirdi). Ayrı bir sorgu, ayrı bir
 * ölçüm gerektiriyor — yazılıp okunmadığı fark edilmezse politika hep
 * boş kurallarla çalışır ve sessizce hiçbir şeyi kısıtlamaz.
 */
func TestRolePathsRoundTripThroughUser(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "yigit", "yigit@warewave.io", "yigit"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateRole(ctx, "dev"); err != nil {
		t.Fatal(err)
	}
	if err := s.AssignRole(ctx, "yigit", "dev", time.Time{}); err != nil {
		t.Fatal(err)
	}

	if err := s.SetRolePath(ctx, "dev", "/home/yigit", true, true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRolePath(ctx, "dev", "/home/yigit/.ssh", false, false); err != nil {
		t.Fatal(err)
	}

	u, err := s.User(ctx, "yigit")
	if err != nil {
		t.Fatal(err)
	}
	if len(u.Roles) != 1 {
		t.Fatalf("rol sayısı %d", len(u.Roles))
	}
	rules := u.Roles[0].Paths
	if len(rules) != 2 {
		t.Fatalf("KURALLAR KULLANICIYLA BİRLİKTE GELMEDİ: %+v", rules)
	}

	// Sıra en kısa önekten uzuna: politika en uzun eşleşmeyi arıyor, ama
	// operatörün okuduğu liste de anlamlı bir sırada olmalı.
	if rules[0].Prefix != "/home/yigit" || !rules[0].Allow || !rules[0].CanWrite {
		t.Errorf("ilk kural: %+v", rules[0])
	}
	if rules[1].Prefix != "/home/yigit/.ssh" || rules[1].Allow {
		t.Errorf("ikinci kural: %+v", rules[1])
	}
}

// Aynı önek yeniden yazılınca güncelleniyor, ikinci satır oluşmuyor.
func TestSetRolePathUpdatesInPlace(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateRole(ctx, "dev"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRolePath(ctx, "dev", "/srv", true, false); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRolePath(ctx, "dev", "/srv", true, true); err != nil {
		t.Fatal(err)
	}

	rules, err := s.RolePaths(ctx, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("kural sayısı %d, 1 bekleniyordu: %+v", len(rules), rules)
	}
	if !rules[0].CanWrite {
		t.Error("güncelleme uygulanmadı")
	}
}

/*
 * ⚠️ MUTLAK OLMAYAN ÖNEK REDDEDİLİYOR.
 *
 * Politika göreli yolları zaten reddediyor; kabul etseydik hiçbir zaman
 * eşleşmeyecek bir kural yazdırırdık. Yönetici koruma koyduğunu sanır,
 * koymamış olurdu — kural yazmanın en sessiz başarısızlığı.
 */
func TestRelativePrefixIsRefused(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateRole(ctx, "dev"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRolePath(ctx, "dev", "home/yigit", true, false); err == nil {
		t.Fatal("göreli önek kabul edildi")
	}
}

// Olmayan role kural yazmak sessizce başarılı olmamalı.
func TestSetRolePathOnAMissingRoleFails(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	err := s.SetRolePath(ctx, "yok", "/srv", true, false)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("hata = %v, ErrNotFound bekleniyordu", err)
	}
}
