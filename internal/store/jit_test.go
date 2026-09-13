package store

// Geçici erişim haklarının saklanması (göç 041).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/sudoers"
)

func aGrant(expiresIn time.Duration) JITGrant {
	now := time.Unix(1_800_000_000, 0)
	return JITGrant{
		Username: "ayse", Target: "web01", OSUser: "ayse",
		Groups:    []string{"dba"},
		Sudo:      &sudoers.Rule{Commands: []sudoers.Command{{Path: "/usr/bin/nginx", Args: []string{"-t"}}}},
		GrantedBy: "ops", GrantedAt: now, ExpiresAt: now.Add(expiresIn),
	}
}

/*
 * ⚠️ HAK BAYT BAYT GERİ OKUNMALI — sudo kuralı dahil. Geri alma planı
 * dosya yolunu kuraldan, üyelik adımı grupları listeden türetiyor; eksik
 * dönen bir alan, makinede bırakılan bir şey demek.
 */
func TestJITGrantSurvivesTheRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	want := aGrant(2 * time.Hour)
	id, err := s.CreateJITGrant(ctx, want)
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.JITGrant(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Username != "ayse" || got.Target != "web01" || got.OSUser != "ayse" || got.GrantedBy != "ops" {
		t.Errorf("kimlik alanları bozuldu: %+v", got)
	}
	if len(got.Groups) != 1 || got.Groups[0] != "dba" {
		t.Errorf("gruplar = %v", got.Groups)
	}
	if got.Sudo == nil || len(got.Sudo.Commands) != 1 || got.Sudo.Commands[0].Path != "/usr/bin/nginx" {
		t.Errorf("sudo kuralı bozuldu: %+v", got.Sudo)
	}
	if !got.ExpiresAt.Equal(want.ExpiresAt) || !got.GrantedAt.Equal(want.GrantedAt) {
		t.Errorf("zamanlar bozuldu: %+v", got)
	}
	if !got.Active() || got.Due(want.GrantedAt) {
		t.Errorf("yeni hak aktif ve vadesi gelmemiş olmalı: %+v", got)
	}
	if !got.AppliedAt.IsZero() {
		t.Error("uygulanmadan applied_at dolu")
	}

	// Kuralsız hak: nil geri dönmeli, boş kural değil.
	plain := aGrant(time.Hour)
	plain.Sudo = nil
	plain.Groups = nil
	id2, err := s.CreateJITGrant(ctx, plain)
	if err != nil {
		t.Fatal(err)
	}
	got2, _ := s.JITGrant(ctx, id2)
	if got2.Sudo != nil || got2.Groups == nil || len(got2.Groups) != 0 {
		t.Errorf("kuralsız hak yanlış okundu: sudo=%+v groups=%#v", got2.Sudo, got2.Groups)
	}
}

/*
 * ⚠️ SÜPÜRÜCÜ YALNIZCA VADESİ GELENİ VE DENEME ZAMANI GELENİ GÖRMELİ.
 * Vadesi gelmemiş bir hakkı geri almak hakkı kesmek; geri alınmışı
 * yeniden almak hedefe boşuna root'la girmek; deneme zamanı gelmemişi
 * almak ise başarısız bir makineye saniyede bir bağlanmak demek.
 */
func TestDueGrantsAreOnlyTheOnesTheSweeperShouldTouch(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	now := time.Unix(1_800_000_000, 0)

	expired, _ := s.CreateJITGrant(ctx, aGrant(time.Hour))
	fresh, _ := s.CreateJITGrant(ctx, aGrant(48*time.Hour))
	revoked, _ := s.CreateJITGrant(ctx, aGrant(time.Hour))
	backoff, _ := s.CreateJITGrant(ctx, aGrant(time.Hour))

	later := now.Add(2 * time.Hour)
	if err := s.MarkJITGrantRevoked(ctx, revoked, "account removed", later); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkJITGrantRevokeFailed(ctx, backoff, "target unreachable", later.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}

	due, err := s.DueJITGrants(ctx, later)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, g := range due {
		ids[g.ID] = true
	}
	if !ids[expired] {
		t.Error("vadesi dolan hak listede yok")
	}
	if ids[fresh] {
		t.Error("vadesi GELMEMİŞ hak süpürülecekti")
	}
	if ids[revoked] {
		t.Error("geri alınmış hak yeniden süpürülecekti")
	}
	if ids[backoff] {
		t.Error("deneme zamanı gelmemiş hak süpürülecekti")
	}

	// Deneme zamanı gelince başarısız olan geri geliyor; sayaç ve sebep duruyor.
	due, _ = s.DueJITGrants(ctx, later.Add(11*time.Minute))
	found := false
	for _, g := range due {
		if g.ID == backoff {
			found = true
			if g.RevokeAttempts != 1 || g.RevokeError != "target unreachable" {
				t.Errorf("başarısız deneme kaydı eksik: %+v", g)
			}
		}
	}
	if !found {
		t.Error("deneme zamanı geldiği hâlde başarısız hak listede yok")
	}
}

/*
 * ⚠️ TAM UYGULANAMAYAN HAK HEMEN VADESİ DOLMUŞ SAYILIYOR. Yarım bir
 * hesabı istenen süre boyunca makinede bırakmak, kimsenin onaylamadığı bir
 * erişim bırakmak olurdu; süpürücü ilk turunda toplamalı.
 */
func TestAGrantThatCouldNotBeAppliedFallsDueAtOnce(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	now := time.Unix(1_800_000_000, 0)

	id, _ := s.CreateJITGrant(ctx, aGrant(8*time.Hour))
	if err := s.MarkJITGrantApplied(ctx, id, false, "1 applied, 1 failed, 2 not attempted", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	g, _ := s.JITGrant(ctx, id)
	if !g.AppliedAt.IsZero() {
		t.Error("başarısız uygulama applied_at yazdı")
	}
	if !g.Due(now.Add(time.Minute)) {
		t.Errorf("yarım uygulanan hak vadesi dolmuş sayılmıyor: %+v", g)
	}
	if g.ApplyReport == "" {
		t.Error("rapor kaybolmuş")
	}

	// Karşı örnek: başarılı uygulama vadeyi DEĞİŞTİRMİYOR.
	ok, _ := s.CreateJITGrant(ctx, aGrant(8*time.Hour))
	if err := s.MarkJITGrantApplied(ctx, ok, true, "4 applied", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	g, _ = s.JITGrant(ctx, ok)
	if g.AppliedAt.IsZero() || g.Due(now.Add(time.Hour)) {
		t.Errorf("başarılı uygulama yanlış yazıldı: %+v", g)
	}
}

// Geri alınmış hak bir daha değiştirilemez; elle geri alma vadeyi şimdiye çeker.
func TestRevokedGrantIsFinalAndExpireBringsTheEndForward(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	now := time.Unix(1_800_000_000, 0)

	id, _ := s.CreateJITGrant(ctx, aGrant(8*time.Hour))
	if err := s.ExpireJITGrant(ctx, id, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	g, _ := s.JITGrant(ctx, id)
	if !g.Due(now.Add(time.Minute)) {
		t.Errorf("elle sonlandırılan hak vadesi dolmuş değil: %+v", g)
	}

	if err := s.MarkJITGrantRevoked(ctx, id, "done", now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"revoked again": s.MarkJITGrantRevoked(ctx, id, "again", now.Add(3*time.Minute)),
		"failed after":  s.MarkJITGrantRevokeFailed(ctx, id, "x", now.Add(3*time.Minute)),
		"expire after":  s.ExpireJITGrant(ctx, id, now.Add(3*time.Minute)),
		"applied after": s.MarkJITGrantApplied(ctx, id, true, "x", now.Add(3*time.Minute)),
		"unknown grant": s.MarkJITGrantRevoked(ctx, "yok", "x", now),
	} {
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: err = %v, ErrNotFound bekleniyordu", name, err)
		}
	}

	active, _ := s.ActiveJITGrantsForUser(ctx, "ayse")
	if len(active) != 0 {
		t.Errorf("geri alınmış hak aktif listede: %d", len(active))
	}
}

/*
 * ⚠️ BASTION'IN KENDİ EYLEMİ DEFTERE YAZILABİLMELİ — VE YAZILAMIYORDU.
 * via sütununun kısıtı 'system'i tanımıyordu; kayıt budayıcısı başından
 * beri o değerle yazıyor ve her satırı reddediliyordu. Süpürücü aynı
 * duvara çarpınca ortaya çıktı (göç 042).
 */
func TestTheBastionItselfCanWriteToTheAdminLog(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if err := s.LogAdmin(ctx, AdminLogEntry{
		Actor: "system", Via: "system", Action: "jit.revoke", Entity: "web01",
		Details: "expired grant revoked unattended",
	}); err != nil {
		t.Fatalf("bastion kendi eylemini yazamadı: %v", err)
	}

	logs, err := s.AdminLog(ctx, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 || logs[0].Via != "system" {
		t.Errorf("satır yok ya da via yanlış: %+v", logs)
	}
}

// Sekme bütün hedefleri tek listede, en yeni önce istiyor.
func TestAllGrantsComeNewestFirstAcrossTargets(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := t.Context()

	older := aGrant(time.Hour)
	older.GrantedAt = older.GrantedAt.Add(-time.Hour)
	first, err := s.CreateJITGrant(ctx, older)
	if err != nil {
		t.Fatal(err)
	}
	newer := aGrant(time.Hour)
	newer.Target = "db01"
	second, err := s.CreateJITGrant(ctx, newer)
	if err != nil {
		t.Fatal(err)
	}

	all, err := s.JITGrants(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].ID != second || all[1].ID != first {
		t.Fatalf("liste = %+v; en yeni (%s) önce, sonra %s bekleniyordu", all, second, first)
	}
	if all[0].Target != "db01" || all[1].Target != "web01" {
		t.Errorf("hedefler karıştı: %s, %s", all[0].Target, all[1].Target)
	}
	if one, err := s.JITGrants(ctx, 1); err != nil || len(one) != 1 || one[0].ID != second {
		t.Errorf("limit 1: %+v (%v)", one, err)
	}
}

// Açılan gruplar ve temizleme izni kayıtta gidip geliyor.
func TestCreatedGroupsAndCleanupFlagRoundTrip(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := t.Context()

	g := aGrant(time.Hour)
	g.CleanupGroups = true
	id, err := s.CreateJITGrant(ctx, g)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.JITGrant(ctx, id)
	if err != nil || !got.CleanupGroups || len(got.CreatedGroups) != 0 {
		t.Fatalf("yeni hak: %+v (%v)", got, err)
	}
	if err := s.SetJITGrantCreatedGroups(ctx, id, []string{"gecici", "dba"}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.JITGrant(ctx, id)
	if len(got.CreatedGroups) != 2 || got.CreatedGroups[0] != "gecici" {
		t.Errorf("açılan gruplar geri okunmadı: %+v", got.CreatedGroups)
	}
	if err := s.SetJITGrantCreatedGroups(ctx, "yok", []string{"x"}); err == nil {
		t.Error("olmayan hak için hata yok")
	}

	off := aGrant(time.Hour)
	off.CleanupGroups = false
	id2, _ := s.CreateJITGrant(ctx, off)
	if got, _ := s.JITGrant(ctx, id2); got.CleanupGroups {
		t.Error("kapalı temizleme izni açık okundu")
	}
}
