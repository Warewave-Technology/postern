package store

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// evilName, hedefin sshd günlüğüne kendi satırını yazdıran ad — v1.1.0'da
// imzalama kapısının reddettiği, yazma yollarının kabul ettiği ad.
const evilName = "evil\nAccepted publickey for root from 6.6.6.6"

/*
 * ⚠️ KAPI YAZAN YERDE, ÇAĞIRANDA DEĞİL — ve bu test onu yazan HER
 * fonksiyonda ayrı ayrı ölçüyor.
 *
 * ÖLÇÜLEN ARIZA: aynı kural bir kez yalnızca panel ve CLI çağrılarına
 * konmuştu; SSH giriş yolu (sshd/auth.go -> ProvisionUser,
 * RecordPending) ve `admin bootstrap` açıkta kalmıştı. Kural yazma
 * fonksiyonunda olduğunda çağıranın onu hatırlaması gerekmiyor.
 *
 * Her ret iddiasının yanında KABUL karşı örneği var: ikisi birlikte,
 * reddin adın kendisinden geldiğini ve yolun genel olarak çalıştığını
 * gösteriyor.
 */
func TestEveryUsernameWritePathRefusesControlCharacters(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedMappingFixtures(t, s)
	if err := s.AddGroupMapping(ctx, "sysadmins", "ops", "yigit"); err != nil {
		t.Fatal(err)
	}

	if _, err := s.CreateUser(ctx, evilName, "", "deploy"); !errors.Is(err, ErrInvalid) {
		t.Errorf("CreateUser: err = %v, ErrInvalid bekleniyordu", err)
	}
	if _, err := s.CreateUser(ctx, "temiz", "", "deploy"); err != nil {
		t.Fatalf("temiz ad reddedildi — ret yanlış sebepten geliyor olabilir: %v", err)
	}

	if err := s.SetUserOSUser(ctx, evilName, "deploy"); !errors.Is(err, ErrInvalid) {
		t.Errorf("SetUserOSUser: err = %v, ErrInvalid bekleniyordu", err)
	}

	if _, err := s.RecordPending(ctx, PendingUser{
		Subject: "oidc-evil", Source: "oidc", Username: evilName,
	}); !errors.Is(err, ErrInvalid) {
		t.Errorf("RecordPending: err = %v, ErrInvalid bekleniyordu", err)
	}
	if _, err := s.RecordPending(ctx, PendingUser{
		Subject: "oidc-temiz", Source: "oidc", Username: "temiz2",
	}); err != nil {
		t.Fatalf("temiz kuyruk satırı reddedildi: %v", err)
	}

	if _, err := s.CreateFromDirectory(ctx, DirectoryAccount{
		Username: evilName, Subject: "dir-evil", Groups: []string{"sysadmins"},
	}); !errors.Is(err, ErrInvalid) {
		t.Errorf("CreateFromDirectory: err = %v, ErrInvalid bekleniyordu", err)
	}

	/*
	 * Onay yolu: kapıdan ÖNCE yazılmış bir kuyruk satırını taklit etmek
	 * için satır doğrudan tabloya konuyor. Onay onu users'a taşımamalı.
	 */
	id, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO pending_users (id, subject, source, username, email, seen_groups, state, first_seen, last_seen)
		VALUES ($1, 'oidc-eski', 'oidc', $2, '', '', 'waiting', 1, 1);`, id, evilName); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApprovePending(ctx, id, "deploy", "yigit"); !errors.Is(err, ErrInvalid) {
		t.Errorf("ApprovePending: err = %v, ErrInvalid bekleniyordu", err)
	}

	users, err := s.Users(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if i := strings.IndexFunc(u.Name, func(r rune) bool { return r < 0x20 || r == 0x7f }); i >= 0 {
			t.Errorf("KONTROL KARAKTERLİ HESAP YAZILDI: %q", u.Name)
		}
	}
}

/*
 * ⚠️ YAZMA KURALI İMZALAMA KURALINDAN GEVŞEK OLAMAZ. Gevşek olsaydı
 * açılabilen ama sertifikası hiç kesilemeyen bir hesap doğardı — bu depo
 * o arızayı os_user tarafında bir kez ölçtü (refuseBadOSUser'ın yorumu).
 * C1 aralığı (U+0080-U+009F) imzalama tarafındaki bayt taramasının
 * kaçırdığı yer; kural rune üzerinden olduğu için burada yakalanıyor.
 *
 * Kabul karşı örneği ŞEKLİN DAYATILMADIĞINI gösteriyor: kullanıcı adı
 * kimlik sağlayıcısından geliyor ve e-posta ya da UPN olabiliyor.
 */
func TestWriteGateIsAtLeastAsStrictAsSigning(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	for _, name := range []string{"bel\a", "del\x7f", "c1\u0085", "nul\x00", "tab\there"} {
		if _, err := s.CreateUser(ctx, name, "", "deploy"); !errors.Is(err, ErrInvalid) {
			t.Errorf("CreateUser(%q): err = %v, ErrInvalid bekleniyordu", name, err)
		}
	}
	if _, err := s.CreateUser(ctx, "yigit.basalma@corp.com", "", "deploy"); err != nil {
		t.Errorf("e-posta biçimli ad reddedildi — şekil dayatılmamalı: %v", err)
	}
}
