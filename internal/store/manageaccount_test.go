package store

/*
 * Yönetim hesabının adları hiçbir yazma yolundan bir kişiye verilemez.
 *
 * ⚠️ NEDEN HER YOL AYRI SINANIYOR. Bu paketin kendi dersi: doğrulayıcı
 * vardı, çağıran yoktu (osuser_test.go). users.os_user'a dört farklı yol
 * yazıyor ve ikisi (onay, dizinden açılış) refuseBadOSUser'ı hiç
 * çağırmıyor. Tek bir yolu sınamak, kapanmamış öbür yolu yeşil gösterirdi.
 *
 * Hesap "postern", hedefte parolasız root sudo tutuyor ve yalnızca
 * "postern-manage" principal'ıyla açılıyor (deploy/ansible/roles/postern_target).
 * İkisinin şekli de geçerli; yalnızca desene bakan her kontrol onları kabul
 * ediyordu.
 */

import (
	"context"
	"errors"
	"testing"
)

var managementNames = []string{"postern", "postern-manage"}

func TestRefuseBadOSUserRefusesTheManagementAccount(t *testing.T) {
	for _, name := range managementNames {
		err := refuseBadOSUser("test", name)
		if err == nil {
			t.Errorf("%q kabul edildi: yönetim hesabı bir kişiye verilebiliyor", name)
			continue
		}
		// httpapi ErrInvalid'i 400'e ve mesajı gövdeye eşliyor; yöneticinin
		// neyi düzelteceğini görmesi gerekiyor.
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%q için hata ErrInvalid değil: %v", name, err)
		}
		if !contains(err.Error(), name) {
			t.Errorf("%q için mesaj değeri içermiyor: %v", name, err)
		}
	}

	// Karşı örnek: benzeyen ama farklı adlar etkilenmemeli.
	for _, name := range []string{"deploy", "posternx", "postern_ops", "manage"} {
		if err := refuseBadOSUser("test", name); err != nil {
			t.Errorf("%q reddedildi, kabul bekleniyordu: %v", name, err)
		}
	}
}

func TestCreateAndModifyRefuseTheManagementAccount(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	for _, name := range managementNames {
		if _, err := s.CreateUser(ctx, "kisi-"+name, "", name); !errors.Is(err, ErrInvalid) {
			t.Errorf("CreateUser os_user=%q: err = %v, ErrInvalid bekleniyordu", name, err)
		}
	}

	if _, err := s.CreateUser(ctx, "ayse", "", "ayse"); err != nil {
		t.Fatal(err)
	}
	for _, name := range managementNames {
		if err := s.SetUserOSUser(ctx, "ayse", name); !errors.Is(err, ErrInvalid) {
			t.Errorf("SetUserOSUser %q: err = %v, ErrInvalid bekleniyordu", name, err)
		}
	}
	u, err := s.User(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if u.OSUser != "ayse" {
		t.Errorf("reddedilen değişiklik yine de yazıldı: os_user = %q", u.OSUser)
	}
}

/*
 * ⚠️ ONAY YOLU os_user'I HİÇ DOĞRULAMIYORDU. Hesap ham SQL ile açılıyor;
 * yöneticinin onay ekranına yazdığı değer ne şekle ne yönetim adına
 * bakılmadan tabloya giriyordu.
 */
func TestApprovePendingRefusesAnOSUserTheOtherPathsRefuse(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.RecordPending(ctx, PendingUser{
		Subject: "11111111-2222-3333-4444-555555555555", Source: "dir",
		Username: "mehmet", Email: "mehmet@warewave.io",
	}); err != nil {
		t.Fatal(err)
	}
	all, _ := s.ListPending(ctx)
	id := all[0].ID

	for _, osUser := range append([]string{"Mehmet Bey", "mehmet@corp.com"}, managementNames...) {
		if _, err := s.ApprovePending(ctx, id, osUser, "ops"); !errors.Is(err, ErrInvalid) {
			t.Errorf("onay os_user=%q: err = %v, ErrInvalid bekleniyordu", osUser, err)
		}
	}

	// Reddedilen onay hesabı açmamalı ve kişiyi kuyruktan düşürmemeli:
	// yönetici doğru adla yeniden onaylayabilmeli.
	if _, err := s.User(ctx, "mehmet"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reddedilen onay hesabı yine de açtı: %v", err)
	}
	if left, _ := s.ListPending(ctx); len(left) != 1 {
		t.Fatalf("reddedilen onay kişiyi kuyruktan düşürdü: %d satır", len(left))
	}

	if _, err := s.ApprovePending(ctx, id, "mehmet", "ops"); err != nil {
		t.Fatalf("geçerli adla onay: %v", err)
	}
}

/*
 * ⚠️ OTOMATİK YOLLAR: kimsenin karar vermediği açılış. preferred_username
 * birçok IdP'de kullanıcının kendi düzenleyebildiği bir alan; dizinde uid'si
 * "postern" olan bir kayıt da aynı şekilde gelir. Sonuç ErrAccessDenied:
 * giriş akışı bunu "erişim yok" diye göstermeli, "geçersiz istek" diye değil.
 */
func TestAutomaticProvisioningRefusesTheManagementAccount(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedMappingFixtures(t, s)
	if err := s.AddGroupMapping(ctx, "sysadmins", "ops", "yigit"); err != nil {
		t.Fatal(err)
	}

	for _, name := range managementNames {
		t.Run("oidc "+name, func(t *testing.T) {
			_, err := s.ProvisionUser(ctx, ProvisionRequest{
				AutoCreate: true, Username: name, GroupsResolved: true,
				Groups: []string{"sysadmins"},
				Issuer: "https://idp.local", Subject: "sub-" + name,
			})
			if !errors.Is(err, ErrAccessDenied) {
				t.Errorf("err = %v, ErrAccessDenied bekleniyordu", err)
			}
			if _, uerr := s.User(ctx, name); !errors.Is(uerr, ErrNotFound) {
				t.Error("hesap yine de açıldı")
			}
		})

		t.Run("dizin "+name, func(t *testing.T) {
			_, err := s.CreateFromDirectory(ctx, DirectoryAccount{
				Username: name, Subject: "dir-" + name, Groups: []string{"sysadmins"},
			})
			if !errors.Is(err, ErrAccessDenied) {
				t.Errorf("err = %v, ErrAccessDenied bekleniyordu", err)
			}
			if _, uerr := s.User(ctx, name); !errors.Is(uerr, ErrNotFound) {
				t.Error("hesap yine de açıldı")
			}
		})
	}

	// Karşı örnek: aynı eşlemeyle sıradan bir ad açılmalı. Aksi hâlde
	// yukarıdaki retler eşleme eksikliğinden de gelebilirdi.
	if _, err := s.CreateFromDirectory(ctx, DirectoryAccount{
		Username: "deploy", Subject: "dir-deploy", Groups: []string{"sysadmins"},
	}); err != nil {
		t.Fatalf("sıradan dizin hesabı açılmadı — retler yanlış sebepten geliyor olabilir: %v", err)
	}
}
