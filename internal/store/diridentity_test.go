package store

import (
	"context"
	"errors"
	"testing"
)

/*
 * ⚠️ BİR DİZİN KİMLİĞİ, EN FAZLA BİR HESAP.
 *
 * Kısıt olmasaydı iki hesap aynı kimliği iddia edebilir ve hangisine
 * girildiği veritabanının sıralamasına kalırdı — 011'in OIDC için
 * kapattığı belirsizliğin aynısı.
 */
func TestDirIdentityBindsToOneAccount(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	for _, n := range []string{"ayse", "mehmet"} {
		if _, err := s.CreateUser(ctx, n, n+"@warewave.io", n); err != nil {
			t.Fatal(err)
		}
	}
	const uuid = "f74a3e90-373a-1041-92eb-dbd441920715"

	if err := s.BindDirIdentity(ctx, "ayse", uuid); err != nil {
		t.Fatal(err)
	}
	u, err := s.UserByDirSubject(ctx, uuid)
	if err != nil || u.Name != "ayse" {
		t.Fatalf("UserByDirSubject = %q, %v", u.Name, err)
	}

	// Aynı kimliği ikinci bir hesap alamaz.
	if err := s.BindDirIdentity(ctx, "mehmet", uuid); err == nil {
		t.Fatal("aynı dizin kimliği iki hesaba bağlandı")
	}
	// Ve ilk hesap DOKUNULMAMIŞ kaldı.
	if u, err := s.UserByDirSubject(ctx, uuid); err != nil || u.Name != "ayse" {
		t.Fatalf("çakışan deneme sonrası = %q, %v", u.Name, err)
	}
}

/*
 * ⚠️ VAR OLAN BİR BAĞ SESSİZCE DEĞİŞTİRİLEMEZ.
 *
 * Değiştirilebilseydi, dizinde bir kayıt silinip yeniden açıldığında
 * (yeni kimlik) eski hesap yeni kişiye geçerdi — tam olarak önlenmek
 * istenen devralma.
 */
func TestDirIdentityCannotBeSilentlyRebound(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if _, err := s.CreateUser(ctx, "ayse", "ayse@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}
	if err := s.BindDirIdentity(ctx, "ayse", "aaaa-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.BindDirIdentity(ctx, "ayse", "bbbb-2"); !errors.Is(err, ErrConflict) {
		t.Fatalf("bağlı hesap yeniden bağlandı: %v", err)
	}
	if got, _ := s.DirSubjectOf(ctx, "ayse"); got != "aaaa-1" {
		t.Fatalf("bağ değişti: %q", got)
	}

	// Kurtarma yolu VAR: dizinde silinip yeniden açılan kişi yeni bir
	// kimlik alır ve eski bağ onu kendi hesabından kilitler.
	if err := s.UnbindDirIdentity(ctx, "ayse"); err != nil {
		t.Fatal(err)
	}
	if err := s.BindDirIdentity(ctx, "ayse", "bbbb-2"); err != nil {
		t.Fatalf("bağ koparıldıktan sonra yeniden bağlanamadı: %v", err)
	}
}

/*
 * ⚠️ freshen'ın DOĞRU koşulu: "dizine bağlı mı", `sso_only` değil.
 *
 * Ölçüldü: yetkisi dizinden gelen bir yönetici (admin_via='group') demo
 * veritabanında sso_only=false ile duruyordu — yani dizine karşı hiç
 * yeniden sorulmuyordu ve dizinde kapatılsa bile anahtarıyla girerdi.
 */
func TestHasDirectoryIdentityIsIndependentOfSSOOnly(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if _, err := s.CreateUser(ctx, "ayse", "ayse@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}

	if bound, err := s.HasDirectoryIdentity(ctx, "ayse"); err != nil || bound {
		t.Fatalf("bağlanmamış hesap bağlı göründü: %v %v", bound, err)
	}
	if err := s.BindDirIdentity(ctx, "ayse", "f74a3e90-373a-1041-92eb-dbd441920715"); err != nil {
		t.Fatal(err)
	}
	// sso_only'ye HİÇ dokunmadık.
	if bound, err := s.HasDirectoryIdentity(ctx, "ayse"); err != nil || !bound {
		t.Fatalf("bağlı hesap bağsız göründü: %v %v", bound, err)
	}
}

// Boş kimlik hiçbir şeyle eşleşmemeli: aksi hâlde kimlik vermeyen bir
// dizinde HERKES tek bir "boş" kimliğe düşerdi.
func TestEmptyDirSubjectMatchesNothing(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if _, err := s.CreateUser(ctx, "ayse", "ayse@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UserByDirSubject(ctx, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("boş kimlik bir hesap buldu: %v", err)
	}
	if err := s.BindDirIdentity(ctx, "ayse", ""); err == nil {
		t.Fatal("boş kimlik bağlandı")
	}
}
