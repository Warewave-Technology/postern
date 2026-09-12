package store

// Güvenlik anahtarlarının saklanması (göç 039).

import (
	"context"
	"errors"
	"math"
	"testing"
)

// keyUser, anahtar bağlanabilecek bir hesap açar.
func keyUser(t *testing.T, s *Store, name string) {
	t.Helper()
	if _, err := s.CreateUser(context.Background(), name, name+"@warewave.io", name); err != nil {
		t.Fatal(err)
	}
}

// aKey, saklanabilir bir kimlik bilgisi üretir.
func aKey(id, name string) WebAuthnCredential {
	return WebAuthnCredential{
		ID:        id,
		PublicKey: []byte("cose-public-key-" + id),
		AAGUID:    []byte("aaguid"),
		SignCount: 7,
		Name:      name,
	}
}

/*
 * ⚠️ AÇIK ANAHTAR GERİ OKUNABİLMELİ — İMZA DOĞRULAMANIN TEK GİRDİSİ O.
 *
 * Bayt bayt aynı dönmezse hiçbir imza doğrulanmaz ve anahtarını kaydeden
 * kişi bir daha giremez; arıza "anahtarınız kabul edilmedi" diye
 * görünür, yani kaydın değil doğrulayıcının suçlu sanıldığı bir yerde.
 */
func TestWebAuthnCredentialSurvivesTheRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	keyUser(t, s, "ayse")

	want := aKey("a2V5LWJpcg", "iş dizüstü")
	if err := s.AddWebAuthnCredential(ctx, "ayse", want); err != nil {
		t.Fatal(err)
	}

	got, err := s.WebAuthnCredentials(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("anahtar sayısı = %d, 1 bekleniyordu", len(got))
	}
	if string(got[0].PublicKey) != string(want.PublicKey) {
		t.Errorf("AÇIK ANAHTAR BOZULDU: %q, %q bekleniyordu",
			got[0].PublicKey, want.PublicKey)
	}
	if got[0].SignCount != want.SignCount {
		t.Errorf("sayaç = %d, %d bekleniyordu", got[0].SignCount, want.SignCount)
	}
	if got[0].Name != want.Name {
		t.Errorf("ad = %q, %q bekleniyordu", got[0].Name, want.Name)
	}
	// ⚠️ Hiç kullanılmamış anahtarın son kullanımı YOK, 1970 değil.
	if !got[0].LastUsedAt.IsZero() {
		t.Errorf("kullanılmamış anahtara zaman damgası kondu: %v", got[0].LastUsedAt)
	}
}

/*
 * ⚠️ AYNI ANAHTAR İKİ HESABA BAĞLANAMAZ.
 *
 * Bağlanabilseydi, bir imza iki kişiye işaret ederdi ve "bunu kim
 * yaptı" sorusunun cevabı kalmazdı — postern'in bütün denetim iddiası
 * o sorunun cevaplanabilmesine dayanıyor.
 */
func TestWebAuthnCredentialCannotBelongToTwoAccounts(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	keyUser(t, s, "ayse")
	keyUser(t, s, "veli")

	if err := s.AddWebAuthnCredential(ctx, "ayse", aKey("ortak", "anahtar")); err != nil {
		t.Fatal(err)
	}

	err := s.AddWebAuthnCredential(ctx, "veli", aKey("ortak", "anahtar"))
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("İKİNCİ HESABA BAĞLANDI: err = %v, ErrConflict bekleniyordu", err)
	}
}

/*
 * ⚠️ SAYAÇ GERİ GİTMİYOR.
 *
 * Klon sezgisinin tamamı "gelen sayı saklanandan büyük mü" sorusuna
 * dayanıyor. Küçük bir sayıyı yazsaydık, bir kez geri giden sayaç
 * saklanan değeri de düşürür ve sonraki klon denemeleri fark
 * edilmeden geçerdi.
 */
func TestWebAuthnSignCountNeverGoesBackwards(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	keyUser(t, s, "ayse")

	if err := s.AddWebAuthnCredential(ctx, "ayse", aKey("k1", "anahtar")); err != nil {
		t.Fatal(err)
	}

	if err := s.TouchWebAuthnCredential(ctx, "k1", 3); err != nil {
		t.Fatal(err)
	}

	got, err := s.WebAuthnCredentials(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if got[0].SignCount != 7 {
		t.Errorf("SAYAÇ GERİLEDİ: %d, 7 bekleniyordu", got[0].SignCount)
	}
	if got[0].LastUsedAt.IsZero() {
		t.Error("son kullanım yazılmadı")
	}

	if err := s.TouchWebAuthnCredential(ctx, "k1", 9); err != nil {
		t.Fatal(err)
	}
	got, _ = s.WebAuthnCredentials(ctx, "ayse")
	if got[0].SignCount != 9 {
		t.Errorf("artan sayaç yazılmadı: %d, 9 bekleniyordu", got[0].SignCount)
	}
}

/*
 * ⚠️ SON ANAHTAR SİLİNİNCE KOD YENİDEN AÇILIYOR.
 *
 * Açılmasaydı hesap, kabul ettiği hiçbir ikinci faktörü olmayan bir
 * duruma düşerdi: kod kapalı, anahtar yok. Bu projede kurtarma kodu
 * bilerek yok, yani oradan çıkışın tek yolu yönetici olurdu — ve
 * kullanıcı bunu kendi eliyle, tek tıkla yapardı.
 */
func TestRemovingTheLastKeyLetsCodesBackIn(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	keyUser(t, s, "ayse")

	if err := s.AddWebAuthnCredential(ctx, "ayse", aKey("k1", "bir")); err != nil {
		t.Fatal(err)
	}
	if err := s.AddWebAuthnCredential(ctx, "ayse", aKey("k2", "iki")); err != nil {
		t.Fatal(err)
	}
	if err := s.SetWebAuthnOnly(ctx, "ayse", true); err != nil {
		t.Fatal(err)
	}

	// İlk anahtar gidince kilit DURUYOR: hâlâ bir anahtar var.
	if err := s.DeleteWebAuthnCredential(ctx, "ayse", "k1"); err != nil {
		t.Fatal(err)
	}
	if only, _ := s.WebAuthnOnly(ctx, "ayse"); !only {
		t.Error("anahtar dururken kilit açıldı")
	}

	// Son anahtar gidince kilit KALKIYOR.
	if err := s.DeleteWebAuthnCredential(ctx, "ayse", "k2"); err != nil {
		t.Fatal(err)
	}
	only, err := s.WebAuthnOnly(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if only {
		t.Error("HESAP KİLİTLENDİ: anahtar yok ve kod da kapalı")
	}
}

/*
 * ⚠️ ANAHTARSIZ "YALNIZCA ANAHTAR" AÇILAMIYOR — aynı kilitlenme, öbür
 * kapıdan. Önce kilidi açıp sonra anahtar kaydetmeyi deneyen bir
 * kullanıcı, arada kendini dışarıda bırakırdı.
 */
func TestWebAuthnOnlyNeedsAKeyFirst(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	keyUser(t, s, "ayse")

	if err := s.SetWebAuthnOnly(ctx, "ayse", true); !errors.Is(err, ErrConflict) {
		t.Fatalf("anahtarsız kilitlendi: err = %v, ErrConflict bekleniyordu", err)
	}
}

/*
 * ⚠️ YÖNETİCİ SIFIRLAMASI TEK İŞLEMDE. İki ayrı adım olsaydı, aradaki
 * bir hata hesabı tam da kurtarmaya çalıştığımız yerde bırakırdı:
 * anahtarlar silinmiş, kod hâlâ kapalı.
 */
func TestResetWebAuthnOpensTheAccountAgain(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	keyUser(t, s, "ayse")

	if err := s.AddWebAuthnCredential(ctx, "ayse", aKey("k1", "bir")); err != nil {
		t.Fatal(err)
	}
	if err := s.SetWebAuthnOnly(ctx, "ayse", true); err != nil {
		t.Fatal(err)
	}

	n, err := s.ResetWebAuthn(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("silinen anahtar = %d, 1 bekleniyordu", n)
	}

	creds, _ := s.WebAuthnCredentials(ctx, "ayse")
	if len(creds) != 0 {
		t.Errorf("anahtar kaldı: %d", len(creds))
	}
	if only, _ := s.WebAuthnOnly(ctx, "ayse"); only {
		t.Error("SIFIRLAMADAN SONRA KOD HÂLÂ KAPALI: hesap kurtarılamadı")
	}
}

/*
 * ⚠️ BOZUK BİR SAYAÇ SESSİZCE SARMAMALI — VE YÖNÜ ÖNEMLİ.
 *
 * Sütun BIGINT, sayaç uint32. Elle yazılmış ya da bozulmuş bir satır
 * sınırı aşarsa dönüştürme sarar ve saklanan sayı KÜÇÜLÜR; klon
 * sezgisi tam da kurcalanmış bir satırda körelirdi. Sınıra sabitlemek
 * güvenli yön: büyük bir sayı hiçbir imzayı kabul ettirmiyor.
 */
func TestCorruptSignCountClampsInsteadOfWrapping(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	keyUser(t, s, "ayse")

	if err := s.AddWebAuthnCredential(ctx, "ayse", aKey("k1", "anahtar")); err != nil {
		t.Fatal(err)
	}

	// uint32 sınırının üstünde bir değer: 2^32 + 5.
	if _, err := s.db.ExecContext(ctx,
		`UPDATE webauthn_credentials SET sign_count = $1 WHERE id = 'k1';`,
		int64(1)<<32+5); err != nil {
		t.Fatal(err)
	}

	got, err := s.WebAuthnCredentials(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if got[0].SignCount != math.MaxUint32 {
		t.Errorf("SAYAÇ SARDI: %d okundu, %d (sınır) bekleniyordu — "+
			"küçülen bir sayaç klon sezgisini köreltir",
			got[0].SignCount, uint32(math.MaxUint32))
	}
}
