package store

import (
	"errors"
	"testing"
)

func uidEnv(t *testing.T, names ...string) *Store {
	t.Helper()
	s := newTestStore(t)
	for _, n := range names {
		if _, err := s.CreateUser(t.Context(), n, "", n); err != nil {
			t.Fatal(err)
		}
	}

	return s
}

/*
 * ⚠️ AYNI KİŞİ HER ÇAĞRIDA AYNI NUMARAYI ALIR. Bu, özelliğin var olma
 * sebebi: numara makineden makineye değişirse paylaşılan bir dosya
 * sisteminde ya da yedekten dönen bir dizinde dosyanın sahibi yanlış
 * görünür.
 */
func TestTheSamePersonKeepsTheSameNumber(t *testing.T) {
	s := uidEnv(t, "ayse")
	ctx := t.Context()

	first, err := s.AllocateUIDFromPool(ctx, "ayse", 60000, 60010)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.AllocateUIDFromPool(ctx, "ayse", 60000, 60010)
	if err != nil {
		t.Fatal(err)
	}
	if first.UID != second.UID {
		t.Fatalf("ikinci çağrı %d verdi, ilki %d vermişti", second.UID, first.UID)
	}
	if first.UID < 60000 || first.UID > 60010 {
		t.Fatalf("numara havuz dışında: %d", first.UID)
	}
	if first.Source != UIDFromPool {
		t.Fatalf("kaynak = %q, %q bekleniyordu", first.Source, UIDFromPool)
	}
}

// İki kişi aynı numarayı paylaşamaz — havuz sırayla iniyor.
func TestTwoPeopleNeverShareANumber(t *testing.T) {
	s := uidEnv(t, "ayse", "veli")
	ctx := t.Context()

	a, err := s.AllocateUIDFromPool(ctx, "ayse", 60000, 60010)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.AllocateUIDFromPool(ctx, "veli", 60000, 60010)
	if err != nil {
		t.Fatal(err)
	}
	if a.UID == v.UID {
		t.Fatalf("iki kişi de %d aldı", a.UID)
	}
}

/*
 * ⚠️ DİZİNİN NUMARASI HAVUZUNKİNİ EZMİYOR — VE TERSİ DE DOĞRU.
 *
 * Bir kişinin numarasını sonradan değiştirmek, o kişinin filodaki bütün
 * dosyalarının sahipliğini bir anda koparmak demek: dosyalar eski
 * numarayla duruyor, hesap yeni numarayla giriyor. Dizin bir gün
 * uidNumber yayınlamaya başladığında olacak şey tam olarak bu.
 */
func TestAnExistingNumberIsNeverReplaced(t *testing.T) {
	s := uidEnv(t, "ayse")
	ctx := t.Context()

	pooled, err := s.AllocateUIDFromPool(ctx, "ayse", 60000, 60010)
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.ReserveUID(ctx, "ayse", 4242, UIDFromDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if got.UID != pooled.UID {
		t.Fatalf("numara %d'den %d'ye kaydı", pooled.UID, got.UID)
	}
	if got.Source != UIDFromPool {
		t.Fatalf("kaynak %q'ya kaydı", got.Source)
	}
}

/*
 * Dizin önce konuşursa havuz hiç devreye girmiyor: kişi dizinin
 * numarasını taşıyor.
 */
func TestTheDirectorysNumberWinsWhenItComesFirst(t *testing.T) {
	s := uidEnv(t, "ayse")
	ctx := t.Context()

	if _, err := s.ReserveUID(t.Context(), "ayse", 4242, UIDFromDirectory); err != nil {
		t.Fatal(err)
	}
	got, err := s.AllocateUIDFromPool(ctx, "ayse", 60000, 60010)
	if err != nil {
		t.Fatal(err)
	}
	if got.UID != 4242 || got.Source != UIDFromDirectory {
		t.Fatalf("havuz dizinin numarasını ezdi: %+v", got)
	}
}

/*
 * ⚠️ BİR NUMARAYI İKİ KİŞİYE VERMEK ENGELLENİYOR. Dizin iki kişiye aynı
 * uidNumber'ı verdiyse (olur: elle düzenlenmiş şema) ikincisini kabul
 * etmek, iki kişiyi makinede aynı kimlik yapardı — dosya izinleri o
 * andan itibaren ikisini ayırt edemez.
 */
func TestANumberCannotBeGivenToTwoPeople(t *testing.T) {
	s := uidEnv(t, "ayse", "veli")
	ctx := t.Context()

	if _, err := s.ReserveUID(ctx, "ayse", 4242, UIDFromDirectory); err != nil {
		t.Fatal(err)
	}
	_, err := s.ReserveUID(ctx, "veli", 4242, UIDFromDirectory)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, ErrConflict bekleniyordu", err)
	}
}

// Havuz dolduğunda sessizce aralık dışına taşmıyor.
func TestAFullPoolIsAnErrorNotAnOverflow(t *testing.T) {
	s := uidEnv(t, "ayse", "veli")
	ctx := t.Context()

	if _, err := s.AllocateUIDFromPool(ctx, "ayse", 60000, 60000); err != nil {
		t.Fatal(err)
	}
	got, err := s.AllocateUIDFromPool(ctx, "veli", 60000, 60000)
	if err == nil {
		t.Fatalf("havuz dolu ama %d verildi", got.UID)
	}
}
