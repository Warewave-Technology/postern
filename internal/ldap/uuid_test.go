package ldap

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

/*
 * ⚠️ objectGUID BAYT SIRASI: en kolay yanlış yapılan ve en geç fark
 * edilen yer.
 *
 * Yanlış sıra 36 karakterlik, geçerli GÖRÜNEN bir değer üretiyor —
 * bozukluğu ancak biri AD araçlarıyla karşılaştırdığında ortaya çıkıyor.
 * O noktada bütün bağlar yazılmış oluyor ve sırayı düzeltmek hepsini tek
 * seferde geçersiz kılıyor.
 *
 * Vektör, Windows GUID yapısının tanımından türetildi: ilk üç alan
 * little-endian, son sekiz bayt olduğu gibi.
 */
func TestFormatObjectGUIDByteOrder(t *testing.T) {
	// Tel üzerindeki 16 bayt.
	raw, err := hex.DecodeString("d05e5a3a5d9a3e4a924a8f6c0c5e9b8a")
	if err != nil {
		t.Fatal(err)
	}

	got, err := formatObjectGUID(raw)
	if err != nil {
		t.Fatal(err)
	}
	const want = "3a5a5ed0-9a5d-4a3e-924a-8f6c0c5e9b8a"
	if got != want {
		t.Fatalf("formatObjectGUID = %s, %s bekleniyordu", got, want)
	}

	// ⚠️ Ve DÜZ hex'e eşit OLMAMALI: bu, "baytları soldan sağa yazdım"
	// hatasının imzası ve tek başına en olası hata.
	straight := "d05e5a3a-5d9a-3e4a-924a-8f6c0c5e9b8a"
	if got == straight {
		t.Fatal("bayt sırası uygulanmamış: düz hex ile aynı çıktı")
	}
}

// Her alanın AYRI AYRI çevrildiğini gösteren ikinci vektör: tek bir
// alanın sırası unutulsa da yakalansın.
func TestFormatObjectGUIDFieldsAreIndependent(t *testing.T) {
	raw, err := hex.DecodeString("01020304" + "0506" + "0708" + "090a0b0c0d0e0f10")
	if err != nil {
		t.Fatal(err)
	}
	got, err := formatObjectGUID(raw)
	if err != nil {
		t.Fatal(err)
	}
	const want = "04030201-0605-0807-090a-0b0c0d0e0f10"
	if got != want {
		t.Fatalf("formatObjectGUID = %s, %s bekleniyordu", got, want)
	}
}

// 16 bayt olmayan değer REDDEDİLİR: kısa ya da uzun bir değerden GUID
// uydurmak, kimlik alanına çöp yazmak olurdu.
func TestFormatObjectGUIDRejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 15, 17, 32} {
		if _, err := formatObjectGUID(make([]byte, n)); !errors.Is(err, ErrNotAUUID) {
			t.Fatalf("%d baytlık değer kabul edildi", n)
		}
	}
}

/*
 * ⚠️ NORMALİZASYON: aynı kişi için iki ayrı dize saklanamaz.
 *
 * Saklanabilseydi, büyük harfli dönen bir dizinde kullanıcı ikinci
 * girişinde "bu kimlik bağlı değil" durumuna düşer ve adı eşleşen hesabı
 * devralma yoluna girerdi — yani korumanın kendisi devre dışı kalırdı.
 */
func TestNormalizeEntryUUID(t *testing.T) {
	// Gerçek OpenLDAP'tan ölçülen biçim (dc=warewave,dc=io).
	const measured = "f74a3e90-373a-1041-92eb-dbd441920715"

	for _, in := range []string{
		measured,
		strings.ToUpper(measured),
		"  " + measured + "  ",
		"{" + measured + "}",
	} {
		got, err := normalizeEntryUUID(in)
		if err != nil {
			t.Fatalf("normalizeEntryUUID(%q): %v", in, err)
		}
		if got != measured {
			t.Fatalf("normalizeEntryUUID(%q) = %q, %q bekleniyordu", in, got, measured)
		}
	}
}

// Biçimi tutmayan değer REDDEDİLİR: dizinin döndürdüğü her şeyi kimlik
// saymak, "kimlik" alanına rastgele bir dize yazdırmak olurdu.
func TestNormalizeEntryUUIDRejectsGarbage(t *testing.T) {
	bad := []string{
		"", "not-a-uuid",
		"f74a3e90-373a-1041-92eb-dbd44192071",   // kısa
		"f74a3e90-373a-1041-92eb-dbd4419207155", // uzun
		"f74a3e90x373a-1041-92eb-dbd441920715",  // ayraç yanlış
		"g74a3e90-373a-1041-92eb-dbd441920715",  // hex değil
		"f74a3e90 373a 1041 92eb dbd441920715",  // ayraç yok
	}
	for _, in := range bad {
		if got, err := normalizeEntryUUID(in); !errors.Is(err, ErrNotAUUID) {
			t.Fatalf("normalizeEntryUUID(%q) = %q, %v — reddedilmeliydi", in, got, err)
		}
	}
}

/*
 * decodeIdentity BİÇİME göre seçiyor, bir ayara göre değil.
 *
 * "Hangi öznitelik" diye bir ayar, operatörün yanlış doldurabileceği bir
 * alan daha olurdu — ve yanlış doldurulduğunda cevap "bu dizinde kararlı
 * kimlik yok" olurdu: sessiz ve yanlış.
 */
func TestDecodeIdentityDispatchesByShape(t *testing.T) {
	// 16 ham bayt: AD objectGUID.
	guid, err := hex.DecodeString("d05e5a3a5d9a3e4a924a8f6c0c5e9b8a")
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeIdentity(guid)
	if err != nil || got != "3a5a5ed0-9a5d-4a3e-924a-8f6c0c5e9b8a" {
		t.Fatalf("16 bayt → %q, %v", got, err)
	}

	// 36 karakterlik metin: RFC 4530 entryUUID (gerçek OpenLDAP'tan ölçüldü).
	got, err = decodeIdentity([]byte("F74A3E90-373A-1041-92EB-DBD441920715"))
	if err != nil || got != "f74a3e90-373a-1041-92eb-dbd441920715" {
		t.Fatalf("36 karakter → %q, %v", got, err)
	}

	// ⚠️ BOŞ DEĞER HATA DEĞİL, CEVABIN KENDİSİ: bu dizin (ya da bu
	// servis hesabı) kararlı kimlik vermiyor. Hata saymak, kimliği
	// olmayan dizinlerde girişi düşürürdü.
	got, err = decodeIdentity(nil)
	if err != nil || got != "" {
		t.Fatalf("boş değer → %q, %v; sessiz yokluk bekleniyordu", got, err)
	}

	// ⚠️ Anlaşılmayan değer REDDEDİLİR. "Belki budur" diye yazmak,
	// kimliğin kendisini anlamsız kılardı.
	for _, bad := range [][]byte{
		[]byte("kisa"),
		make([]byte, 15),
		make([]byte, 17),
		[]byte("zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"),
	} {
		if v, err := decodeIdentity(bad); !errors.Is(err, ErrNotAUUID) {
			t.Fatalf("decodeIdentity(%q) = %q, %v — reddedilmeliydi", bad, v, err)
		}
	}
}

/*
 * ⚠️ FİLTRE, KANONİK METİNDEN TEL SIRASINA GERİ ÇEVİRMELİ.
 *
 * objectGUID filtrede ham bayt olarak yazılıyor ve baytlar tel
 * sırasında olmak zorunda — yani formatObjectGUID'in TERSİ. Ters
 * çevirme atlanırsa filtre geçerli görünür ama hiçbir şey bulmaz, ve
 * sonuç "bu kullanıcı dizinde yok" olur: sessiz, yanlış, ve erişim
 * iptaline dönüşen bir cevap.
 *
 * Vektör, TestFormatObjectGUIDByteOrder'ın tam tersi yönü.
 */
func TestSubjectFilterRoundTripsToWireOrder(t *testing.T) {
	got, err := subjectFilter("3a5a5ed0-9a5d-4a3e-924a-8f6c0c5e9b8a")
	if err != nil {
		t.Fatal(err)
	}
	const want = `(|(entryUUID=3a5a5ed0-9a5d-4a3e-924a-8f6c0c5e9b8a)` +
		`(objectGUID=\d0\5e\5a\3a\5d\9a\3e\4a\92\4a\8f\6c\0c\5e\9b\8a))`
	if got != want {
		t.Fatalf("filtre =\n  %s\nbeklenen =\n  %s", got, want)
	}
}

// Geçersiz kimlik filtre üretmemeli: dizine anlamsız bir sorgu atmak,
// "bulunamadı" cevabını yanlış sebeple üretirdi.
func TestSubjectFilterRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "kim-bu", "3a5a5ed0-9a5d-4a3e-924a"} {
		if f, err := subjectFilter(bad); !errors.Is(err, ErrNotAUUID) {
			t.Fatalf("subjectFilter(%q) = %q, %v", bad, f, err)
		}
	}
}
