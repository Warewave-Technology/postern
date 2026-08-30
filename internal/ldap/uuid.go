package ldap

// Dizin kimliğinin KARARLI anahtarı: entryUUID / objectGUID.
//
// ⚠️ Bu dosyanın tamamı, "aynı kişi mi" sorusunun cevabının kullanıcı
// ADINA değil bu değere bağlanması içindir. 011 göçünün OIDC için
// kapattığı açığın dizin karşılığı: adı devralan kişi hesabı devralmasın.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ErrNotAUUID: değer, kararlı bir kimlik gibi görünmüyor.
var ErrNotAUUID = errors.New("ldap: value is not a directory UUID")

/*
 * normalizeEntryUUID, RFC 4530 entryUUID metnini tek biçime indirir.
 *
 * ⚠️ NORMALİZASYON ŞART. Aynı kişi için büyük harfli ve küçük harfli iki
 * ayrı dize saklanırsa, ikisi ayrı kimlik sayılır: kullanıcı ikinci kez
 * girdiğinde "bu kimlik bağlı değil" denir ve adı eşleşen hesabı
 * devralmaya çalışılır — tam olarak kaçınılan yol.
 *
 * Biçim de DOĞRULANIYOR: dizin ne döndürürse döndürsün kabul etmek,
 * "kimlik" alanına rastgele bir dize yazdırmak demekti.
 */
func normalizeEntryUUID(v string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(v))
	s = strings.TrimPrefix(strings.TrimSuffix(s, "}"), "{")

	if len(s) != 36 {
		return "", fmt.Errorf("%w: %d characters", ErrNotAUUID, len(s))
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return "", fmt.Errorf("%w: separator at %d", ErrNotAUUID, i)
			}
		default:
			if !isHexDigit(r) {
				return "", fmt.Errorf("%w: non-hex at %d", ErrNotAUUID, i)
			}
		}
	}
	return s, nil
}

func isHexDigit(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')
}

/*
 * formatObjectGUID, Active Directory'nin 16 baytlık objectGUID'ini
 * kanonik metne çevirir.
 *
 * ⚠️ BAYT SIRASI KARIŞIK VE BU EN KOLAY YANLIŞ YAPILAN YER.
 *
 * objectGUID, Windows'un GUID yapısının ham hâli:
 *
 *	Data1 uint32  — 4 bayt, LITTLE-ENDIAN
 *	Data2 uint16  — 2 bayt, LITTLE-ENDIAN
 *	Data3 uint16  — 2 bayt, LITTLE-ENDIAN
 *	Data4 [8]byte — OLDUĞU GİBİ
 *
 * Yani baytları soldan sağa hex'e çevirmek YANLIŞ bir GUID üretir ve
 * yanlışlığı gözle görülmez: 36 karakterlik, geçerli görünen, ama AD
 * araçlarının gösterdiğinden BAŞKA bir değer. Bunun bedeli gecikmeli
 * ödenir — kimlikler yazılır, sonra biri `dsquery` ile karşılaştırır ve
 * hiçbir kaydın tutmadığını görür. Daha kötüsü: sıralama düzeltilirse
 * saklanan bütün bağlar tek seferde geçersiz olur.
 *
 * Bu yüzden dönüşüm burada, tek yerde, ve bilinen vektörlerle sınanıyor.
 */
func formatObjectGUID(raw []byte) (string, error) {
	if len(raw) != 16 {
		return "", fmt.Errorf("%w: objectGUID is %d bytes, expected 16", ErrNotAUUID, len(raw))
	}

	b := make([]byte, 16)
	// Data1: ters
	b[0], b[1], b[2], b[3] = raw[3], raw[2], raw[1], raw[0]
	// Data2: ters
	b[4], b[5] = raw[5], raw[4]
	// Data3: ters
	b[6], b[7] = raw[7], raw[6]
	// Data4: olduğu gibi
	copy(b[8:], raw[8:])

	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], nil
}

/*
 * identityAttrs, KARARLI kimliği taşıyabilecek öznitelikler.
 *
 * ⚠️ İKİSİ BİRDEN İSTENİYOR ve hangisinin kullanılacağı DEĞERİN
 * BİÇİMİNDEN anlaşılıyor, bir ayardan değil.
 *
 * Gerekçe: "hangi öznitelik" diye bir ayar, operatörün yanlış
 * doldurabileceği bir alan daha demek — ve yanlış doldurulduğunda
 * çıkan cevap "bu dizinde kararlı kimlik yok" oluyor, yani sessiz ve
 * yanlış. Ölçüldü (OpenLDAP): olmayan öznitelik boş dönüyor, hata
 * değil; yani ikisini birden istemek bedavaya geliyor.
 *
 * ⚠️ Sıra ANLAMLI ve sabit: AD'de ikisi de bulunabilir ve seçimin
 * koşudan koşuya DEĞİŞMESİ, saklanmış bütün bağların tek seferde
 * kopması demek olurdu.
 */
var identityAttrs = []string{"objectGUID", "entryUUID"}

/*
 * decodeIdentity, ham öznitelik değerini kanonik kimliğe çevirir.
 *
 * Seçim BİÇİME göre: 16 ham bayt AD'nin objectGUID'i, 36 karakterlik
 * metin RFC 4530 entryUUID'i. Hiçbirine uymayan değer HATA — kimlik
 * alanına "belki budur" yazmak, kimliğin kendisini anlamsız kılardı.
 *
 * Boş değer hata DEĞİL, cevabın kendisi: bu dizin (ya da bu servis
 * hesabı) kararlı bir kimlik vermiyor. Çağıran bunu bir yokluk olarak
 * ele almalı, bir arıza olarak değil.
 */
func decodeIdentity(raw []byte) (string, error) {
	switch len(raw) {
	case 0:
		return "", nil
	case 16:
		return formatObjectGUID(raw)
	default:
		return normalizeEntryUUID(string(raw))
	}
}

/*
 * subjectFilter, kanonik kimlikten LDAP arama filtresi üretir.
 *
 * ⚠️ İKİ ÖZNİTELİK BİRDEN: hangi dizinde olduğumuzu bilmek zorunda
 * değiliz ve olmayanı sormak bedava (ölçüldü — sunucu boş döndürüyor,
 * hata değil).
 *
 * ⚠️ objectGUID BİNARY ve filtrede ham bayt olarak, her biri kaçışlı
 * yazılıyor. Baytlar da tel üzerindeki sıraya GERİ çevriliyor:
 * formatObjectGUID'in tersi. Bu ters çevirme atlanırsa filtre hiçbir
 * şey bulmaz ve sonuç "bu kullanıcı dizinde yok" olur — yani sessiz ve
 * yanlış.
 */
func subjectFilter(subject string) (string, error) {
	canonical, err := normalizeEntryUUID(subject)
	if err != nil {
		return "", err
	}

	hexOnly := strings.ReplaceAll(canonical, "-", "")
	b, err := hex.DecodeString(hexOnly)
	if err != nil || len(b) != 16 {
		return "", fmt.Errorf("%w: %q", ErrNotAUUID, subject)
	}

	// Kanonik metinden TEL sırasına: ilk üç alan yeniden ters çevriliyor.
	wire := make([]byte, 16)
	wire[0], wire[1], wire[2], wire[3] = b[3], b[2], b[1], b[0]
	wire[4], wire[5] = b[5], b[4]
	wire[6], wire[7] = b[7], b[6]
	copy(wire[8:], b[8:])

	var esc strings.Builder
	for _, c := range wire {
		esc.WriteString(fmt.Sprintf("\\%02x", c))
	}

	return "(|(entryUUID=" + canonical + ")(objectGUID=" + esc.String() + "))", nil
}
