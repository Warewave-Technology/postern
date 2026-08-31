package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/warewave/postern/internal/store"
)

/*
 * Kullanıcı parolaları.
 *
 * ⚠️ BU DOSYA, localcred.go'daki "BURADA PAROLA YOK VE OLMAYACAK"
 * kuralının BİLİNÇLİ İSTİSNASI. O kural bir kaprisle değil ölçülmüş
 * gerekçelerle yazılmıştı ve hâlâ geçerli — yalnızca kapsamı daraldı:
 *
 *   - MAKİNE ÜRETİMİ SIR (localcred.go) kırılmadı. Acil durum kapısı,
 *     yani yöneticiler ve `postern admin issue`, hâlâ yalnızca o değeri
 *     kabul ediyor. Bir yönetici hesabı ASLA parola tutamaz.
 *   - PAROLA (bu dosya) yalnızca sıradan kullanıcılar için ve yalnızca
 *     panel kapısında. postern'in kendi kullanıcı veritabanı olduğu
 *     kurulumlarda insanlardan 34 karakterlik bir base32 dizisini
 *     ezberlemelerini istemek gerçekçi değildi; olan şey, o dizinin bir
 *     yapışkan nota yazılmasıydı.
 *
 * KAYBEDİLEN ŞEYİ AÇIKÇA YAZIYORUM, çünkü bir gün biri bunu okuyup
 * "neden hız sınırı bu kadar sıkı" diye soracak:
 *
 *   1. Kimlik bilgisi doldurma (credential stuffing) artık YAPISAL
 *      OLARAK imkânsız değil. Kullanıcı kurumsal parolasını buraya
 *      yazabilir. Politika bunu tamamen engelleyemez; yalnızca en kötü
 *      seçimleri eler.
 *   2. Çevrimiçi tahmin artık bir YÜK sorunu değil, bir GÜVENLİK
 *      sorunu. Bu yüzden hesap başına gecikme (bkz. httpapi/backoff.go)
 *      bu değişiklikle BİRLİKTE geldi, sonradan değil.
 *
 * Kazanılan şey: insanların gerçekten kullanabildiği bir kapı.
 */

// Politika ayarları. TEK AYARLANABİLİR DÜĞME uzunluk.
//
// ⚠️ "Büyük harf + rakam + sembol şart" kuralı BİLEREK YOK. Ölçülen
// sonucu şu: insanlar "Parola1!" yazıyor ve kural sağlanmış oluyor.
// Kuralın ürettiği şey tahmin edilebilir bir kalıp, entropi değil.
// Uzunluk + çeşitlilik tabanı + yaygın parola listesi aynı işi, kalıp
// üretmeden yapıyor. Düğmeyi eklemek isteyen olursa gerekçesini burada
// bu paragrafın karşısına yazsın.
const KeyPasswordMinLength = "password.min_length"

// Uzunluk sınırları.
//
// Alt sınır bir TABAN, ayarın kendisi değil: paneldeki bir yönetici
// `password.min_length = 4` yazarak politikayı kapatamasın. Üst sınır
// argon2'ye giden girdiyi bağlıyor — 10MB'lık bir "parola" doğrulama
// yuvasını gereksiz yere tutardı.
const (
	passwordMinFloor   = 8
	passwordMinDefault = 12
	passwordMaxLength  = 256
)

// ErrPolicyBound, ayarın taban/tavan dışında olduğunu söyler.
var ErrPolicyBound = fmt.Errorf(
	"password.min_length must be a whole number between %d and %d",
	passwordMinFloor, passwordMaxLength)

/*
 * ParsePasswordMinLength, ayar değerini çözer.
 *
 * ⚠️ YAZMA ANINDA ÇAĞRILIYOR, okuma anında değil. Çözülemeyen değer
 * okuma anında varsayılana düşerdi (güvenli yön) ama operatöre hiçbir
 * şey söylemezdi: "8" yerine "sekiz" yazıp politikanın 12'de kaldığını
 * fark etmemek mümkün olurdu. auth.ParseAccountDuration'daki karar.
 */
func ParsePasswordMinLength(v string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, ErrPolicyBound
	}
	if n < passwordMinFloor || n > passwordMaxLength {
		return 0, ErrPolicyBound
	}
	return n, nil
}

// PasswordPolicy, bir parolanın geçmesi gereken kurallar.
//
// Yalnızca MinLength ayarlanabilir; gerisi taban ve kapatılamaz. Yapı
// yine de bütün kuralları taşıyor: panelin kullanıcıya "kural neydi"
// diye gösterebilmesi için tek kaynak burası olmalı, ekranda ikinci bir
// kopyası değil.
type PasswordPolicy struct {
	MinLength int `json:"min_length"`
	MaxLength int `json:"max_length"`
	// MinDistinct, farklı karakter sayısı tabanı.
	MinDistinct int `json:"min_distinct"`
}

// DefaultPasswordPolicy, ayar okunamadığında geçerli olan.
func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength: passwordMinDefault,
		MaxLength: passwordMaxLength,
		// 5 farklı karakter: "aaaaaaaaaaaa" ve "121212121212" gibi uzun
		// ama boş parolalar uzunluk kuralını geçiyordu.
		MinDistinct: 5,
	}
}

/*
 * LoadPasswordPolicy, politikayı ayarlardan okur.
 *
 * ⚠️ HATA VARSAYILANA DÜŞÜYOR, kapıyı kapatmıyor. Bu bir yetkilendirme
 * kararı değil, bir kalite eşiği: veritabanı okunamadığı için hiç kimse
 * parolasını değiştiremesin demek, arızayı bir kilitlenmeye çevirirdi.
 * Yön güvenli: düşülen değer varsayılan, gevşek değil.
 */
func LoadPasswordPolicy(ctx context.Context, db *store.Store) PasswordPolicy {
	p := DefaultPasswordPolicy()
	v, err := db.Setting(ctx, KeyPasswordMinLength)
	if err != nil {
		return p
	}
	if n, perr := ParsePasswordMinLength(v); perr == nil {
		p.MinLength = n
	}
	return p
}

/*
 * ErrWeakPassword, parolanın politikayı geçmediğini söyler.
 *
 * ⚠️ PAKET ÖNEKİ ("auth: ") BİLEREK YOK. Bu paketteki diğer sentinel'ler
 * onu taşıyor ve doğru: onlar günlüğe ve operatöre gidiyor, nereden
 * geldiklerini söylemeleri gerekiyor. Bu metin ise doğrudan
 * KULLANICININ EKRANINA basılıyor — parolasını değiştirmeye çalışan
 * kişiye "auth: password does not meet the policy" demek, ona hiçbir
 * şey anlatmayan bir uygulama detayını göstermek.
 */
var ErrWeakPassword = errors.New("password does not meet the policy")

/*
 * Check, parolayı politikaya göre sınar.
 *
 * ⚠️ SEBEP AÇIKÇA DÖNÜYOR ve bu bir sızıntı DEĞİL: kişi zaten kendi
 * seçtiği değeri biliyor. Gizlenecek bir şey yok, gizlemenin bedeli ise
 * "reddedildi, neden bilmiyorum" döngüsü.
 *
 * username BOŞ GEÇİLEBİLİR; verildiğinde parola onu içeremez.
 */
func (p PasswordPolicy) Check(password, username string) error {
	if len([]rune(password)) < p.MinLength {
		return fmt.Errorf("%w: it must be at least %d characters", ErrWeakPassword, p.MinLength)
	}
	// Uzunluk RUNE değil BAYT olarak da bağlanıyor: argon2'ye giden şey
	// bayt dizisi ve emoji'den kurulu bir "parola" rune sayısını
	// geçerken bayt olarak katbekat büyük olabilir.
	if len(password) > p.MaxLength {
		return fmt.Errorf("%w: it must be at most %d bytes", ErrWeakPassword, p.MaxLength)
	}

	distinct := map[rune]struct{}{}
	for _, r := range password {
		distinct[r] = struct{}{}
	}
	if len(distinct) < p.MinDistinct {
		return fmt.Errorf(
			"%w: it repeats too few different characters (needs at least %d)",
			ErrWeakPassword, p.MinDistinct)
	}

	lower := strings.ToLower(password)

	/*
	 * ⚠️ KULLANICI ADI İÇEREMEZ.
	 *
	 * Somut olan şu: yönetici "ayse.yilmaz" hesabına parola verir, kişi
	 * ilk girişte "ayse.yilmaz2026" yazar. Uzunluk kuralı geçilir ve
	 * ortaya, hesap adını bilen herkesin ilk deneyeceği bir parola
	 * çıkar. Tersi de yasak: adı parolanın içinde saklamak da aynı şey.
	 */
	if username != "" {
		u := strings.ToLower(strings.TrimSpace(username))
		if u != "" && strings.Contains(lower, u) {
			return fmt.Errorf("%w: it must not contain your username", ErrWeakPassword)
		}
	}

	// Ürün adı: kurulumun ilk günü herkesin aklına gelen kelime.
	if strings.Contains(lower, "postern") {
		return fmt.Errorf("%w: it must not contain \"postern\"", ErrWeakPassword)
	}

	if reason := commonReason(lower); reason != "" {
		return fmt.Errorf("%w: %s", ErrWeakPassword, reason)
	}
	return nil
}

/*
 * commonReason, parolanın bilinen bir zayıf kalıp olup olmadığı.
 *
 * ⚠️ BU LİSTE KÜÇÜK VE BUNU DÜRÜSTÇE YAZIYORUM. On binlik bir sızıntı
 * listesi gömmek cazip ama asıl işi uzunluk kuralı yapıyor: 12 karakter
 * tabanı, o listelerin ezici çoğunluğunu (hepsi daha kısa) zaten eliyor.
 * Kalan gerçek risk uzun-ama-tahmin-edilebilir seçimler, ve onu bir
 * kelime listesi değil YAPISAL kontroller yakalıyor — art arda giden
 * tuşlar, tek karakterin tekrarı, listedeki kökün sonuna rakam eklemek.
 *
 * Yani buradaki liste kök listesidir, parola listesi değil: "Parola123!"
 * kökünden yakalanıyor.
 */
func commonReason(lower string) string {
	// Sondaki rakam ve noktalama atılıyor: "password2026!" ile
	// "password" aynı seçimdir.
	root := strings.TrimRightFunc(lower, func(r rune) bool {
		return unicode.IsDigit(r) || unicode.IsPunct(r) || unicode.IsSymbol(r)
	})
	for _, w := range commonRoots {
		if root == w {
			return "it is one of the most commonly chosen passwords"
		}
	}

	if runLength(lower) >= 6 {
		return "it is mostly a run of neighbouring keys or characters"
	}
	return ""
}

/*
 * runLength, en uzun ARDIŞIK diziyi ölçer: "abcdef", "123456",
 * "qwerty" ve tersleri.
 *
 * Klavye sırası da sayılıyor çünkü "qwertyuiop" alfabetik olarak ardışık
 * değil ama tahmin edilebilirlik açısından "abcdefghij" ile aynı şey.
 */
func runLength(s string) int {
	rows := []string{
		"qwertyuiop", "asdfghjkl", "zxcvbnm",
		"abcdefghijklmnopqrstuvwxyz", "0123456789",
	}
	best := 0
	for _, row := range rows {
		for _, dir := range []string{row, reverse(row)} {
			for n := len(s); n >= 4; n-- {
				for i := 0; i+n <= len(s); i++ {
					if strings.Contains(dir, s[i:i+n]) && n > best {
						best = n
					}
				}
			}
		}
	}
	return best
}

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// commonRoots, sondaki rakam/noktalama atıldıktan sonra karşılaştırılan
// kökler. Kısa tutuluyor: uzunluk kuralı ağır işi yapıyor.
var commonRoots = []string{
	"password", "parola", "sifre", "şifre", "passw0rd", "p@ssword", "p@ssw0rd",
	"welcome", "hosgeldin", "hoşgeldin", "letmein", "changeme", "default",
	"admin", "administrator", "yonetici", "yönetici", "root", "toor",
	"qwerty", "azerty", "asdfgh", "zxcvbn", "iloveyou", "monkey", "dragon",
	"football", "baseball", "basketball", "sunshine", "princess", "master",
	"trustno", "starwars", "superman", "batman", "pokemon", "shadow",
	"bastion", "server", "linux", "ubuntu", "debian", "windows",
	"galatasaray", "fenerbahce", "fenerbahçe", "besiktas", "beşiktaş",
	"trabzonspor", "turkiye", "türkiye", "istanbul", "ankara", "izmir",
	"secret", "secrets", "access", "login", "signin", "credential",
	"summer", "winter", "spring", "autumn", "january", "december",
	"company", "corporate", "internal", "temporary", "temp", "test",
}

/*
 * HashPassword, kullanıcı seçimi bir parolanın doğrulayıcısını üretir.
 *
 * ⚠️ BİÇİM KONTROLÜ YOK ve olmamalı: kontrol edilecek bir biçim yok.
 * Bu, localcred.go'daki NormalizeSecret'ın TAM TERSİ ve iki yolun neden
 * birbirine karışmaması gerektiğinin de sebebi. Politika kontrolü
 * ÇAĞIRANIN işi — burada yapılsaydı, politika sıkılaştığında var olan
 * parolaların yeniden hash'lenmesi imkânsız hâle gelirdi.
 *
 * KDF aynı: argon2id, localcred.go'daki parametrelerle. Orada maliyet
 * "gücü için gerekli değil ama ileride biri parola derse" diye
 * seçilmişti. O gün geldi ve parametreler zaten yerindeydi.
 */
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("auth.HashPassword: empty password")
	}
	if len(password) > passwordMaxLength {
		return "", errors.New("auth.HashPassword: password too long")
	}
	return hashSecret(password)
}

/*
 * VerifyPassword, parolayı doğrulayıcıyla karşılaştırır.
 *
 * ⚠️ VerifyLocalSecret'tan AYRI BİR FONKSİYON, aynı fonksiyona bayrak
 * eklenmiş hâli değil. Sebebi somut: tek fonksiyon olsaydı, çağıranın
 * bayrağı unutması ya da saldırganın bayrağı seçebilmesi hâlinde
 * kurumsal parola, biçim kontrolüne takılmadan doğrudan KDF'e giderdi.
 * İki ayrı isim, çağrı yerinde hangi kapının açıldığını görünür yapıyor.
 */
func VerifyPassword(verifier, input string) bool {
	if input == "" || len(input) > passwordMaxLength {
		/*
		 * ⚠️ ERKEN DÖNMÜYORUZ — VerifyLocalSecret'taki gerekçenin
		 * aynısı, ters yönden.
		 *
		 * Boş parola KDF'e ulaşmamalı (aşırı uzunu da: yuvayı boşuna
		 * tutar). Ama düz bir `return false`, bu yolu sır yolundan
		 * ÖLÇÜLEBİLİR biçimde ayırırdı: boş bir tahmin, parola tutan
		 * hesapta mikrosaniyeler, sır tutan hesapta argon2 süresi
		 * sürerdi. Fark tek bir şey söyler — "bu hesabın acil durum
		 * sırrı var" — ve saldırganın hedef seçmesine yarayan tam da o
		 * bilgidir.
		 */
		compareArgon2(verifier, uniformCostInput)
		return false
	}
	return compareArgon2(verifier, input)
}
