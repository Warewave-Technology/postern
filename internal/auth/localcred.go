package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

/*
 * Yerel kimlik bilgisi: postern'in KENDİ kapısı.
 *
 * ⚠️ BURADA "PAROLA" YOK VE OLMAYACAK. Değeri makine üretiyor; operatör
 * seçemiyor, değiştiremiyor, hatırlamıyor. Gerekçe kolaylık değil:
 * postern'in en keskin iddiası kullanıcının KURUMSAL parolasını hiç
 * görmemesi, ve "yerel parolanı AD parolan yapma" demek bunu
 * engellemiyor. Engelleyen tek şey, o değeri kabul edecek bir yolun
 * hiç bulunmaması.
 *
 * Yan etkileri zincirleme ve hepsi lehimize:
 *   - Kimlik bilgisi doldurma (credential stuffing) yapısal olarak
 *     imkânsız: sır yeniden kullanılmış olamaz.
 *   - 128 bit rastgelelik karşısında çevrimiçi tahmin bir güvenlik
 *     sorunu olmaktan çıkıp yalnızca bir yük sorunu oluyor.
 *   - Dolayısıyla hesap KİLİTLEMEYE gerek kalmıyor — ki kilitleme,
 *     kimliği doğrulanmamış bir saldırganın eline kurulumun tek
 *     yöneticisini dışarıda tutan bir düğme verirdi.
 */

// secretBytes, üretilen sırrın uzunluğu. 16 bayt = 128 bit: base32'de
// 26 karakter, elle yazılabilir uzunlukta ve tahmin edilemez.
const secretBytes = 16

// secretEncoding, base32 (RFC 4648) BÜYÜK HARF ve dolgusuz.
//
// Base64 değil: sır ekrana basılıp bir kasaya taşınıyor, arada telefonda
// okunabiliyor. Base32'de büyük/küçük harf ayrımı ve 0/O, 1/l gibi
// karışan çiftlerin bir kısmı yok; yanlış yazma ihtimali düşük.
var secretEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// argon2 parametreleri. Değer 128 bit rastgele olduğu için KDF maliyeti
// GÜCÜ için gerekli değil — hiçbir donanım 2^128'i denemiyor. Yine de
// argon2id kullanılıyor: bu dosyanın dışındaki bir değişiklik (birinin
// ileride "operatör kendi parolasını seçsin" demesi) hızlı bir hash'i
// sessizce zayıflığa çevirirdi. Maliyet ölçülü tutuluyor ve giriş ucunda
// eşzamanlılık sınırı var — yoksa her deneme 19MB ayırtan bir kaldıraç
// olurdu.
const (
	argonTime    = 2
	argonMemory  = 19 * 1024 // KiB
	argonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16
)

// ErrMalformedSecret, girilen değerin postern'in ÜRETEBİLECEĞİ bir
// biçimde olmadığını söyler.
var ErrMalformedSecret = errors.New("auth: value is not shaped like a postern secret")

/*
 * NewLocalSecret, yeni bir sır ve onun doğrulayıcısını üretir.
 *
 * Dönen ilk değer operatöre BİR KEZ gösterilecek olan; ikincisi
 * veritabanına yazılacak olan. Sır hiçbir yerde saklanmıyor.
 */
func NewLocalSecret() (secret, verifier string, err error) {
	raw := make([]byte, secretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("auth.NewLocalSecret: %w", err)
	}
	secret = groupSecret(secretEncoding.EncodeToString(raw))

	verifier, err = hashSecret(secret)
	if err != nil {
		return "", "", err
	}
	return secret, verifier, nil
}

// groupSecret, okunabilirlik için dörtlü gruplar hâlinde ayırır.
// Ayraçlar doğrulamada atılıyor: kullanıcı isterse yapıştırır, isterse
// elle yazar.
func groupSecret(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && i%4 == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
}

/*
 * NormalizeSecret, girilen değeri karşılaştırılabilir hâle getirir.
 *
 * ⚠️ BİÇİM KONTROLÜ BİR GÜVENLİK ÖZELLİĞİ, kolaylık değil. postern'in
 * üretemeyeceği bir değer KDF'e hiç ulaşmıyor. Bunun somut faydası:
 * kutucuğa kurumsal parolasını yazan operatörün parolası hiçbir zaman
 * hash'lenmiyor, hiçbir zaman bir karşılaştırmaya girmiyor ve hiçbir
 * biçimde saklanmıyor — yalnızca reddediliyor.
 */
func NormalizeSecret(in string) (string, error) {
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case '-', ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, in)
	cleaned = strings.ToUpper(cleaned)

	want := secretEncoding.EncodedLen(secretBytes)
	if len(cleaned) != want {
		return "", ErrMalformedSecret
	}
	if _, err := secretEncoding.DecodeString(cleaned); err != nil {
		return "", ErrMalformedSecret
	}
	return groupSecret(cleaned), nil
}

// hashSecret, doğrulayıcıyı üretir. Biçim kendini tanımlıyor:
// "argon2id$v=19$m=..,t=..,p=..$salt$hash" — parametreler değerin
// içinde, böylece ileride sertleştirilebilirler ve eski satırlar
// okunmaya devam eder.
func hashSecret(secret string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth.hashSecret: %w", err)
	}
	sum := argon2.IDKey([]byte(secret), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum)), nil
}

/*
 * VerifyLocalSecret, girilen değerin doğrulayıcıya uyup uymadığı.
 *
 * ⚠️ SABİT ZAMANLI KARŞILAŞTIRMA. Doğrulayıcı bir hash olsa da,
 * baytları erken biten bir karşılaştırma saldırgana adım adım geri
 * bildirim verir.
 */
func VerifyLocalSecret(verifier, input string) bool {
	normalized, err := NormalizeSecret(input)
	if err != nil {
		/*
		 * ⚠️ ERKEN DÖNMÜYORUZ, MALİYETİ YİNE ÖDÜYORUZ.
		 *
		 * Eskiden burada düz bir `return false` vardı ve doğruydu:
		 * postern'in TEK kimlik bilgisi türü makine üretimi sırdı, yani
		 * her hesap aynı yoldan geçiyordu ve ölçülecek bir fark yoktu.
		 *
		 * Parola (password.go) eklendiği an bu bozuldu. İki yol iki
		 * farklı maliyet demek: biçimsiz bir tahmin, sır tutan bir
		 * hesapta mikrosaniyeler, parola tutan bir hesapta argon2
		 * süresi. Aradaki fark ölçülebilir ve tam olarak şunu söyler:
		 * "bu kullanıcı ACİL DURUM sırrı taşıyor" — yani saldırganın
		 * hangi hesabı hedefleyeceğini seçmesine yarayan tek bilgi.
		 *
		 * Sahte bir doğrulama yaparak farkı kapatıyoruz. Sonuç yine
		 * false; ödenen tek şey zaman.
		 */
		compareArgon2(verifier, uniformCostInput)
		return false
	}
	return compareArgon2(verifier, normalized)
}

// uniformCostInput, biçim kontrolü düştüğünde argon2'ye verilen sabit
// değer. İçeriği önemsiz — tek işi aynı maliyeti ödetmek.
const uniformCostInput = "postern-uniform-cost"

// compareArgon2, kendini tanımlayan doğrulayıcıyı çözüp sabit zamanlı
// karşılaştırır. İki kimlik bilgisi türünün ORTAK yanı yalnızca bu.
func compareArgon2(verifier, input string) bool {
	parts := strings.Split(verifier, "$")
	if len(parts) != 5 || parts[0] != "argon2id" {
		return false
	}
	var version, memory, time, threads int
	if _, err := fmt.Sscanf(parts[1], "v=%d", &version); err != nil {
		return false
	}
	if _, err := fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}

	// #nosec G115 -- parametreler bizim yazdığımız doğrulayıcıdan geliyor
	got := argon2.IDKey([]byte(input), salt,
		uint32(time), uint32(memory), uint8(threads), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}
