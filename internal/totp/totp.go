// Package totp, RFC 6238 zaman tabanlı tek kullanımlık kodları üretir ve
// doğrular.
//
// NEDEN ELLE YAZILDI: TOTP, HMAC üzerine ~40 satırlık bir belirtim ve
// RFC 6238 RESMÎ TEST VEKTÖRLERİ yayımlıyor — yani doğruluğu iddia
// edilmiyor, ölçülüyor (totp_test.go). Kimlik doğrulamanın kalbine
// duruma göre denetlenmesi gereken bir bağımlılık koymamak, bu ölçüm
// mümkünken tercih edilir.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	/*
	 * ⚠️ SHA-1, BİLEREK — ve gosec'in G505 uyarısı burada YANLIŞ POZİTİF
	 * DEĞİL, ama gerekçesi bu kullanımı kapsamıyor.
	 *
	 * SHA-1'in kırıldığı yer ÇAKIŞMA direnci (imza, sertifika). HMAC
	 * çakışmaya dayanmıyor; HMAC-SHA1'e karşı pratik bir saldırı yok ve
	 * TLS'ten IPsec'e kadar hâlâ yaygın.
	 *
	 * Asıl belirleyici olan şu: RFC 6238'in varsayılan profili SHA-1 ve
	 * kimlik doğrulayıcı uygulamalarının (Google Authenticator, Aegis,
	 * 1Password) fiilen desteklediği tek birleşim bu. "Daha güçlü" diye
	 * SHA-256 seçmek, kullanıcının telefonundaki uygulamanın SESSİZCE
	 * YANLIŞ kod üretmesi demek olurdu — yani hesabın kilitlenmesi.
	 * Kimsenin giremediği bir hesap, güvenlik kazancı değil.
	 */
	"crypto/sha1" // #nosec G505 -- HMAC-SHA1: RFC 6238 varsayılanı, bkz. yukarısı
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

/*
 * Parametreler.
 *
 * ⚠️ SHA-1 ve 6 hane, RFC 6238'in varsayılanı ve kimlik doğrulayıcı
 * uygulamalarının (Google Authenticator, Aegis, 1Password) fiilen
 * desteklediği tek birleşim. "Daha güçlü" diye SHA-256 seçmek,
 * kullanıcının telefonundaki uygulamanın sessizce YANLIŞ kod üretmesi
 * demek olurdu — hesabın kilitlenmesi, güvenlik kazancı değil.
 */
const (
	Digits = 6
	Period = 30 * time.Second
	// SecretBytes, üretilen sırrın uzunluğu. RFC 4226 en az 128 bit
	// istiyor, 160 bit öneriyor; base32'de 32 karakter ediyor.
	SecretBytes = 20
)

/*
 * Skew, kabul edilen adım toleransı (her yönde).
 *
 * ⚠️ 1 ADIM, yani ±30 saniye. Gerekçe: telefon saatiyle sunucu saati
 * birkaç saniye kayabilir ve kullanıcı kodu okuyup yazarken adım
 * sınırını geçebilir. Daha geniş bir pencere (±2, ±3) her kodu 2,5–3,5
 * dakika geçerli kılar — çalınan bir kodun kullanılabilir ömrünü
 * gereksizce uzatır.
 */
const Skew = 1

// base32NoPad, kimlik doğrulayıcı uygulamalarının beklediği kodlama:
// büyük harf, dolgusuz.
var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret, yeni bir paylaşılan sır üretir.
func NewSecret() (string, error) {
	b := make([]byte, SecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("totp: secret generation failed: %w", err)
	}
	return base32NoPad.EncodeToString(b), nil
}

// Code, verilen an için beklenen kodu üretir.
func Code(secret string, t time.Time) (string, error) {
	key, err := decode(secret)
	if err != nil {
		return "", err
	}
	return hotp(key, step(t)), nil
}

/*
 * Verify, kodu doğrular ve HANGİ ADIMIN kullanıldığını döner.
 *
 * ⚠️ ADIM DIŞARI VERİLİYOR ÇÜNKÜ TEKRAR KORUMASI ÇAĞIRANIN İŞİ. TOTP'nin
 * kendisi bir kodun daha önce kullanılıp kullanılmadığını bilemez:
 * aynı kod 30 saniye boyunca geçerlidir. Omuz üstünden okuyan ya da
 * araya giren biri, kodu aynı pencerede İKİNCİ kez kullanabilir.
 * Kullanılan adımı saklamak ve tekrarını reddetmek zorunlu
 * (bkz. store.UseTOTPStep).
 *
 * used=false dönüşü, "yanlış kod" ile "geçersiz sır"ı ayırmıyor
 * bilerek: ikisi de kullanıcıya aynı cevabı vermeli.
 */
func Verify(secret, code string, now time.Time) (ok bool, usedStep int64, err error) {
	key, err := decode(secret)
	if err != nil {
		return false, 0, err
	}
	code = strings.TrimSpace(code)
	if len(code) != Digits {
		return false, 0, nil
	}

	current := step(now)
	/*
	 * ⚠️ TÜM PENCERE HER ZAMAN TARANIYOR — eşleşme bulununca DÖNÜLMÜYOR.
	 *
	 * Erken dönen bir döngü, doğru kodun pencerenin neresinde olduğunu
	 * çalışma süresine sızdırır. Tek başına küçük bir sızıntı ama
	 * bedava kapatılıyor: karşılaştırma da subtle.ConstantTimeCompare.
	 */
	var found bool
	var at int64
	for d := int64(-Skew); d <= Skew; d++ {
		s := current + d
		want := hotp(key, s)
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			found = true
			at = s
		}
	}
	if !found {
		return false, 0, nil
	}
	return true, at, nil
}

// StepAt, bir anın adım numarası — çağıranın tekrar koruması için.
func StepAt(t time.Time) int64 { return step(t) }

func step(t time.Time) int64 {
	return t.UTC().Unix() / int64(Period/time.Second)
}

func decode(secret string) ([]byte, error) {
	// Kullanıcı sırrı elle girebiliyor: boşluk ve küçük harf temizleniyor.
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	key, err := base32NoPad.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("totp: secret is not valid base32: %w", err)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("totp: empty secret")
	}
	return key, nil
}

// hotp, RFC 4226 §5.3: HMAC-SHA1, dinamik kesme, mod 10^Digits.
func hotp(key []byte, counter int64) string {
	var buf [8]byte
	/*
	 * ⚠️ int64 → uint64 dönüşümü kayıpsız: her ikisi de 64 bit ve
	 * RFC 4226 sayacı zaten 8 baytlık işaretsiz bir değer. Negatif
	 * sayaç ancak 1970 ÖNCESİ bir zaman için oluşur; step() Unix
	 * saniyesinden türediği için üretimde mümkün değil, oluşsa da
	 * ikili gösterim RFC'nin istediği 8 baytın aynısı olur.
	 */
	binary.BigEndian.PutUint64(buf[:], uint64(counter)) // #nosec G115 -- 64->64 bit, bkz. yukarısı

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])

	mod := uint32(1)
	for i := 0; i < Digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", Digits, value%mod)
}

/*
 * URI, kimlik doğrulayıcı uygulamasının okuduğu otpauth bağlantısı.
 *
 * ⚠️ issuer HEM yolda HEM parametrede: uygulamaların bir kısmı birini,
 * bir kısmı diğerini okuyor. Yalnızca birini yazmak, hesabın telefonda
 * "issuer" olmadan görünmesine yol açıyor — iki bastion kullanan biri
 * hangi kodun hangisine ait olduğunu ayırt edemez.
 */
func URI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(Digits))
	q.Set("period", fmt.Sprint(int(Period/time.Second)))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
