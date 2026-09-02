package objstore

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

/*
 * AWS Signature Version 4 — elle.
 *
 * ⚠️ NEDEN SDK DEĞİL. aws-sdk-go-v2 tek bir PUT için onlarca modül
 * getiriyor; bu depoda 12 doğrudan bağımlılık var ve duruş açık:
 * "bir öğleden sonra yazılıp bir sabah test edilebilecek şey
 * getirilmez". TOTP RFC vektörlerine, QR referans kodlayıcıya,
 * SFTP çözücü protokol belgesine karşı elle yazıldı — bu da aynı raf.
 *
 * ⚠️ VE DOĞRULANABİLİR. İmzalama HMAC-SHA256 zincirinden ibaret ve
 * AWS'nin kendi test paketi (aws4_testsuite) bilinen girdi/çıktı
 * çiftleri veriyor. sigv4_test.go o vektörleri koşuyor: "doğru
 * olduğunu düşünüyorum" ile "resmi vektör geçiyor" arasındaki fark
 * bu dosyanın var olma şartı.
 *
 * ⚠️ TEK PUT, MULTIPART YOK. Ölçüldü: 140 KB ham terminal çıktısı
 * 155 KB .cast üretiyor, yani dosya boyutu ≈ üretilen çıktı. Tek
 * PUT'un sınırı 5 GB; oraya ulaşmak için bir oturumun 5 GB terminal
 * çıktısı basması gerekir. Multipart'ı BUGÜN yazmak, kullanılmayan
 * bir kod yolunu bakım yüküne çevirmek olurdu — ama sınır aşıldığında
 * SESSİZ KALINMIYOR (bkz. client.go'daki boyut kontrolü).
 */

const (
	algorithm   = "AWS4-HMAC-SHA256"
	terminator  = "aws4_request"
	amzDateFmt  = "20060102T150405Z"
	dateOnlyFmt = "20060102"
)

// Credentials, imzalama için gereken kimlik.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

/*
 * sign, isteği yerinde imzalar.
 *
 * payloadHash ÇAĞIRAN TARAFINDAN veriliyor ve bu bilinçli:
 * UNSIGNED-PAYLOAD da kabul edilirdi ama o zaman gövde imzaya BAĞLI
 * OLMAZDI. Kaydı yükleyip "şu baytları gönderdim" diyebilmek, tam da
 * denetim izini taşıdığımız için önemli — araya giren biri gövdeyi
 * değiştirdiğinde imza tutmamalı.
 */
func sign(req *http.Request, creds Credentials, region, service, payloadHash string, now time.Time) {
	amzDate := now.UTC().Format(amzDateFmt)

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if req.Host == "" {
		req.Host = req.URL.Host
	}

	signedHeaders, canonicalHeaders := canonicalizeHeaders(req)

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL),
		canonicalQuery(req.URL),
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	scope, signature := deriveSignature(canonicalRequest, creds, region, service, now)

	/*
	 * ⚠️ BU BAŞLIK ASLA LOGLANMAZ. İçinde imza ve kimlik kapsamı var;
	 * bir hata satırına düşen Authorization, sırrın kendisi olmasa da
	 * o istek için geçerli bir yetkidir.
	 */
	req.Header.Set("Authorization", algorithm+
		" Credential="+creds.AccessKeyID+"/"+scope+
		", SignedHeaders="+signedHeaders+
		", Signature="+signature)
}

/*
 * deriveSignature, kanonik istekten imzayı üretir: SigV4'ün SAF
 * çekirdeği.
 *
 * ⚠️ AYRI DURUYOR ÇÜNKÜ RESMİ VEKTÖRLER BURAYI SINIYOR. AWS'nin
 * aws4_testsuite'i "host;x-amz-date" imzalayan istekler üzerinden
 * yazılmış; bizim S3 imzalayıcımız haklı olarak bir başlık daha
 * (x-amz-content-sha256) imzalıyor. İkisini tek fonksiyonda tutsaydık
 * vektör testi ya yazılamaz ya da uydurma bir beklentiyle
 * "geçirilirdi" — yani elle yazmanın tek gerekçesi olan bağımsız
 * doğrulama kaybolurdu.
 *
 * Vektörler bu fonksiyonu ölçüyor; sign() ise onun etrafındaki S3
 * kablolamasını.
 */
func deriveSignature(canonicalRequest string, creds Credentials, region, service string, now time.Time) (scope, signature string) {
	amzDate := now.UTC().Format(amzDateFmt)
	dateOnly := now.UTC().Format(dateOnlyFmt)

	scope = strings.Join([]string{dateOnly, region, service, terminator}, "/")
	stringToSign := strings.Join([]string{
		algorithm,
		amzDate,
		scope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+creds.SecretAccessKey), dateOnly)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, terminator)
	return scope, hex.EncodeToString(hmacSHA256(kSigning, stringToSign))
}

// canonicalizeHeaders, imzalanacak başlıkları küçük harfe indirip sıralar.
func canonicalizeHeaders(req *http.Request) (signedHeaders, canonical string) {
	names := make([]string, 0, len(req.Header)+1)
	values := map[string]string{}

	// Host, req.Header'da DEĞİL: net/http onu ayrı tutuyor ve
	// imzalanması zorunlu.
	names = append(names, "host")
	values["host"] = req.Host

	for name, vs := range req.Header {
		lower := strings.ToLower(name)
		// Authorization imzanın kendisi; imzalanamaz.
		if lower == "authorization" {
			continue
		}
		names = append(names, lower)
		trimmed := make([]string, len(vs))
		for i, v := range vs {
			trimmed[i] = collapseSpaces(v)
		}
		values[lower] = strings.Join(trimmed, ",")
	}

	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		b.WriteString(n)
		b.WriteString(":")
		b.WriteString(values[n])
		b.WriteString("\n")
	}
	return strings.Join(names, ";"), b.String()
}

/*
 * canonicalURI, yolu SigV4'ün istediği gibi kodlar.
 *
 * ⚠️ url.EscapedPath() DEĞİL: SigV4 her segmenti RFC 3986'ya göre
 * kodlanmış ister ve '/' ayraç olarak KALIR. Bizim anahtarlarımız
 * <önek>/<tarih>/<oturum-id>.cast biçiminde ve yalnızca güvenli
 * karakter içeriyor, ama operatörün yazdığı bir önek boşluk ya da
 * Türkçe harf taşıyabilir; orada yanlış kodlama imzayı sessizce
 * bozardı ve hata "SignatureDoesNotMatch" olarak dönerdi — sebebi
 * hiçbir yerde yazmayan bir mesaj.
 */
func canonicalURI(u *url.URL) string {
	if u.Path == "" {
		return "/"
	}
	segments := strings.Split(u.Path, "/")
	for i, s := range segments {
		segments[i] = uriEncode(s, false)
	}
	return strings.Join(segments, "/")
}

/*
 * canonicalQuery, sorgu dizesini kanonikleştirir.
 *
 * ⚠️ SIRALAMA KODLANMIŞ ANAHTARA GÖRE, çözülmüşe göre değil. SigV4
 * böyle tanımlı ve ikisi ayrışabiliyor ("a b" ile "a-b" çözülmüş hâlde
 * bir sırada, kodlanmış hâlde başka). Bugün hiçbir isteğimiz sorgu
 * parametresi taşımıyor, ama yanlış sıra imzayı sessizce bozar ve
 * sunucu yalnızca "SignatureDoesNotMatch" der.
 */
func canonicalQuery(u *url.URL) string {
	q := u.Query()

	type pair struct{ k, v string }
	var pairs []pair
	for k, vs := range q {
		ek := uriEncode(k, true)
		for _, v := range vs {
			pairs = append(pairs, pair{ek, uriEncode(v, true)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})

	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, p.k+"="+p.v)
	}
	return strings.Join(parts, "&")
}

/*
 * collapseSpaces, başlık değerini SigV4'ün istediği hâle getirir:
 * baştaki/sondaki boşluk atılır, ARDIŞIK iç boşluklar tek boşluğa iner.
 *
 * ⚠️ SADECE TrimSpace YETMİYOR ve bunun tek pratik kurbanı operatörün
 * ELİYLE YAZDIĞI tek başlık değeri: server_side_encryption. Oraya
 * "aws:  kms" yazan biri, sebebi hiçbir yerde yazmayan bir 403 alırdı.
 */
func collapseSpaces(v string) string {
	v = strings.TrimSpace(v)
	if !strings.Contains(v, "  ") {
		return v
	}
	return strings.Join(strings.Fields(v), " ")
}

/*
 * uriEncode, AWS'nin tarif ettiği kodlama.
 *
 * Ayrılmamış karakterler (A-Z a-z 0-9 - _ . ~) olduğu gibi kalır,
 * geri kalan %XX olur ve HEX BÜYÜK HARF. encodeSlash false ise '/'
 * korunur (yol segmentlerini birleştirirken gerekiyor).
 */
func uriEncode(s string, encodeSlash bool) string {
	const upperhex = "0123456789ABCDEF"
	var b strings.Builder
	for i := range len(s) {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte('/')
		default:
			b.WriteByte('%')
			b.WriteByte(upperhex[c>>4])
			b.WriteByte(upperhex[c&15])
		}
	}
	return b.String()
}
