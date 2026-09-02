package objstore

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

/*
 * ⚠️ AWS'NİN KENDİ TEST VEKTÖRLERİ.
 *
 * Elle yazılmış bir imzalayıcının tek savunulabilir gerekçesi, doğru
 * olduğunun BAĞIMSIZ olarak gösterilebilmesi. Aşağıdaki değerler
 * AWS'nin aws4_testsuite paketinden: girdiler ve BEKLENEN imza
 * bizden gelmiyor. Bu dosya düşerse imzalayıcı yanlıştır — ne kadar
 * makul göründüğünden bağımsız olarak.
 */

const (
	// Test paketinin standart kimliği.
	tvAccessKey = "AKIDEXAMPLE"
	tvSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	tvRegion    = "us-east-1"
	tvService   = "service"
	tvHost      = "example.amazonaws.com"
)

func tvTime(t *testing.T) time.Time {
	t.Helper()
	ts, err := time.Parse(amzDateFmt, "20150830T123600Z")
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

// emptyHash, boş gövdenin SHA-256'sı — vektörlerin hepsi GET.
func emptyHash() string {
	sum := sha256.Sum256(nil)
	return hex.EncodeToString(sum[:])
}

// signatureOf, Authorization başlığından imzayı çeker.
func signatureOf(t *testing.T, req *http.Request) string {
	t.Helper()
	auth := req.Header.Get("Authorization")
	i := strings.Index(auth, "Signature=")
	if i < 0 {
		t.Fatalf("Authorization imza taşımıyor: %q", auth)
	}
	return auth[i+len("Signature="):]
}

/*
 * get-vanilla: test paketinin en sade hâli.
 *
 * ⚠️ VEKTÖR, SAF ÇEKİRDEĞİ SINIYOR. aws4_testsuite istekleri
 * "host;x-amz-date" imzalıyor; bizim S3 imzalayıcımız haklı olarak bir
 * başlık daha (x-amz-content-sha256) imzalıyor ve bu FARKLI bir kanonik
 * istek üretir. Vektörü sign() üzerinden koşmaya çalışsaydık ya
 * geçmezdi ya da beklentiyi kendi çıktımıza uydurmak zorunda kalırdık —
 * ikincisi, elle yazmanın tek gerekçesi olan bağımsız doğrulamayı yok
 * ederdi. Bu yüzden kanonik istek vektörün tarif ettiği gibi elle
 * kuruluyor ve deriveSignature ölçülüyor.
 */
func TestSigV4GetVanillaVector(t *testing.T) {
	canonicalRequest := strings.Join([]string{
		"GET", "/", "",
		"host:" + tvHost,
		"x-amz-date:20150830T123600Z",
		"",
		"host;x-amz-date",
		emptyHash(),
	}, "\n")

	_, got := deriveSignature(canonicalRequest,
		Credentials{tvAccessKey, tvSecretKey}, tvRegion, tvService, tvTime(t))

	const want = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got != want {
		t.Errorf("imza = %s\nbeklenen = %s", got, want)
	}
}

/*
 * get-vanilla-query-order-key-case: iki sorgu parametresi. Kanonik
 * sorgu yanlış sıralanırsa imza tutmaz ve sunucu yalnızca
 * "SignatureDoesNotMatch" der — sebebi hiçbir yerde yazmaz.
 */
func TestSigV4QueryOrderVector(t *testing.T) {
	u, err := url.Parse("https://" + tvHost + "/?Param2=value2&Param1=value1")
	if err != nil {
		t.Fatal(err)
	}
	// Kanonik sorguyu KENDİ kodumuz üretiyor: vektörün sınadığı şey de bu.
	canonicalRequest := strings.Join([]string{
		"GET", "/", canonicalQuery(u),
		"host:" + tvHost,
		"x-amz-date:20150830T123600Z",
		"",
		"host;x-amz-date",
		emptyHash(),
	}, "\n")

	_, got := deriveSignature(canonicalRequest,
		Credentials{tvAccessKey, tvSecretKey}, tvRegion, tvService, tvTime(t))

	const want = "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"
	if got != want {
		t.Errorf("imza = %s\nbeklenen = %s\nkanonik sorgu = %q", got, want, canonicalQuery(u))
	}
}

// S3 imzalayıcısı gövde özetini HER ZAMAN imzalamalı: UNSIGNED-PAYLOAD
// bir seçenek değil (bkz. TestBodyIsBoundToTheSignature).
func TestSignAlwaysSignsThePayloadHash(t *testing.T) {
	req, err := http.NewRequest("PUT", "https://"+tvHost+"/kova/a.cast", nil)
	if err != nil {
		t.Fatal(err)
	}
	sign(req, Credentials{tvAccessKey, tvSecretKey}, tvRegion, tvService, emptyHash(), tvTime(t))

	if req.Header.Get("X-Amz-Content-Sha256") != emptyHash() {
		t.Error("gövde özeti başlığı konmamış")
	}
	if !strings.Contains(req.Header.Get("Authorization"), "x-amz-content-sha256") {
		t.Errorf("gövde özeti imzalanmamış: %q", req.Header.Get("Authorization"))
	}
}

/*
 * ⚠️ YOL KODLAMASI, SESSİZ BOZULMANIN EN OLASI YERİ.
 *
 * Operatörün yazdığı bir önek boşluk ya da Türkçe harf taşıyabilir.
 * url.EscapedPath() ile SigV4'ün istediği kodlama aynı DEĞİL; fark
 * yalnızca imza tutmayınca ortaya çıkar ve sunucu sebebini söylemez.
 */
func TestURIEncodeMatchesTheSpec(t *testing.T) {
	cases := []struct{ in, want string }{
		{"kayitlar", "kayitlar"},
		{"a-b_c.d~e", "a-b_c.d~e"},
		{"bir iki", "bir%20iki"},
		{"şüheda", "%C5%9F%C3%BCheda"},
		{"a+b", "a%2Bb"},
		{"a=b", "a%3Db"},
		{"a/b", "a/b"}, // encodeSlash=false: ayraç korunur
	}
	for _, c := range cases {
		if got := uriEncode(c.in, false); got != c.want {
			t.Errorf("uriEncode(%q) = %q, %q bekleniyordu", c.in, got, c.want)
		}
	}
	// Sorgu bağlamında '/' de kodlanır.
	if got := uriEncode("a/b", true); got != "a%2Fb" {
		t.Errorf("sorgu kodlaması = %q", got)
	}
}

// Yol segmentleri tek tek kodlanmalı, ayraç kodlanmamalı.
func TestCanonicalURIEncodesSegmentsNotSeparators(t *testing.T) {
	req, err := http.NewRequest("PUT",
		"https://"+tvHost+"/kova/bir%20iki/2026-09-02/abc.cast", nil)
	if err != nil {
		t.Fatal(err)
	}
	got := canonicalURI(req.URL)
	const want = "/kova/bir%20iki/2026-09-02/abc.cast"
	if got != want {
		t.Errorf("canonicalURI = %q, %q bekleniyordu", got, want)
	}
}

/*
 * ⚠️ GÖVDE İMZAYA BAĞLI OLMALI.
 *
 * UNSIGNED-PAYLOAD da kabul edilir ve daha kolaydır — ama o zaman
 * araya giren biri gövdeyi değiştirdiğinde imza tutmaya devam eder.
 * Denetim izi taşıdığımız için bu kabul edilemez. Test, farklı
 * gövdenin farklı imza ürettiğini gösteriyor.
 */
func TestBodyIsBoundToTheSignature(t *testing.T) {
	sigFor := func(body string) string {
		req, err := http.NewRequest("PUT", "https://"+tvHost+"/kova/a.cast", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		sign(req, Credentials{tvAccessKey, tvSecretKey}, tvRegion, tvService,
			sha256Hex([]byte(body)), tvTime(t))
		return signatureOf(t, req)
	}

	a := sigFor("kayit bir")
	b := sigFor("kayit iki")
	if a == b {
		t.Fatal("farklı gövdeler aynı imzayı üretti — gövde imzaya bağlı değil")
	}
}

// Authorization imzalanan başlıklara girmemeli (kendi kendine referans).
func TestAuthorizationIsNotSigned(t *testing.T) {
	req, err := http.NewRequest("GET", "https://"+tvHost+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "eski-deger")
	signed, _ := canonicalizeHeaders(req)
	if strings.Contains(signed, "authorization") {
		t.Errorf("imzalanan başlıklar Authorization içeriyor: %q", signed)
	}
}

// Host imzalanmak ZORUNDA: net/http onu Header'da tutmuyor.
func TestHostIsAlwaysSigned(t *testing.T) {
	req, err := http.NewRequest("GET", "https://"+tvHost+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = tvHost
	signed, canonical := canonicalizeHeaders(req)
	if !strings.Contains(signed, "host") {
		t.Errorf("host imzalanmamış: %q", signed)
	}
	if !strings.Contains(canonical, "host:"+tvHost) {
		t.Errorf("kanonik başlıklar host taşımıyor: %q", canonical)
	}
}

/*
 * ⚠️ BAŞLIK DEĞERİNDEKİ ARDIŞIK BOŞLUKLAR DARALTILMALI.
 *
 * SigV4 böyle tanımlı. Tek pratik kurbanı operatörün eliyle yazdığı
 * server_side_encryption değeri: "aws:  kms" yazan biri, sebebi
 * hiçbir yerde yazmayan bir 403 alırdı.
 */
func TestHeaderValuesCollapseInternalSpaces(t *testing.T) {
	cases := map[string]string{
		"aws:kms":    "aws:kms",
		"aws:  kms":  "aws: kms",
		"  AES256  ": "AES256",
		"a   b    c": "a b c",
	}
	for in, want := range cases {
		if got := collapseSpaces(in); got != want {
			t.Errorf("collapseSpaces(%q) = %q, %q bekleniyordu", in, got, want)
		}
	}
}

// Kanonik sorgu KODLANMIŞ anahtara göre sıralanmalı.
func TestCanonicalQuerySortsByEncodedKey(t *testing.T) {
	// Çözülmüş hâlde "a b" < "a-b"; kodlanmış hâlde "a%20b" < "a-b"
	// de doğru, ama sıralamanın hangi biçim üzerinden yapıldığını
	// sabitliyoruz.
	u, err := url.Parse("https://h/?a-b=2&" + url.QueryEscape("a b") + "=1")
	if err != nil {
		t.Fatal(err)
	}
	got := canonicalQuery(u)
	const want = "a%20b=1&a-b=2"
	if got != want {
		t.Errorf("canonicalQuery = %q, %q bekleniyordu", got, want)
	}
}
