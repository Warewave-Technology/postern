package objstore

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

/*
 * S3 uyumlu nesne deposuna tek nesne yazan istemci.
 *
 * Kapsam kasten dar: PUT ve HEAD. Liste, silme, çok parçalı yükleme ve
 * ön imzalı bağlantı YOK — çünkü postern'in ihtiyacı "bu dosyayı oraya
 * koy ve orada olduğunu doğrula"dan ibaret. Yazılmayan her uç, yanlış
 * yapılandırıldığında zarar verebilecek bir yetki daha demek.
 *
 * ⚠️ SİLME YOK ve bu bir güvenlik kararı: bastion'ı ele geçiren
 * saldırgan yükleme kimliğini de ele geçirir. postern'in kendisinde
 * silme yeteneği olmaması, o kimliğe silme yetkisi VERİLMEMESİ
 * gerektiğini kodda da söylüyor.
 */

// Yükleme hataları.
var (
	// ErrTransient: geçici; yeniden denenmeli (ağ, zaman aşımı, 5xx, 429).
	ErrTransient = errors.New("objstore: temporary failure")

	// ErrPermanent: yapılandırma ya da yetki hatası; yeniden denemek
	// aynı sonucu verir ve operatörün müdahalesi gerekir.
	//
	// ⚠️ AYRIM ÖNEMLİ: ikisini birleştirmek ya yanlış kimlikle sonsuza
	// dek denemek (gürültü) ya da geçici bir kesintide pes etmek
	// (kanıt kaybı) demekti.
	ErrPermanent = errors.New("objstore: permanent failure")

	// ErrTooLarge: tek PUT'un sınırını aşan nesne.
	ErrTooLarge = errors.New("objstore: object exceeds the single-PUT limit")
)

// maxSinglePut, S3'ün tek PUT sınırı (5 GiB).
//
// ⚠️ AŞILDIĞINDA SESSİZ KALINMIYOR. Çok parçalı yükleme yazmadık
// (ölçüldü: kayıt boyutu ≈ terminal çıktısı, 5 GB'a ulaşmak için bir
// oturumun 5 GB basması gerek) ama sınır aşıldığında dosya YEREL
// KALIYOR ve sebebi kaydediliyor — yükleyemediğimiz bir kanıtı
// yüklenmiş saymak, budayıcının onu silmesine izin vermek olurdu.
const maxSinglePut = 5 << 30

// Config, istemcinin hedefi.
type Config struct {
	// Endpoint, deponun kök adresi ("https://s3.eu-central-1.amazonaws.com"
	// ya da "https://minio.ic:9000").
	Endpoint string
	Region   string
	Bucket   string

	// CAFile, şirket içi bir depo kendi kökünü kullanıyorsa.
	CAFile string

	Credentials Credentials

	// Timeout, tek bir isteğin üst sınırı.
	Timeout time.Duration

	/*
	 * ServerSideEncryption, x-amz-server-side-encryption başlığının
	 * değeri ("AES256", "aws:kms"). BOŞ = başlık gönderilmiyor.
	 *
	 * ⚠️ VARSAYILAN BOŞ ve bu ÖLÇÜLDÜKTEN SONRA böyle. İlk hâli
	 * koşulsuz "AES256" gönderiyordu; KMS yapılandırılmamış bir MinIO
	 * buna 501 NotImplemented ile cevap veriyor ("Server side
	 * encryption specified but KMS is not configured"). Yani şirket
	 * içi kurulumların çoğunda hiçbir kayıt yüklenemezdi ve sebebi
	 * postern'in istemediği bir şeyi ısrarla istemesi olurdu.
	 *
	 * İstemenin faydası da sınırlı: bastion'ı ele geçiren yükleme
	 * kimliğini de ele geçiriyor, yani sunucu tarafı şifreleme O
	 * saldırgana karşı hiçbir şey yapmıyor. Kapattığı şey deponun
	 * diskine başka bir yoldan erişen biri — ve AWS S3'te kovalar
	 * 2023'ten beri zaten varsayılan olarak şifreli.
	 *
	 * Doğru yer kovanın kendi ayarı; postern istemiyor, isteyen
	 * operatör buraya yazıyor.
	 */
	ServerSideEncryption string
}

// Client, yapılandırılmış bir nesne deposu istemcisi.
type Client struct {
	cfg  Config
	base *url.URL
	http *http.Client
}

/*
 * New, istemciyi kurar ve YAPILANDIRMAYI BAŞLANGIÇTA doğrular.
 *
 * ⚠️ Hatalar burada veriliyor, ilk yüklemede değil: yanlış yazılmış bir
 * uç adresi, kurulumdan saatler sonra "yükleme başarısız" satırları
 * olarak görünseydi, operatör sebebi aramak zorunda kalırdı.
 */
func New(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" || cfg.Bucket == "" {
		return nil, fmt.Errorf("objstore.New: endpoint and bucket are required")
	}
	if cfg.Credentials.AccessKeyID == "" || cfg.Credentials.SecretAccessKey == "" {
		return nil, fmt.Errorf("objstore.New: credentials are required")
	}
	if cfg.Region == "" {
		// S3 uyumlu depoların çoğu bölgeyi umursamıyor ama imza onu
		// içeriyor; boş bırakmak "SignatureDoesNotMatch" olarak dönerdi.
		cfg.Region = "us-east-1"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}

	if err := checkEndpointScheme(cfg.Endpoint); err != nil {
		return nil, fmt.Errorf("objstore.New: %w", err)
	}

	base, err := url.Parse(strings.TrimRight(cfg.Endpoint, "/"))
	if err != nil {
		return nil, fmt.Errorf("objstore.New: %w", err)
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, rerr := os.ReadFile(cfg.CAFile)
		if rerr != nil {
			return nil, fmt.Errorf("objstore.New: ca_file: %w", rerr)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("objstore.New: ca_file %s has no usable certificate", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	}

	return &Client{
		cfg:  cfg,
		base: base,
		http: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},

			/*
			 * ⚠️ YÖNLENDİRME TAKİP EDİLMİYOR.
			 *
			 * Go'nun varsayılanı 301'i izliyor VE PUT'u GET'e
			 * çeviriyor; üstelik host değişirse Authorization'ı
			 * düşürüyor. Sonuç: yanlış yazılmış bir bölge, 301
			 * olarak değil "AccessDenied" olarak görünüyor ve
			 * operatör kimlik bilgilerini kontrol etmeye gidiyor —
			 * oysa sorun tek bir yapılandırma satırında.
			 *
			 * Cevabı olduğu gibi alıyoruz; classify 301'i kalıcı
			 * sayıyor ve x-amz-bucket-region başlığından doğru
			 * bölgeyi söylüyor.
			 */
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

/*
 * checkEndpointScheme, düz metni yalnızca loopback'te kabul eder.
 *
 * ⚠️ insecure_skip_verify YOK ve bilerek yok. Kayıtlar oturumun
 * tamamını taşıyor; doğrulanmamış bir TLS bağlantısına yazmak, denetim
 * izini araya girene teslim etmenin en sessiz yolu. Şirket içi bir
 * depo için doğru cevap kendi kökünü tanıtmak (ca_file), sertifika
 * kontrolünü kapatmak değil. Gerekçe ldap.go'daki checkScheme ile
 * aynı; oradaki loopback istisnası burada da geçerli, çünkü aynı
 * makinedeki bir MinIO ile konuşmak ağa çıkmıyor.
 */
func checkEndpointScheme(raw string) error {
	scheme, rest, found := strings.Cut(raw, "://")
	if !found {
		return fmt.Errorf("endpoint must start with https:// (got %q)", raw)
	}
	switch strings.ToLower(scheme) {
	case "https":
		return nil
	case "http":
		if !isLoopbackHost(rest) {
			return fmt.Errorf("plain http:// is only allowed for loopback; "+
				"use https://, and point ca_file at your own root if the "+
				"certificate is private (got %q)", raw)
		}
		return nil
	default:
		return fmt.Errorf("unsupported endpoint scheme %q; use https://", scheme)
	}
}

func isLoopbackHost(rest string) bool {
	host := rest
	if i := strings.IndexAny(host, "/?"); i >= 0 {
		host = host[:i]
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Put, dosyayı verilen anahtara yazar ve orada olduğunu DOĞRULAR.
//
// Dönen sha256, gönderilen içeriğin özeti: çağıran bunu denetim
// kaydına yazıyor.
func (c *Client) Put(ctx context.Context, key string, f *os.File, size int64) (sha256hex string, err error) {
	if size > maxSinglePut {
		return "", fmt.Errorf("objstore.Put %s: %d bytes: %w", key, size, ErrTooLarge)
	}

	/*
	 * ⚠️ DOSYA İKİ KEZ OKUNUYOR: bir kez özet için, bir kez gövde için.
	 *
	 * SigV4 gövde özetini imzanın İÇİNE koyuyor, yani göndermeden önce
	 * bilinmesi gerekiyor. Alternatif UNSIGNED-PAYLOAD'dı ve o, gövdeyi
	 * imzadan koparırdı (bkz. sigv4.go). Bellekte tutmak da seçenek
	 * değil: kayıt dosyası büyük olabilir. İki geçiş, yerel diskte
	 * ucuz ve doğru olan.
	 */
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return "", fmt.Errorf("objstore.Put %s: hashing: %w", key, err)
	}
	digest := sum.Sum(nil)
	sha256hex = hex.EncodeToString(digest)

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("objstore.Put %s: rewind: %w", key, err)
	}

	u := *c.base
	u.Path = "/" + c.cfg.Bucket + "/" + strings.TrimLeft(key, "/")

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), f)
	if err != nil {
		return "", fmt.Errorf("objstore.Put %s: %w", key, err)
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/x-asciicast")

	// Bozulma kontrolü — bütünlük mührü DEĞİL. Depo, yazdığı baytların
	// gönderdiklerimizle aynı olduğunu bununla doğruluyor; bastion'ı ele
	// geçiren biri her ikisini de üretebilir.
	req.Header.Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(digest))

	// Yalnızca operatör istediyse (bkz. Config.ServerSideEncryption).
	if c.cfg.ServerSideEncryption != "" {
		req.Header.Set("X-Amz-Server-Side-Encryption", c.cfg.ServerSideEncryption)
	}

	// ⚠️ Object Lock başlığı GÖNDERMİYORUZ. Saklama süresini istek
	// belirleseydi, kimliği ele geçiren onu sıfır da yapabilirdi.
	// Koruma kovanın VARSAYILAN saklama ayarından gelmeli — postern'in
	// isteyebileceği bir şey değil.

	sign(req, c.cfg.Credentials, c.cfg.Region, "s3", sha256hex, time.Now())

	resp, err := c.http.Do(req)
	if err != nil {
		// Ağ hatası: geçici. Kimlik ya da adres yanlışsa sunucu cevap
		// verirdi; buraya düşen "ulaşamadım".
		return "", fmt.Errorf("objstore.Put %s: %w: %v", key, ErrTransient, err)
	}
	defer resp.Body.Close()

	if err := classify(key, resp); err != nil {
		return "", err
	}
	return sha256hex, nil
}

/*
 * Head, nesnenin orada olduğunu ve boyutunun beklenen olduğunu doğrular.
 *
 * ⚠️ PUT'un 200 dönmesi yetmiyor. "yüklendi" damgasını vurup budayıcıya
 * silme izni vermeden önce, deponun nesneyi GERÇEKTEN tuttuğunu ondan
 * duymak istiyoruz — bizim istemcimizin başarı dediği şeyden bağımsız
 * bir teyit. Sıra: yükle → doğrula → damgala → silmeye izin ver.
 */
func (c *Client) Head(ctx context.Context, key string) (size int64, err error) {
	u := *c.base
	u.Path = "/" + c.cfg.Bucket + "/" + strings.TrimLeft(key, "/")

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
	if err != nil {
		return 0, fmt.Errorf("objstore.Head %s: %w", key, err)
	}
	sign(req, c.cfg.Credentials, c.cfg.Region, "s3", sha256Hex(nil), time.Now())

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("objstore.Head %s: %w: %v", key, ErrTransient, err)
	}
	defer resp.Body.Close()

	if err := classify(key, resp); err != nil {
		return 0, err
	}
	return resp.ContentLength, nil
}

/*
 * classify, HTTP durumunu geçici/kalıcı olarak ayırır.
 *
 * ⚠️ GÖVDEDEN YALNIZCA <Code> ALINIYOR — HAM GÖVDE DEĞİL.
 *
 * İlk hâli 512 baytlık bir alıntıyı hataya koyuyordu ve yorumu "sır
 * taşımıyor" diyordu. YANLIŞTI: AWS'nin SignatureDoesNotMatch cevabı
 * <AWSAccessKeyId>, <StringToSign> ve <CanonicalRequest> alanlarını
 * içeriyor. O hata metni archive.fail üzerinden slog'a gidiyor, yani
 * imzalama girdisi log dosyasına düşerdi.
 *
 * <Code> sınırlı bir küme ("NoSuchBucket", "AccessDenied",
 * "RequestTimeTooSkewed"...) ve operatörün ihtiyacı olan tam olarak o:
 * çıplak bir 403, dört ayrı düzeltme gerektiren dört ayrı durumu
 * kapsıyor. Aynı gerekçe discover/proxmox.go'da da uygulanmış.
 *
 * ⚠️ OKUNAMAYAN GÖVDE "kod yok" DİYE GÖSTERİLMİYOR: çözülemedi ile
 * gönderilmedi ayrı şeyler.
 */
func classify(key string, resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	detail := errorCode(resp.Body)

	// Bölge yanlışsa S3 doğrusunu BAŞLIKTA söylüyor. HEAD cevabının
	// gövdesi hiç yok, yani bu tek ipucu.
	if r := resp.Header.Get("X-Amz-Bucket-Region"); r != "" {
		detail += " (bucket region is " + r + ")"
	}

	switch {
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return fmt.Errorf("objstore %s: http %d: %w: %s",
			key, resp.StatusCode, ErrTransient, detail)
	default:
		// 403 yanlış kimlik, 404 yok olan kova, 400 bozuk istek,
		// 301 yanlış bölge. Hiçbiri tekrar denemeyle düzelmiyor.
		return fmt.Errorf("objstore %s: http %d: %w: %s",
			key, resp.StatusCode, ErrPermanent, detail)
	}
}

// errorCode, S3 hata gövdesinden YALNIZCA <Code> alanını çıkarır.
func errorCode(body io.Reader) string {
	var parsed struct {
		Code string `xml:"Code"`
	}
	// Sınırlı okuma: gövde megabaytlarca olabilir.
	raw, err := io.ReadAll(io.LimitReader(body, 4096))
	if err != nil {
		return "(error body could not be read)"
	}
	if len(raw) == 0 {
		return "(no error body)"
	}
	if xerr := xml.Unmarshal(raw, &parsed); xerr != nil || parsed.Code == "" {
		// ⚠️ "kod yok" DEMİYORUZ: çözemedik.
		return "(error code could not be parsed)"
	}
	return parsed.Code
}

// Bucket, yapılandırılmış kova adı — arşivleyici bunu denetim
// kaydına yazıyor.
func (c *Client) Bucket() string { return c.cfg.Bucket }

/*
 * SignForTest, testin isteği bizim imzamızla imzalamasına izin verir.
 *
 * ⚠️ YALNIZCA TESTLER İÇİN ve gerekçesi bağımsız tanık: arşivlenmiş
 * bir nesnenin varlığını postern'in KENDİ Put/Head'iyle doğrulamak,
 * "depoda duruyor" ile "istemcimiz duruyor sanıyor"u ayırt edemezdi.
 * Test düz bir http.Client kuruyor ve yalnızca imzayı buradan alıyor.
 */
func (c *Client) SignForTest(req *http.Request, payloadHash string) {
	sign(req, c.cfg.Credentials, c.cfg.Region, "s3", payloadHash, time.Now())
}
