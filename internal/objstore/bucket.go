package objstore

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

/*
 * Kovanın SÖYLEDİĞİ yapılandırma — salt okunur.
 *
 * ⚠️ BUNLAR GÜVENLİK KONTROLÜ DEĞİL, YANLIŞ YAPILANDIRMA DEDEKTÖRÜ.
 * Sorgular bastion'da çalışıyor; saldırganın ele geçirdiği makine de o.
 * Yani buradan dönen "sürümleme açık" cevabı, saldırgan altında da aynı
 * cevabı verirdi. Faydası operatörün kurulumunu doğru yaptığını
 * görmesi — saldırıya karşı bir savunma değil ve komut da öyle
 * söylüyor.
 *
 * ⚠️ SİLME YETENEĞİ EKLENMEDİ. Kimliğin silme hakkı olup olmadığını
 * kesin öğrenmenin tek yolu bir nesne yazıp silmeyi denemek; bu, bu
 * pakete silme yeteneği koymayı gerektirirdi ve paketin kendi
 * gerekçesini bozardı (client.go'daki nota bak).
 *
 * Ve gerekmiyor: compliance kipinde Object Lock + varsayılan saklama
 * varsa nesne IAM'den BAĞIMSIZ olarak silinemiyor — yani asıl bilinmesi
 * gereken silme yetkisi değil, kilidin durumu. Rapor onu veriyor.
 */

// CodeError, S3'ün <Code> alanını taşıyan hata.
type CodeError struct {
	Code   string
	Status int
	Err    error
}

func (e *CodeError) Error() string {
	return fmt.Sprintf("objstore: http %d: %s", e.Status, e.Code)
}
func (e *CodeError) Unwrap() error { return e.Err }

// CodeOf, hatadan S3 kodunu çıkarır ("NoSuchBucket", "AccessDenied"...).
func CodeOf(err error) (string, bool) {
	var ce *CodeError
	if errors.As(err, &ce) {
		return ce.Code, true
	}
	return "", false
}

// Versioning, kovanın sürümleme durumu.
//
// Boş dize = hiç açılmamış. S3 bu durumda 200 ve BOŞ bir belge
// döndürüyor; "kapalı" ile "okuyamadım" bu yüzden karışmıyor.
func (c *Client) Versioning(ctx context.Context) (string, error) {
	var doc struct {
		Status string `xml:"Status"`
	}
	if err := c.getBucketSubresource(ctx, "versioning", &doc); err != nil {
		return "", err
	}
	return doc.Status, nil
}

// ObjectLock, kovanın Object Lock yapılandırması.
type ObjectLock struct {
	Enabled bool
	// Mode: "GOVERNANCE" ya da "COMPLIANCE". Boş = varsayılan saklama
	// tanımlı değil, yani kilit açık ama SÜRE YOK.
	Mode  string
	Days  int
	Years int
}

/*
 * ObjectLockConfig, kilidi okur.
 *
 * ⚠️ "Kilit açık ama varsayılan saklama yok" AYRI BİR DURUM ve rapor
 * onu ayrı gösteriyor: o hâlde her nesnenin kendi saklama süresini
 * istekle belirtmesi gerekir — ve postern bilerek belirtmiyor, çünkü
 * kimliği ele geçiren onu sıfır da yapabilirdi. Yani kilit var ama
 * hiçbir şeyi korumuyor.
 */
func (c *Client) ObjectLockConfig(ctx context.Context) (ObjectLock, error) {
	var doc struct {
		ObjectLockEnabled string `xml:"ObjectLockEnabled"`
		Rule              struct {
			DefaultRetention struct {
				Mode  string `xml:"Mode"`
				Days  int    `xml:"Days"`
				Years int    `xml:"Years"`
			} `xml:"DefaultRetention"`
		} `xml:"Rule"`
	}
	if err := c.getBucketSubresource(ctx, "object-lock", &doc); err != nil {
		return ObjectLock{}, err
	}
	return ObjectLock{
		Enabled: doc.ObjectLockEnabled == "Enabled",
		Mode:    doc.Rule.DefaultRetention.Mode,
		Days:    doc.Rule.DefaultRetention.Days,
		Years:   doc.Rule.DefaultRetention.Years,
	}, nil
}

// Encryption, kovanın varsayılan sunucu tarafı şifrelemesi.
// Boş dize = varsayılan tanımlı değil.
func (c *Client) Encryption(ctx context.Context) (string, error) {
	var doc struct {
		Rule struct {
			Default struct {
				Algorithm string `xml:"SSEAlgorithm"`
			} `xml:"ApplyServerSideEncryptionByDefault"`
		} `xml:"Rule"`
	}
	if err := c.getBucketSubresource(ctx, "encryption", &doc); err != nil {
		return "", err
	}
	return doc.Rule.Default.Algorithm, nil
}

// getBucketSubresource, GET /{bucket}?<name> çağırır ve XML'i çözer.
func (c *Client) getBucketSubresource(ctx context.Context, name string, out any) error {
	u := *c.base
	u.Path = "/" + c.cfg.Bucket
	u.RawQuery = name

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("objstore.%s: %w", name, err)
	}
	sign(req, c.cfg.Credentials, c.cfg.Region, "s3", sha256Hex(nil), time.Now())

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("objstore.%s: %w: %v", name, ErrTransient, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// ⚠️ KOD KORUNUYOR: çağıran "okuma yetkim yok" ile "böyle bir
		// yapılandırma yok"u ayırt edebilmeli. İkisini tek bir hataya
		// toplamak, raporun en önemli ayrımını yok ederdi.
		code := errorCode(resp.Body)
		base := ErrPermanent
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			base = ErrTransient
		}
		return &CodeError{Code: code, Status: resp.StatusCode, Err: base}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return fmt.Errorf("objstore.%s: %w", name, err)
	}
	if len(body) == 0 {
		// Boş belge: yapılandırma yok. Hata değil.
		return nil
	}
	if err := xml.Unmarshal(body, out); err != nil {
		return fmt.Errorf("objstore.%s: could not parse the response: %w", name, err)
	}
	return nil
}
