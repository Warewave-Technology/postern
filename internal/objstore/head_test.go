package objstore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

/*
 * ⚠️ BU DOSYANIN ÖLÇTÜĞÜ ŞEY, ZİNCİRİN KUTU DIŞI KOPYASININ OKUNABİLMESİ.
 *
 * Zincir başı yüklenirken nesnenin üstverisine yazılıyor ve o kopya,
 * bastion'da root olan birinin ulaşamadığı tek yer. Ama Head yalnızca
 * boyut döndürdüğü sürece hiç kimse onu okumuyordu: yazılan ama
 * okunmayan bir kanıt, kanıt değil.
 */

// headServer, verilen başlıklarla cevap veren sahte bir S3.
func headServer(t *testing.T, headers map[string]string) *Client {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("beklenen HEAD, gelen %s", r.Method)
		}
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	c, err := New(Config{
		Endpoint: srv.URL, Region: "us-east-1", Bucket: "kayitlar",
		Credentials: Credentials{AccessKeyID: "AK", SecretAccessKey: "SK"},
	})
	if err != nil {
		t.Fatal(err)
	}

	return c
}

func TestHeadReturnsTheChainHead(t *testing.T) {
	c := headServer(t, map[string]string{
		"x-amz-meta-postern-chain": "abc123",
		"x-amz-meta-postern-links": "42",
	})

	info, err := c.Head(context.Background(), "gun/kayit.cast")
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if got := info.Meta[MetaChain]; got != "abc123" {
		t.Errorf("zincir başı = %q, abc123 bekleniyordu", got)
	}
	if got := info.Meta[MetaLinks]; got != "42" {
		t.Errorf("halka sayısı = %q", got)
	}
}

/*
 * ⚠️ ANAHTAR KUTUSU NORMALLEŞTİRİLMELİ.
 *
 * S3 kullanıcı üstverisini küçük harfe çeviriyor, araya giren vekiller de
 * başlık kutusunu değiştirebiliyor. Yazan taraf "Postern-Chain" yazıyor;
 * okuyan taraf "Postern-Chain" arasa, gelen "X-Amz-Meta-Postern-Chain"i
 * bulamaz ve sonuç "üstveri yok" olur — yani var olan bir kanıt
 * SESSİZCE yok sayılır ve doğrulama "bakamadım" der.
 */
func TestMetadataKeysAreCaseInsensitive(t *testing.T) {
	for _, header := range []string{
		"X-Amz-Meta-Postern-Chain",
		"x-amz-meta-postern-chain",
		"X-AMZ-META-POSTERN-CHAIN",
	} {
		t.Run(header, func(t *testing.T) {
			c := headServer(t, map[string]string{header: "deadbeef"})
			info, err := c.Head(context.Background(), "k")
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Meta[MetaChain]; got != "deadbeef" {
				t.Errorf("%q başlığı okunamadı: %q", header, got)
			}
		})
	}
}

// Üstverisi olmayan nesne BOŞ dönmeli, hata değil: zincirlerden önce
// yüklenmiş bir kayıt kurcalanmış bir kayıtla aynı şey değil.
func TestHeadWithoutMetadataIsNotAnError(t *testing.T) {
	c := headServer(t, nil)

	info, err := c.Head(context.Background(), "eski.cast")
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if got := info.Meta[MetaChain]; got != "" {
		t.Errorf("olmayan üstveri %q döndü", got)
	}
}

// Üstveri OLMAYAN başlıklar sızmamalı: nesnenin ETag'i ya da içerik
// tipi, zincir başı aranan bir haritada işi olmayan şeyler.
func TestOnlyUserMetadataIsReturned(t *testing.T) {
	c := headServer(t, map[string]string{
		"x-amz-meta-postern-chain": "abc",
		"ETag":                     `"deadbeef"`,
		"x-amz-request-id":         "R1",
	})

	info, err := c.Head(context.Background(), "k")
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Meta) != 1 {
		t.Errorf("üstveri haritasında fazladan alan var: %v", info.Meta)
	}
}
