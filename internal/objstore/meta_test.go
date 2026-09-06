package objstore

import (
	"net/http"
	"strings"
	"testing"
)

/*
 * ⚠️ ÜSTVERİ İMZANIN İÇİNDE OLMALI.
 *
 * Kayıt zincirinin başı nesnenin x-amz-meta-* üstverisinde taşınıyor ve
 * bunun tek anlamı imzalanmış olması. İmza dışında kalsaydı, aradaki bir
 * taraf başı değiştirip nesneyi değiştirilmemiş gösterebilirdi — yani
 * kanıt diye taşıdığımız şey, taşınırken sessizce değiştirilebilir
 * olurdu.
 *
 * canonicalizeHeaders bugün istekteki HER başlığı imzalıyor; bu test o
 * davranışın üstveri için de sürdüğünü çiviliyor. Bir gün biri imzayı
 * beyaz listeye çevirirse (ki SigV4 buna izin veriyor), zincir sessizce
 * korumasız kalır.
 */
func TestObjectMetadataIsSigned(t *testing.T) {
	req, err := http.NewRequest("PUT", "https://"+tvHost+"/kova/kayit.cast", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = tvHost
	req.Header.Set("X-Amz-Meta-Postern-Chain", "abc123")
	req.Header.Set("X-Amz-Meta-Postern-Links", "42")

	signed, canonical := canonicalizeHeaders(req)

	for _, want := range []string{"x-amz-meta-postern-chain", "x-amz-meta-postern-links"} {
		if !strings.Contains(signed, want) {
			t.Errorf("%q imzalı başlıklar arasında yok: %q", want, signed)
		}
		if !strings.Contains(canonical, want+":") {
			t.Errorf("%q kanonik başlıklarda yok", want)
		}
	}
	if !strings.Contains(canonical, "x-amz-meta-postern-chain:abc123") {
		t.Errorf("zincir başının DEĞERİ imzaya girmemiş: %q", canonical)
	}
}
