package httpapi

import (
	"strings"
	"testing"
	"time"

	"github.com/warewave/postern/internal/auth"
)

/*
 * Sahte doğrulayıcı BİÇİM OLARAK GEÇERLİ olmak zorunda.
 *
 * Geçersiz olsaydı VerifyLocalSecret onu ayrıştıramayıp erken dönerdi:
 * argon2 hiç çalışmaz, yanıt gözle görülür biçimde hızlanır ve "bu
 * kullanıcı yok" bilgisi tam da gizlemeye çalıştığımız yerden sızardı.
 */
func TestDecoyVerifierIsWellFormed(t *testing.T) {
	d := decoyVerifier()
	if !strings.HasPrefix(d, "argon2id$") || strings.Count(d, "$") != 4 {
		t.Fatalf("sahte doğrulayıcı biçimi bozuk: %q", d)
	}

	secret, _, err := auth.NewLocalSecret()
	if err != nil {
		t.Fatal(err)
	}
	// Uymamalı — ama ayrıştırılabildiği için GERÇEK iş yaparak uymamalı.
	if auth.VerifyLocalSecret(d, secret) {
		t.Fatal("sahte doğrulayıcı bir sırrı kabul etti")
	}

	// Ölçüm: gerçek bir doğrulayıcıya karşı yapılan yanlış denemeyle
	// aynı büyüklük sırasında sürmeli. Erken dönen bir yol
	// mikrosaniyelerde biterdi.
	_, real, err := auth.NewLocalSecret()
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	auth.VerifyLocalSecret(real, secret)
	realCost := time.Since(start)

	start = time.Now()
	auth.VerifyLocalSecret(d, secret)
	decoyCost := time.Since(start)

	if decoyCost < realCost/4 {
		t.Fatalf("sahte doğrulama %v, gerçeği %v — erken dönüyor ve "+
			"kullanıcı varlığını sızdırır", decoyCost, realCost)
	}
}

// Hız sınırı penceresi: kota dolunca reddetmeli, pencere dönünce
// yeniden açmalı.
func TestLocalLimiterWindow(t *testing.T) {
	now := time.Now()
	l := newLocalLimiter()
	l.now = func() time.Time { return now }

	for i := range localLoginPerIP {
		if !l.allow("1.2.3.4") {
			t.Fatalf("%d. deneme kotanın içindeyken reddedildi", i+1)
		}
	}
	if l.allow("1.2.3.4") {
		t.Fatal("kota aşıldığı hâlde kabul edildi")
	}
	// Başka bir kaynak etkilenmemeli.
	if !l.allow("5.6.7.8") {
		t.Fatal("bir kaynağın kotası diğerini kapattı")
	}

	now = now.Add(time.Minute)
	if !l.allow("1.2.3.4") {
		t.Fatal("pencere dönmesine rağmen hâlâ kapalı")
	}
}
