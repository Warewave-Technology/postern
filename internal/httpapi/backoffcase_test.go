package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/ldap"
	"github.com/warewave/postern/internal/ldap/ldaptest"
)

/*
 * ⚠️ GECİKME KOVASI, ADIN YAZIMIYLA BÖLÜNMEMELİ.
 *
 * Hesap her yerde harf duyarsız çözülüyor (users.username 019'dan beri
 * harf duyarsız tekil, sorgular ciEq kullanıyor, dizinler
 * caseIgnoreMatch). Kova ham adı anahtarlarken bir hesap, adının yazım
 * sayısı kadar ayrı kova alıyordu: "admin", "Admin", "aDmin"... Sekiz
 * harfli bir ad için 256 bedava merdiven.
 *
 * Bu, saldırganın SEÇTİĞİ bir alandaki tek harfin büyüklüğünü
 * değiştirerek atlanabilen bir denetimdi — hem kodda hem testlerinde
 * "var" görünüyordu.
 */
func TestBackoffBucketIsNotSplitByLetterCase(t *testing.T) {
	b := newGuessBackoff()
	now := time.Now()
	b.now = func() time.Time { return now }

	const addr = "203.0.113.9"

	// Saldırgan bir yazımla merdiveni tırmandırıyor.
	for range 12 {
		b.fail(backoffKey("operator", addr))
	}
	if b.retryAfter(backoffKey("operator", addr)) <= 0 {
		t.Fatal("aynı yazımda bile gecikme yok — kurgu tutmadı")
	}

	// ⚠️ Sonra yazımı döndürüyor. Aynı hesap, aynı adres: gecikme
	// AYNEN geçerli olmalı.
	for _, yazim := range []string{"Operator", "OPERATOR", "oPeRaToR", "operatoR"} {
		if d := b.retryAfter(backoffKey(yazim, addr)); d <= 0 {
			t.Errorf("%q yazımı bedava merdiven aldı (gecikme %v) — "+
				"saldırgan adın büyük/küçük harfini değiştirerek "+
				"gecikmeyi sıfırlıyor", yazim, d)
		}
	}
}

/*
 * ⚠️ AYNISI GERÇEK KAPIDA: yazımı döndürmek dizin kapısını da açmamalı.
 *
 * Ölçülen arıza tam olarak buydu — sabit yazımla 4 bind dizine
 * gidiyordu, döndürülmüş yazımla 10: hem saatte 600 parola tahmini geri
 * geliyordu hem de postern yeniden uzaktan hesap kilitleme kolu
 * oluyordu (tipik AD eşiği 5-10).
 *
 * Sahte dizin adı HARF DUYARSIZ eşliyor: gerçek dizinlerin uid ve
 * sAMAccountName için yaptığı şey bu (dialect.go:226 aynı varsayımı
 * yazıyor). Yani döndürülmüş yazımlar decoy değil, aynı DN'e karşı
 * gerçek tahminler.
 */
func TestDirectoryDoorThrottlesDespiteRotatedSpelling(t *testing.T) {
	ctx := context.Background()
	db := migratedStore(t)

	const userDN = "cn=ayse,ou=people,dc=test"
	srv, err := ldaptest.New(func(base, filter string, attrs []string) ldaptest.Response {
		// caseIgnoreMatch: filtrede adın hangi yazımı gelirse gelsin
		// aynı girdi dönüyor.
		if !strings.Contains(strings.ToLower(filter), "cn=ayse") {
			return ldaptest.Response{}
		}
		return ldaptest.Response{Entries: []ldaptest.Entry{
			{DN: userDN, Attrs: map[string][]string{}},
		}}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.RefuseBindFor(userDN, 49)

	set := func(k, v string) {
		if err := db.SetSetting(ctx, k, v, false, "test"); err != nil {
			t.Fatal(err)
		}
	}
	set(auth.KeyLoginSource, "ldap")
	set(ldap.KeyURL, srv.URL())
	set(ldap.KeyBindDN, "cn=okuyucu,dc=test")
	set(ldap.KeyBindPassword, "s")
	set(ldap.KeyUserBase, "ou=people,dc=test")
	set(ldap.KeyUserFilter, "(cn=%s)")
	set(ldap.KeyGroupBase, "ou=groups,dc=test")
	set(ldap.KeyGroupFilter, "(member=%s)")

	s := New(auth.NewOIDCHolder(), auth.NewLogins(auth.NewOIDCHolder()), db,
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Her denemede farklı bir yazım — saldırganın yapacağı şey.
	yazimlar := []string{
		"ayse", "Ayse", "aYse", "aySe", "aysE",
		"AYse", "AySe", "AYSE", "aYSe", "AySE",
	}
	var codes []int
	for _, ad := range yazimlar {
		r := httptest.NewRequest(http.MethodPost, "/auth/local", nil)
		r.RemoteAddr = "203.0.113.9:5555"
		w := httptest.NewRecorder()
		s.directoryLogin(w, r, s.logger, ad, "yanlis-parola")
		codes = append(codes, w.Code)
	}
	t.Logf("kodlar: %v", codes)

	if codes[0] != http.StatusUnauthorized {
		t.Fatalf("ilk deneme = %d, 401 bekleniyordu (kurgu tutmadı)", codes[0])
	}
	throttled := false
	for _, c := range codes {
		if c == http.StatusTooManyRequests {
			throttled = true
		}
	}
	if !throttled {
		t.Error("yazım döndürülünce hiç 429 gelmedi — gecikme merdiveni " +
			"her yazımda sıfırlanıyor")
	}

	userBinds := 0
	for _, dn := range srv.Binds() {
		if dn == userDN {
			userBinds++
		}
	}
	t.Logf("kullanıcı bind'i: %d", userBinds)
	if userBinds >= 10 {
		t.Errorf("dizine ulaşan kullanıcı bind'i = %d/10; yazım döndürerek "+
			"kilitleme kolu geri geliyor", userBinds)
	}
}
