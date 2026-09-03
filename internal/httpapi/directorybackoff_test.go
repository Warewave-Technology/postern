package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Warewave-Technology/postern/internal/auth"
	"github.com/Warewave-Technology/postern/internal/ldap"
	"github.com/Warewave-Technology/postern/internal/ldap/ldaptest"
)

/*
 * ⚠️ DİZİN KAPISININ DA ARTAN GECİKMESİ OLMALI.
 *
 * Yerel kapı, TOTP ve anahtar uçları guessBackoff kullanıyordu; dizin
 * kapısı — İNSAN SEÇİMLİ parolayı kabul eden TEK kapı — kullanmıyordu.
 * Sonucu iki katmanlı: kurumsal parola tahmini düz localLimit hızında
 * (her pencerede sıfırlanır) ve her yanlış deneme dizine gerçek bir bind
 * olarak gidip hesabı kilitleme kolu.
 *
 * Test, aynı hesap + aynı adresten üst üste yanlış parolanın 429'a
 * TIRMANDIĞINI ölçüyor. directoryLogin doğrudan çağrılıyor: sınanan şey
 * o fonksiyonun backoff kullanması ve gerçek guessBackoff/clientKey ile
 * (üretim New yapıcısından) koşması.
 */
func TestDirectoryDoorEscalatesOnRepeatedGuesses(t *testing.T) {
	ctx := context.Background()
	db := migratedStore(t)

	// Kullanıcıyı bulan ama bind'i REDDEDEN dizin: yanlış parola tam
	// olarak bu — DN bulunuyor, bind 49 ile düşüyor.
	srv, err := ldaptest.New(func(base, filter string, attrs []string) ldaptest.Response {
		return ldaptest.Response{Entries: []ldaptest.Entry{
			{DN: "cn=ayse,ou=people,dc=test", Attrs: map[string][]string{}},
		}}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.RefuseBindFor("cn=ayse,ou=people,dc=test", 49) // yalnizca kullanici bind'i reddedilsin

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

	attempt := func() int {
		r := httptest.NewRequest(http.MethodPost, "/auth/local", nil)
		r.RemoteAddr = "203.0.113.9:5555"
		w := httptest.NewRecorder()
		s.directoryLogin(w, r, s.logger, "ayse", "yanlis-parola")
		return w.Code
	}

	var codes []int
	for range 10 {
		codes = append(codes, attempt())
	}
	t.Logf("kodlar: %v", codes)

	// İlk denemeler 401 (üç bedava), sonrası 429'a tırmanmalı.
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
		t.Error("dizin kapısı üst üste tahminlerde hiç 429 dönmedi — " +
			"artan gecikme yok; kurumsal parola tahmini ve uzaktan " +
			"hesap kilitleme kolu açık")
	}

	// ⚠️ HESAP KİLİTLEME KOLU: dizine ulaşan KULLANICI bind'i, deneme
	// sayısından belirgin biçimde az olmalı — 429 dönenler bind'e hiç
	// ulaşmıyor. Sayı, tipik bir AD kilitleme eşiğinin (5-10) altında
	// kalmalı.
	userBinds := 0
	for _, dn := range srv.Binds() {
		if dn == "cn=ayse,ou=people,dc=test" {
			userBinds++
		}
	}
	t.Logf("kullanıcı bind'i: %d", userBinds)
	if userBinds >= 10 {
		t.Errorf("dizine ulaşan kullanıcı bind'i = %d; backoff bind'leri "+
			"kesmiyor, uzaktan hesap kilitleme kolu hâlâ açık", userBinds)
	}
}
