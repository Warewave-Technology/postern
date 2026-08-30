package auth

import (
	"errors"
	"testing"
	"time"
)

/*
 * ⚠️ TANINMAYAN DEĞER REDDEDİLİR, BİR VARSAYILANA DÜŞMEZ.
 *
 * Düşseydi: "auth.source = odic" (yazım hatası) yazan bir kurulum,
 * kapatmak istediği yerel kapıyı sessizce açık bulurdu — hata ancak
 * biri o kapıdan girdiğinde, yani asla, fark edilirdi.
 */
func TestParseLoginSource(t *testing.T) {
	ok := map[string]LoginSource{
		"local": SourceLocal, "LOCAL": SourceLocal, "  ldap  ": SourceLDAP,
		"oidc": SourceOIDC, "Oidc": SourceOIDC,
	}
	for in, want := range ok {
		got, err := ParseLoginSource(in)
		if err != nil || got != want {
			t.Fatalf("ParseLoginSource(%q) = %q, %v — %q bekleniyordu", in, got, err, want)
		}
	}

	for _, bad := range []string{"", "odic", "ldaps", "local ldap", "none", "true"} {
		if _, err := ParseLoginSource(bad); !errors.Is(err, ErrUnknownSource) {
			t.Fatalf("ParseLoginSource(%q) kabul edildi (hata: %v)", bad, err)
		}
	}
}

/*
 * ⚠️ "45d" ÇALIŞMAK ZORUNDA — ölçülmüş bir tuzak.
 *
 * time.ParseDuration "d" bilmiyor ve bu ayarların doğal birimi gün.
 * Demo'da ölçüldü: "45d" kaydediliyor, çözümlenemiyor, sessizce
 * varsayılana düşüyor ve operatör yazdığının anlaşıldığını sanıyor. En
 * kötü hâli "365d" yazıp korumanın 45 günde çalıştığını fark etmemek.
 */
func TestParseAccountDuration(t *testing.T) {
	ok := map[string]time.Duration{
		"45d":  45 * 24 * time.Hour,
		"1d":   24 * time.Hour,
		"720h": 720 * time.Hour,
		"90m":  90 * time.Minute,
		// "0" KAPALI demek ve bilinçli bir karar.
		"0": 0,
		// Boşluk kırpılıyor: kopyala-yapıştır bir ayarı bozmasın.
		"  30d  ": 30 * 24 * time.Hour,
	}
	for in, want := range ok {
		got, err := ParseAccountDuration(in)
		if err != nil || got != want {
			t.Fatalf("ParseAccountDuration(%q) = %v, %v — %v bekleniyordu", in, got, err, want)
		}
	}

	// ⚠️ Anlaşılmayan değer REDDEDİLİR. Sessizce varsayılana düşmek,
	// operatörün yazdığından başka bir şey uygulamak demekti.
	for _, bad := range []string{"", "45 gün", "kırk", "-5d", "d", "45x", "-1h"} {
		if got, err := ParseAccountDuration(bad); err == nil {
			t.Fatalf("ParseAccountDuration(%q) = %v — reddedilmeliydi", bad, got)
		}
	}
}
