package auth

import (
	"errors"
	"testing"
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
