package ldap

import (
	"context"
	"errors"
	"testing"
)

/*
 * ⚠️ EN ÖNEMLİ TEST: BOŞ PAROLA BIND'E HİÇ ULAŞMAMALI.
 *
 * LDAP'ta boş parolayla bind, ANONİM bind demektir ve çoğu sunucuda
 * BAŞARILI olur. Boş parolayı olduğu gibi geçirmek, "parola alanını boş
 * bırakan herkes içeri girer" demekti — kimlik doğrulamanın tamamen
 * atlandığı, klasik ve sessiz bir açık.
 *
 * Kontrolün ağa çıkmadan ÖNCE olması ayrıca önemli: dizin adresi
 * yapılandırılmamış bir kaynakta bile aynı reddi vermeli.
 */
func TestAuthenticateRefusesEmptyPasswordBeforeAnyNetworkCall(t *testing.T) {
	// Bilerek ulaşılamaz bir adres: kontrol ağa çıkmadan dönmezse test
	// bağlantı hatası alır ve bu ayrımı görürüz.
	src, err := New(Config{
		URL: "ldaps://127.0.0.1:1", UserBase: "ou=people,dc=x",
		UserFilter: "(uid=%s)", GroupAttribute: "memberOf", GroupBase: "ou=groups,dc=x",
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := src.Authenticate(context.Background(), "yigit", "")
	if !errors.Is(err, ErrEmptySecret) {
		t.Fatalf("hata = %v, ErrEmptySecret bekleniyordu — boş parola "+
			"anonim bind olur ve herkesi içeri alırdı", err)
	}
	if res.Authenticated {
		t.Fatal("boş parola kimlik doğrulanmış sayıldı")
	}
	if res.Presence != PresenceUnknown {
		t.Fatalf("varlık = %v, unknown bekleniyordu: dizine hiç sorulmadı", res.Presence)
	}
}

// Kullanıcı adı da boş olamaz: filtreye boş dize koymak, dizinin
// tamamını eşleştirebilecek bir arama üretirdi.
func TestAuthenticateRefusesEmptyUsername(t *testing.T) {
	src, err := New(Config{
		URL: "ldaps://127.0.0.1:1", UserBase: "ou=people,dc=x",
		UserFilter: "(uid=%s)", GroupAttribute: "memberOf", GroupBase: "ou=groups,dc=x",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Authenticate(context.Background(), "", "parola"); err == nil {
		t.Fatal("boş kullanıcı adı kabul edildi")
	}
}
