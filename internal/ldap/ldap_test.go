package ldap

import "testing"

// ⚠️ ŞİFRESİZ TAŞIMA yalnızca loopback'te olmalı — ve kontrol
// atlatılamamalı.
//
// Kapatılan boşluk: kontrol yalnızca küçük harfli "ldap://" önekine
// bakıyordu. URL şemaları büyük/küçük harf DUYARSIZDIR (RFC 3986), yani
// "LDAP://" yazmak kontrolü tamamen atlıyor, go-ldap ise şemayı
// normalize edip bağlanıyordu: dizin servis hesabının parolası ağa düz
// metin çıkıyordu. Panelden ldap.url yazabilen bir admin bunu tek
// alanla yapabiliyordu.
func TestNewRefusesUnencryptedTransportOffLoopback(t *testing.T) {
	base := Config{
		UserBase: "ou=people,dc=x", UserFilter: "(uid=%s)",
		GroupAttribute: "memberOf",
	}

	refused := []string{
		"ldap://dc.corp.local",
		"LDAP://dc.corp.local", // büyük harf: eski kontrolü atlıyordu
		"lDaP://dc.corp.local", // karışık
		"LDAP://192.168.1.10:389",
		"ldapi://%2Ftmp%2Fevil.sock", // unix soketi: hiç tanınmıyordu
		"cldap://dc.corp.local",      // bağlantısız LDAP
		"http://dc.corp.local",
		"dc.corp.local", // şemasız
	}
	for _, u := range refused {
		t.Run(u, func(t *testing.T) {
			cfg := base
			cfg.URL = u
			if _, err := New(cfg); err == nil {
				t.Errorf("KABUL EDİLDİ: %q — bind parolası düz metin gidebilir", u)
			}
		})
	}

	allowed := []string{
		"ldaps://dc.corp.local",
		"LDAPS://dc.corp.local", // TLS: yazım fark etmez
		"ldap://localhost:389",
		"ldap://127.0.0.1:389",
		"LDAP://127.0.0.1:389",
		"ldap://[::1]:389",
		"ldap://127.0.0.2:389", // 127/8'in tamamı loopback
	}
	for _, u := range allowed {
		t.Run(u, func(t *testing.T) {
			cfg := base
			cfg.URL = u
			if _, err := New(cfg); err != nil {
				t.Errorf("REDDEDİLDİ: %q — %v", u, err)
			}
		})
	}
}
