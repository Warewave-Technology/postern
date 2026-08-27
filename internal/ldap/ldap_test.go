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
		GroupAttribute: "memberOf", GroupBase: "ou=groups,dc=x",
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

// ⚠️ Grup kimliği DİZİNİN TAMAMINA açık olmamalı.
//
// Kapatılan yetki yükseltme: memberOf yolu dizinin herhangi bir
// yerindeki grubu alıp CN'ine indiriyordu. Dizinde bir yere grup
// açabilen herkes (self-servis grup oluşturma, devredilmiş bir OU,
// yüklenici alt ağacı) adını eşlenmiş bir role denk getirerek o rolü
// alabiliyordu.
func TestUnderBaseScopesGroupIdentity(t *testing.T) {
	const base = "ou=groups,dc=corp,dc=local"

	inside := []string{
		"cn=sysadmins,ou=groups,dc=corp,dc=local",
		"CN=SysAdmins,OU=Groups,DC=Corp,DC=Local",    // harf duyarsız
		"cn=sysadmins, ou=groups, dc=corp, dc=local", // boşluklu
		"cn=x,ou=nested,ou=groups,dc=corp,dc=local",  // daha derin
		base, // tabanın kendisi
	}
	for _, dn := range inside {
		if !underBase(dn, base) {
			t.Errorf("kapsam İÇİNDEKİ grup dışarıda sayıldı: %q", dn)
		}
	}

	outside := []string{
		"cn=sysadmins,ou=contractors,dc=corp,dc=local",
		"cn=sysadmins,dc=corp,dc=local",
		"cn=sysadmins,ou=evilgroups,dc=corp,dc=local", // sonek tuzağı
		"cn=sysadmins,ou=groups,dc=evil,dc=local",
		"cn=sysadmins",
		"",
	}
	for _, dn := range outside {
		if underBase(dn, base) {
			t.Errorf("KAPSAM DIŞINDAKİ grup içeride sayıldı: %q", dn)
		}
	}
}

// Boş bir taban hiçbir şeyi kapsamamalı: yapılandırma eksikse
// varsayılan "her şey serbest" olamaz.
func TestUnderBaseWithEmptyBaseMatchesNothing(t *testing.T) {
	for _, dn := range []string{"cn=x,dc=corp", "", "dc=corp"} {
		if underBase(dn, "") {
			t.Errorf("boş tabanla %q kabul edildi", dn)
		}
	}
}

// group_base ARTIK ZORUNLU — her iki yolda da.
func TestNewRequiresGroupBase(t *testing.T) {
	cfg := Config{
		URL: "ldaps://dc.corp.local", UserBase: "ou=people,dc=x",
		UserFilter: "(uid=%s)", GroupAttribute: "memberOf",
	}
	if _, err := New(cfg); err == nil {
		t.Error("group_base'siz memberOf yapılandırması kabul edildi — " +
			"grup kimliği dizinin tamamına açık kalır")
	}

	cfg.GroupBase = "ou=groups,dc=x"
	if _, err := New(cfg); err != nil {
		t.Errorf("group_base'li yapılandırma reddedildi: %v", err)
	}
}
