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

		// ⚠️ KAÇIŞLI VİRGÜL TUZAĞI. Bu giriş dc=corp,dc=local'in
		// ÇOCUĞU; ou=groups diye bir atası yok. Metin olarak
		// karşılaştıran eski hâl onu kapsam içi sayıyordu ve dizinde
		// dc=corp altına tek bir giriş açabilen herkese istediği rolü
		// veriyordu.
		`cn=sysadmins,ou=evil\,ou=groups,dc=corp,dc=local`,
		// Aynı tuzağın kullanıcı adı tarafındaki biçimi.
		`cn=x\,ou=groups,dc=corp,dc=local`,
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

// Ayrıştırılamayan bir değer kapsam DIŞIDIR.
//
// Bazı dizinler grup özniteliğinde DN olmayan değerler döndürebiliyor.
// Anlamadığımız bir değeri kabul etmek, kapsam süzgecini isteğe bağlı
// hâle getirirdi; reddetmek en fazla bir grubun görülmemesine yol açar.
func TestUnderBaseRejectsUnparseableDN(t *testing.T) {
	const base = "ou=groups,dc=corp,dc=local"
	for _, dn := range []string{
		"bu bir dn degil",
		"=,,=",
		`cn=x,ou=groups,dc=corp,dc=local\`, // sonu yarım kaçış
	} {
		if underBase(dn, base) {
			t.Errorf("ayrıştırılamayan %q kapsam içi sayıldı", dn)
		}
	}
	// Taban ayrıştırılamıyorsa da hiçbir şey kapsam içi olmamalı.
	if underBase("cn=x,ou=groups,dc=corp,dc=local", `ou=groups,dc=corp,dc=local\`) {
		t.Error("bozuk tabanla eşleşme kabul edildi")
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

/*
 * checkScheme, New'den AYRI bir fonksiyon olarak sınanıyor.
 *
 * NEDEN: kural artık iki yerden çağrılıyor — New (tam yapılandırma) ve
 * CheckConnection (sihirbazın tek başına bağlantı sınaması). Kopyalansaydı
 * ikisi ayrışır ve panel, New'in reddedeceği bir bağlantıyı "çalışıyor"
 * diye onaylayan bir yan kapı olurdu.
 */
func TestCheckScheme(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{name: "ldaps her yerde", url: "ldaps://ldap.example:636"},
		{name: "ldap loopback ip", url: "ldap://127.0.0.1:389"},
		{name: "ldap localhost", url: "ldap://localhost:389"},
		{name: "ldap ipv6 loopback", url: "ldap://[::1]:389"},

		// ⚠️ Şemalar BÜYÜK/KÜÇÜK HARF DUYARSIZDIR (RFC 3986). Bir zamanlar
		// yalnızca küçük harfli "ldap://" önekine bakılıyordu ve "LDAP://"
		// kontrolü tamamen atlıyordu — servis hesabının parolası ağa düz
		// metin çıkıyordu.
		{name: "LDAP buyuk harf uzak", url: "LDAP://ldap.example:389", wantErr: true},
		{name: "lDaP karisik uzak", url: "lDaP://ldap.example:389", wantErr: true},
		{name: "LDAPS buyuk harf", url: "LDAPS://ldap.example:636"},

		{name: "ldap uzak reddedilir", url: "ldap://ldap.example:389", wantErr: true},
		// Beyaz liste: tanımadığımız şema geçmez.
		{name: "ldapi unix soketi", url: "ldapi:///", wantErr: true},
		{name: "cldap", url: "cldap://ldap.example", wantErr: true},
		{name: "sema yok", url: "ldap.example:389", wantErr: true},
		{name: "bos", url: "", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkScheme(tc.url)
			if tc.wantErr && err == nil {
				t.Errorf("checkScheme(%q) kabul etti, reddetmeliydi", tc.url)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("checkScheme(%q) reddetti: %v", tc.url, err)
			}
		})
	}
}

/*
 * Grup KAPSAMI: aynı adlı grup başka bir OU'da açılarak rol basılamamalı.
 *
 * Ölçülmüş açık: normalize() grup adını DN'in yalnızca ilk bileşeninden
 * okuyor ve LDAP'ta benzersizlik EBEVEYN BAŞINA. cn=sysadmins zaten
 * varken bir alt-OU'da ikincisi açılabiliyor, ve ikisi de "sysadmins"e
 * çözülüyordu. Grup açma yetkisi devredilmiş her kurumda bu, istediğin
 * rolü kendine basmak demekti.
 */
func TestGroupScopeDirectRefusesNestedGroups(t *testing.T) {
	const base = "ou=groups,dc=corp,dc=local"

	inside := []string{
		"cn=sysadmins," + base,
		"CN=SysAdmins,OU=Groups,DC=Corp,DC=Local", // harf duyarsız
		"cn=x, ou=groups, dc=corp, dc=local",      // boşluklu
	}
	for _, dn := range inside {
		if !inGroupScope(dn, base, ScopeDirect) {
			t.Errorf("doğrudan çocuk kapsam dışı sayıldı: %q", dn)
		}
	}

	outside := []string{
		"cn=sysadmins,ou=teams," + base,  // BİR seviye daha derin
		"cn=sysadmins,ou=a,ou=b," + base, // daha da derin
		base,                             // tabanın kendisi grup değil
		"cn=sysadmins,dc=corp,dc=local",
		`cn=sysadmins,ou=evil\,ou=groups,dc=corp,dc=local`, // kaçış tuzağı
	}
	for _, dn := range outside {
		if inGroupScope(dn, base, ScopeDirect) {
			t.Errorf("KAPSAM DIŞINDAKİ grup doğrudan çocuk sayıldı: %q", dn)
		}
	}

	// subtree kipinde iç içe olan yine sayılır — ama o kip yalnızca
	// group_name_from="dn" ile açılabiliyor (bkz. New).
	if !inGroupScope("cn=sysadmins,ou=teams,"+base, base, ScopeSubtree) {
		t.Error("subtree kipinde iç içe grup sayılmadı")
	}
}

// subtree + cn birlikte REDDEDİLMELİ: ikisi birlikte tam olarak
// kapatılan açığı geri getirir.
func TestNewRefusesSubtreeScopeWithCNNames(t *testing.T) {
	cfg := Config{
		URL: "ldaps://dc.corp.local", UserBase: "ou=people,dc=x",
		UserFilter: "(uid=%s)", GroupAttribute: "memberOf",
		GroupBase: "ou=groups,dc=x", GroupScope: ScopeSubtree,
	}
	if _, err := New(cfg); err == nil {
		t.Error("group_scope=subtree, group_name_from=cn ile kabul edildi — " +
			"alt-OU'daki aynı adlı grup yine rol basardı")
	}

	cfg.GroupNameFrom = "dn"
	if _, err := New(cfg); err != nil {
		t.Errorf("subtree + dn reddedildi: %v — tam DN ile çakışma olamaz", err)
	}
}

// Ayar hiç yazılmamışsa KORUYAN taraf seçilmeli.
func TestNewDefaultsToDirectScope(t *testing.T) {
	cfg := Config{
		URL: "ldaps://dc.corp.local", UserBase: "ou=people,dc=x",
		UserFilter: "(uid=%s)", GroupAttribute: "memberOf",
		GroupBase: "ou=groups,dc=x",
	}
	src, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if src.cfg.GroupScope != ScopeDirect {
		t.Fatalf("varsayılan kapsam = %q, %q bekleniyordu", src.cfg.GroupScope, ScopeDirect)
	}
}
