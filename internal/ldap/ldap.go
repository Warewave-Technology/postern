// Package ldap reads group membership from an LDAP directory.
//
// NE YAPAR: kullanıcının gruplarını sorar. NE YAPMAZ: kimlik doğrulamaz.
//
// Bu ayrım bilinçli bir mimari karar. LDAP'ta kimlik doğrulama "bind"
// demektir: kullanıcının PAROLASI postern'e verilir ve postern onu
// dizine sunar. Bu, "parola bastion'a hiç uğramaz" duruşumuzun tam
// tersi olurdu ve ele geçirilen bir postern kurumun bütün parolalarını
// toplayabilirdi. Kimliği OIDC'de bırakıyoruz; buraya yalnızca kendi
// servis hesabımızla bağlanıyor ve yetki soruyoruz.
//
// Kazandığımız şey TAZELİK: OIDC token'ındaki grup claim'i giriş anında
// dondurulmuştur, dizin ise her sorguda güncel cevap verir.
package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/warewave/postern/internal/auth"
)

// dialTimeout, dizin erişilemezken girişin ne kadar bekleyeceği.
// Kısa tutuluyor: LDAP'ın yavaşlığı SSH el sıkışmasını kilitlememeli.
const dialTimeout = 10 * time.Second

// Config, dizine bağlanmak ve grup aramak için gerekenler.
//
// Değerler veritabanındaki settings tablosundan gelir (S5.1), config
// dosyasından değil: panelden düzenlenip test edilebilsinler ve servis
// hesabı parolası düz metin olarak dosyada gezmesin diye.
type Config struct {
	// URL, "ldaps://host:636" ya da "ldap://host:389".
	URL string

	// BindDN/BindPassword, POSTERN'İN servis hesabı — kullanıcının değil.
	BindDN       string
	BindPassword string

	// UserBase ve UserFilter, kullanıcıyı bulmak için. Filtredeki %s
	// kullanıcı adıyla değiştirilir: "(uid=%s)" ya da
	// "(sAMAccountName=%s)" (Active Directory).
	UserBase   string
	UserFilter string

	// GroupAttribute doluysa gruplar kullanıcı girdisindeki bu
	// öznitelikten okunur (çoğu dizinde "memberOf"). Boşsa GroupBase +
	// GroupFilter ile arama yapılır — eski şemalarda üyelik grubun
	// üstünde durur, kullanıcının değil.
	GroupAttribute string

	GroupBase   string
	GroupFilter string

	// GroupNameFrom, grup adının nasıl çıkarılacağı: "cn" (varsayılan)
	// ya da "dn".
	//
	// "cn" seçilmesinin sebebi eşleme tablosunun OIDC ile ORTAK olması:
	// token'dan gelen "sysadmins" ile dizinden gelen
	// "cn=sysadmins,ou=groups,dc=..." aynı isim uzayına düşmeli. Bedeli:
	// farklı OU'lardaki aynı adlı iki grup birleşir. Bu kabul edilemezse
	// "dn" seçilir ve eşlemeler tam DN yazılır.
	GroupNameFrom string

	/*
	 * GroupScope, grubun taban DN'e göre nerede durabileceği:
	 * "direct" (varsayılan) ya da "subtree".
	 *
	 * ⚠️ VARSAYILAN "direct" VE BU BİR GÜVENLİK KARARI.
	 *
	 * GroupNameFrom="cn" iken grup adı DN'in yalnızca ilk bileşeninden
	 * okunuyor. Ölçüldü:
	 *
	 *     normalize("cn=sysadmins,ou=teams,ou=groups,dc=corp") → "sysadmins"
	 *
	 * LDAP'ta benzersizlik EBEVEYN BAŞINA. Yani cn=sysadmins zaten
	 * varken, bir alt-OU'da aynı adla ikinci bir grup açılabiliyor ve
	 * postern ikisini de aynı role çözüyordu. Grup açma yetkisi
	 * devredilmiş her kurumda (self-servis portal, departman OU'su,
	 * yüklenici alt ağacı) bu, "istediğim rolü kendime basarım"
	 * demekti.
	 *
	 * "direct" bunu kapatır: grup, taban DN'in DOĞRUDAN çocuğu olmak
	 * zorunda, ve orada benzersizliği dizinin kendisi garanti ediyor.
	 *
	 * "subtree" YALNIZCA GroupNameFrom="dn" ile geçerli — orada eşleme
	 * anahtarı tam DN olduğu için çakışma zaten imkânsız. cn ile
	 * birlikte reddediliyor (bkz. New).
	 */
	GroupScope string
}

// Grup kapsam değerleri.
const (
	ScopeDirect  = "direct"
	ScopeSubtree = "subtree"
)

// Source, LDAP'a soran GroupSource gerçekleştirmesi.
type Source struct {
	cfg Config
}

// New, yapılandırmayı doğrular ve kaynağı kurar. Bağlantı BURADA
// kurulmaz: dizin o an erişilemez olabilir ve postern'in açılmaması için
// sebep değildir — sorgu anında bağlanılır.
func New(cfg Config) (*Source, error) {
	if cfg.URL == "" || cfg.UserBase == "" || cfg.UserFilter == "" {
		return nil, fmt.Errorf("ldap.New: url, user_base and user_filter are required")
	}
	if cfg.GroupAttribute == "" && (cfg.GroupBase == "" || cfg.GroupFilter == "") {
		return nil, fmt.Errorf("ldap.New: either group_attribute or group_base+group_filter is required")
	}

	// ⚠️ group_base HER İKİ YOLDA DA ZORUNLU.
	//
	// Kapatılan yetki yükseltme: grup ARAMASI yolu zaten group_base ile
	// sınırlıydı, ama memberOf (group_attribute) yolu dizinin HERHANGİ
	// BİR YERİNDEKİ grubu alıp CN'ine indiriyordu. Yani dizinde bir yere
	// grup açabilen (self-servis grup oluşturma, devredilmiş bir OU,
	// yüklenici alt ağacı, ormandaki başka bir alan) herkes, adını
	// eşlenmiş bir role denk getirerek O ROLÜ alabiliyordu — "grup
	// açabilirim"den "o rolün hedeflerine SSH'layabilirim"e.
	//
	// Kapsamı zorunlu kılmak yapılandırmayı bir satır uzatıyor;
	// alternatifi, grup kimliğinin dizinin tamamına açık olması.
	if cfg.GroupBase == "" {
		return nil, fmt.Errorf("ldap.New: group_base is required — it scopes which " +
			"part of the directory may name a postern role")
	}
	if !strings.Contains(cfg.UserFilter, "%s") {
		return nil, fmt.Errorf("ldap.New: user_filter must contain %%s for the username")
	}

	if err := checkScheme(cfg.URL); err != nil {
		return nil, fmt.Errorf("ldap.New: %w", err)
	}

	if cfg.GroupNameFrom == "" {
		cfg.GroupNameFrom = "cn"
	}
	if cfg.GroupNameFrom != "cn" && cfg.GroupNameFrom != "dn" {
		return nil, fmt.Errorf("ldap.New: group_name_from must be \"cn\" or \"dn\" (got %q)", cfg.GroupNameFrom)
	}

	// ⚠️ VARSAYILAN "direct". Sıfır değeri geniş kapsam olsaydı, ayarı
	// hiç duymamış her kurulum yetki yükseltmesine açık kalırdı —
	// güvenlik ayarının varsayılanı, unutulduğunda KORUYAN taraf olmalı.
	if cfg.GroupScope == "" {
		cfg.GroupScope = ScopeDirect
	}
	if cfg.GroupScope != ScopeDirect && cfg.GroupScope != ScopeSubtree {
		return nil, fmt.Errorf("ldap.New: group_scope must be %q or %q (got %q)",
			ScopeDirect, ScopeSubtree, cfg.GroupScope)
	}
	/*
	 * subtree + cn REDDEDİLİYOR.
	 *
	 * Bu ikisi birlikte, grup adını DN'in ilk bileşeninden okuyup onu
	 * dizinin herhangi bir derinliğinden kabul etmek demek. LDAP'ta
	 * benzersizlik ebeveyn başına olduğu için, alt-OU'ya açılan
	 * cn=sysadmins gerçek olanla aynı role çözülür. Ölçüldü.
	 *
	 * "dn" ile subtree güvenli: eşleme anahtarı tam DN, çakışma yok.
	 */
	if cfg.GroupScope == ScopeSubtree && cfg.GroupNameFrom != "dn" {
		return nil, fmt.Errorf(
			"ldap.New: group_scope %q needs group_name_from \"dn\"; with %q the group name "+
				"is only the first DN component, and a group of the same name in any sub-OU "+
				"would resolve to the same role",
			ScopeSubtree, cfg.GroupNameFrom)
	}

	return &Source{cfg: cfg}, nil
}

/*
 * checkScheme, URL şemasının kabul edilebilir olduğunu doğrular.
 *
 * ŞİFRESİZ TAŞIMA yalnızca loopback'te: servis hesabı parolası ağdan
 * geçiyor. terminal_enabled'ın HTTPS kuralının kardeşi.
 *
 * ⚠️ KONTROL BEYAZ LİSTE, KARA LİSTE DEĞİL.
 *
 * Eskiden yalnızca küçük harfli "ldap://" önekine bakıyordu ve URL
 * şemaları BÜYÜK/KÜÇÜK HARF DUYARSIZDIR (RFC 3986). "LDAP://" ya da
 * "lDaP://" yazmak kontrolü tamamen atlıyor, go-ldap ise şemayı
 * normalize edip bağlantıyı kuruyordu — yani dizin servis hesabının
 * parolası ağa düz metin çıkıyordu. Aynı boşluk "ldapi://" (unix
 * soketi) ve "cldap://" için de vardı.
 *
 * ⚠️ AYRI FONKSİYON, New'in içinde gömülü değil. CheckConnection (tek
 * başına bağlantı sınaması) New'den geçmiyor; kural orada kopyalansaydı
 * ikisi ayrışır ve panel, New'in reddedeceği bir bağlantıyı "çalışıyor"
 * diye onaylayan bir yan kapı olurdu.
 */
func checkScheme(rawURL string) error {
	scheme, _, _ := strings.Cut(rawURL, "://")
	switch strings.ToLower(scheme) {
	case "ldaps":
		// TLS: her yerde serbest.
		return nil
	case "ldap":
		if !isLoopback(rawURL) {
			return fmt.Errorf("plain ldap:// is only allowed for loopback; "+
				"use ldaps:// (got %q)", rawURL)
		}
		return nil
	default:
		return fmt.Errorf("unsupported url scheme %q; use ldaps:// "+
			"(or ldap:// on loopback)", scheme)
	}
}

// isLoopback, adresin yerel makineyi gösterip göstermediğini söyler.
//
// Ayrıştırılamayan bir URL loopback SAYILMAZ: belirsizlik şifresiz
// taşımaya izin vermenin gerekçesi olamaz.
func isLoopback(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	h := strings.ToLower(u.Hostname())
	if h == "localhost" {
		return true
	}

	// ⚠️ Metin karşılaştırması yetmez: "127.0.0.1" kadar "127.1",
	// "0177.0.0.1" ve "::ffff:127.0.0.1" de loopback'tir ve hiçbiri
	// eski listeye uymuyordu — ama tersi daha önemli: eski liste
	// yalnızca ÜÇ yazımı tanıdığı için "127.000.000.001" gibi geçerli
	// bir loopback adresi REDDEDİLİYORDU. net.IP ikisini de doğru
	// cevaplıyor.
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// connect, dizine bağlanır ve servis hesabıyla bind eder.
//
// Bağlantı havuzu yok: giriş sıklığı düşük ve her sorguda taze bağlantı
// açmak, bayat bir bağlantının sessizce ölmesinden daha öngörülebilir.
func (s *Source) connect(ctx context.Context) (*goldap.Conn, error) {
	conn, err := goldap.DialURL(s.cfg.URL,
		goldap.DialWithDialer(&net.Dialer{Timeout: dialTimeout}),
		goldap.DialWithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12}),
	)
	if err != nil {
		return nil, fmt.Errorf("ldap: dial: %w", err)
	}

	// ctx iptal edilirse bağlantıyı kopar: SSH tarafı gittiğinde sorgu
	// dizinde asılı kalmasın.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	_ = stop

	conn.SetTimeout(dialTimeout)

	if s.cfg.BindDN != "" {
		if err := conn.Bind(s.cfg.BindDN, s.cfg.BindPassword); err != nil {
			conn.Close()
			// Parola hata metnine GİRMEZ; go-ldap zaten koymuyor ama
			// sarmalarken de dikkat.
			return nil, fmt.Errorf("ldap: bind as %s: %w", s.cfg.BindDN, err)
		}
	}
	return conn, nil
}

// Test, yapılandırmanın çalıştığını doğrular: bağlan, bind et, kullanıcı
// tabanını ara. Panelden "bağlantıyı test et" için.
func (s *Source) Test(ctx context.Context) error {
	conn, err := s.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Tek satır isteyerek tabanın var olduğunu doğrula: yanlış base DN
	// ilk gerçek girişte değil, testte ortaya çıksın.
	req := goldap.NewSearchRequest(
		s.cfg.UserBase, goldap.ScopeBaseObject, goldap.NeverDerefAliases,
		1, int(dialTimeout.Seconds()), false,
		"(objectClass=*)", []string{"dn"}, nil,
	)
	if _, err := conn.Search(req); err != nil {
		return fmt.Errorf("ldap: user_base %q not searchable: %w", s.cfg.UserBase, err)
	}
	return nil
}

/*
 * Groups, kullanıcının gruplarını ÜÇ DEĞERLİ cevapla döner
 * (auth.GroupSource).
 *
 * ⚠️ ARTIK Lookup'IN ÜSTÜNE KURULU. Eskiden burada ayrı bir arama vardı
 * ve kullanıcı bulunamadığında boş dilim dönüyordu — yorumu "dizin
 * arızası ile 'bu kişi burada yok' karıştırılmasın" diyordu ama
 * gerçekleştirme, "burada yok" ile "burada ve hiçbir grupta değil"i
 * karıştırıyordu. Ölçülen bedeli: adı dizinde tutmayan kullanıcı her
 * girişte bütün SSO rollerini kaybediyordu.
 *
 * Lookup bu ayrımı zaten yapıyor ve senkronizasyon ona dayanıyor; giriş
 * yolunun ondan farklı bir gerçeğe bakması için bir sebep yoktu.
 */
func (s *Source) Groups(ctx context.Context, id auth.Identity) (auth.GroupResult, error) {
	if id.Username == "" {
		// Kullanıcı adı yoksa soracak bir şey yok. "Yok" değil,
		// "bilinmiyor": bu kimlikle dizine hiç sorulmadı.
		return auth.GroupResult{Presence: auth.GroupsUnknown}, nil
	}

	res, err := s.Lookup(ctx, id)
	if err != nil {
		return auth.GroupResult{Presence: auth.GroupsUnknown}, err
	}

	switch res.Presence {
	case PresencePresent:
		return auth.GroupResult{Presence: auth.GroupsPresent, Groups: res.Groups}, nil
	case PresenceAbsent:
		return auth.GroupResult{Presence: auth.GroupsAbsent}, nil
	default:
		return auth.GroupResult{Presence: auth.GroupsUnknown}, nil
	}
}

// findUser, kullanıcının DN'ini ve (varsa) grup özniteliğini döner.
func (s *Source) findUser(conn *goldap.Conn, username string) (string, []string, []string, error) {
	attrs := []string{"dn"}
	if s.cfg.GroupAttribute != "" {
		attrs = append(attrs, s.cfg.GroupAttribute)
	}

	req := goldap.NewSearchRequest(
		s.cfg.UserBase, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		2, int(dialTimeout.Seconds()), false,
		fmt.Sprintf(s.cfg.UserFilter, goldap.EscapeFilter(username)),
		attrs, nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		return "", nil, nil, fmt.Errorf("ldap: user search: %w", err)
	}
	if len(res.Entries) == 0 {
		return "", nil, nil, nil
	}
	if len(res.Entries) > 1 {
		// Belirsiz kimlik: hangi kişinin grupları alınacağı bilinemez.
		// Sessizce ilkini seçmek yanlış kişiye yetki vermek olurdu.
		return "", nil, nil, fmt.Errorf("ldap: user %q matches %d entries; tighten user_filter", username, len(res.Entries))
	}

	entry := res.Entries[0]
	var groups, outOfScope []string
	if s.cfg.GroupAttribute != "" {
		// KAPSAM SÜZGECİ: yalnızca group_base ALTINDAKİ gruplar sayılır.
		// Gerekçe New()'deki group_base kontrolünde.
		for _, dn := range entry.GetAttributeValues(s.cfg.GroupAttribute) {
			if inGroupScope(dn, s.cfg.GroupBase, s.cfg.GroupScope) {
				groups = append(groups, dn)
				continue
			}
			// Kapsam dışında kalanı ATMIYORUZ, ayırıyoruz: operatör
			// yükseltmeden sonra "grubum neden düştü" diye sorduğunda
			// cevabı teşhis ekranında görmeli.
			outOfScope = append(outOfScope, dn)
		}
	}
	return entry.DN, groups, outOfScope, nil
}

// searchGroups, üyeliğin grubun üstünde durduğu şemalar için.
func (s *Source) searchGroups(conn *goldap.Conn, userDN string) ([]string, []string, error) {
	req := goldap.NewSearchRequest(
		s.cfg.GroupBase, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		0, int(dialTimeout.Seconds()), false,
		fmt.Sprintf(s.cfg.GroupFilter, goldap.EscapeFilter(userDN)),
		[]string{"dn", "cn"}, nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		return nil, nil, fmt.Errorf("ldap: group search: %w", err)
	}

	// ⚠️ KAPSAM SÜZGECİ BURADA DA. Arama tabanı group_base olsa bile
	// ScopeWholeSubtree alt-OU'lardaki grupları getiriyor; memberOf
	// yolundaki kuralın burada uygulanmaması, aynı yetki yükseltmesini
	// ikinci bir kapıdan açık bırakırdı.
	out := make([]string, 0, len(res.Entries))
	var outOfScope []string
	for _, e := range res.Entries {
		if !inGroupScope(e.DN, s.cfg.GroupBase, s.cfg.GroupScope) {
			outOfScope = append(outOfScope, e.DN)
			continue
		}
		out = append(out, s.normalize(e.DN))
	}
	return out, outOfScope, nil
}

func (s *Source) normalizeAll(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, s.normalize(v))
	}
	return out
}

// normalize, grup değerini eşleme tablosunun beklediği ada çevirir.
//
// GroupNameFrom="cn" iken "cn=sysadmins,ou=groups,dc=x" → "sysadmins".
// Böylece OIDC claim'inden gelen "sysadmins" ile aynı isim uzayına düşer
// ve tek eşleme tablosu iki kaynağa birden hizmet eder.
func (s *Source) normalize(value string) string {
	if s.cfg.GroupNameFrom == "dn" {
		return value
	}

	dn, err := goldap.ParseDN(value)
	if err != nil || len(dn.RDNs) == 0 || len(dn.RDNs[0].Attributes) == 0 {
		// DN değilse (bazı dizinler düz ad döndürür) olduğu gibi bırak.
		return value
	}
	return dn.RDNs[0].Attributes[0].Value
}

/*
 * underBase, bir DN'in verilen tabanın ALTINDA olup olmadığını söyler.
 *
 * ⚠️ KARŞILAŞTIRMA DN OLARAK YAPILIYOR, METİN OLARAK DEĞİL.
 *
 * Kapatılan açık ölçüldü: eski hâl DN'i ham virgüllerden bölüp sonek
 * karşılaştırıyordu ve RFC 4514 kaçışlarını görmüyordu. Bir RDN'in
 * DEĞERİNİN İÇİNDEKİ kaçışlı virgül, o kaçışı bir bileşen sınırı gibi
 * gösteriyordu:
 *
 *     underBase(`cn=sysadmins,ou=evil\,ou=groups,dc=corp`,
 *               "ou=groups,dc=corp")  →  true
 *
 * Oysa o giriş dc=corp'un çocuğu ve ou=groups'un altında DEĞİL. Yani
 * dizinde dc=corp altına tek bir giriş açabilen biri, adını istediği
 * role denk getirip o rolü alabiliyordu — bu fonksiyonun var olma
 * sebebi olan yetki yükseltmesinin ta kendisi.
 *
 * ParseDN kaçışları, çok değerli RDN'leri ve tırnaklamayı doğru
 * çözüyor; *Fold biçimleri de harf duyarsızlığını veriyor ki
 * "OU=Groups" ile "ou=groups" aynı sayılsın (dizinler öyle sayıyor,
 * aksi hâlde meşru bir grup kapsam dışı görünüp kullanıcının erişimi
 * sessizce kaybolurdu).
 *
 * ⚠️ AYRIŞTIRILAMAYAN DN KAPSAM DIŞIDIR. Anlamadığımız bir değeri
 * "herhalde uygundur" diye kabul etmek, bu fonksiyonun koruduğu şeyi
 * tam olarak geri verirdi.
 */
/*
 * inGroupScope, bir grup DN'inin yapılandırılmış kapsamda olup
 * olmadığını söyler.
 *
 * "direct": taban DN'in DOĞRUDAN çocuğu. Ad çakışmasını dizinin kendi
 * benzersizlik kuralına devrediyor — aynı ebeveyn altında iki
 * cn=sysadmins olamaz.
 *
 * "subtree": altındaki her yer. Yalnızca tam DN ile eşleme yapılırken
 * güvenli.
 */
func inGroupScope(dn, base, scope string) bool {
	if scope == ScopeSubtree {
		return underBase(dn, base)
	}

	b, berr := goldap.ParseDN(base)
	if berr != nil || len(b.RDNs) == 0 {
		return false
	}
	d, derr := goldap.ParseDN(dn)
	if derr != nil {
		return false
	}
	// Tam bir bileşen daha uzun VE tabanın altında: doğrudan çocuk.
	return len(d.RDNs) == len(b.RDNs)+1 && b.AncestorOfFold(d)
}

func underBase(dn, base string) bool {
	b, err := goldap.ParseDN(base)
	if err != nil || len(b.RDNs) == 0 {
		return false
	}
	d, err := goldap.ParseDN(dn)
	if err != nil || len(d.RDNs) == 0 {
		return false
	}
	// Tabanın kendisi de kapsam içi sayılıyor: grup girişinin doğrudan
	// taban DN'i olduğu kurulumlar var ve onları dışarıda bırakmak
	// davranış değişikliği olurdu.
	return b.EqualFold(d) || b.AncestorOfFold(d)
}
