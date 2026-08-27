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
}

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
	if !strings.Contains(cfg.UserFilter, "%s") {
		return nil, fmt.Errorf("ldap.New: user_filter must contain %%s for the username")
	}

	// ŞİFRESİZ TAŞIMA yalnızca loopback'te: servis hesabı parolası
	// ağdan geçiyor. terminal_enabled'ın HTTPS kuralının kardeşi.
	//
	// ⚠️ KONTROL BEYAZ LİSTE, KARA LİSTE DEĞİL.
	//
	// Eskiden yalnızca küçük harfli "ldap://" önekine bakıyordu ve URL
	// şemaları BÜYÜK/KÜÇÜK HARF DUYARSIZDIR (RFC 3986). "LDAP://" ya da
	// "lDaP://" yazmak kontrolü tamamen atlıyor, go-ldap ise şemayı
	// normalize edip bağlantıyı kuruyordu — yani dizin servis hesabının
	// parolası ağa düz metin çıkıyordu. Aynı boşluk "ldapi://" (unix
	// soketi) ve "cldap://" için de vardı.
	//
	// Beyaz liste bu sınıfı kapatıyor: tanımadığımız bir şema geçmez.
	scheme, _, _ := strings.Cut(cfg.URL, "://")
	switch strings.ToLower(scheme) {
	case "ldaps":
		// TLS: her yerde serbest.
	case "ldap":
		if !isLoopback(cfg.URL) {
			return nil, fmt.Errorf("ldap.New: plain ldap:// is only allowed for loopback; "+
				"use ldaps:// (got %q)", cfg.URL)
		}
	default:
		return nil, fmt.Errorf("ldap.New: unsupported url scheme %q; use ldaps:// "+
			"(or ldap:// on loopback)", scheme)
	}

	if cfg.GroupNameFrom == "" {
		cfg.GroupNameFrom = "cn"
	}
	if cfg.GroupNameFrom != "cn" && cfg.GroupNameFrom != "dn" {
		return nil, fmt.Errorf("ldap.New: group_name_from must be \"cn\" or \"dn\" (got %q)", cfg.GroupNameFrom)
	}

	return &Source{cfg: cfg}, nil
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

// Groups, kullanıcının grup adlarını döner (auth.GroupSource).
//
// Kullanıcı dizinde bulunamazsa BOŞ liste döner, hata değil: bu kişinin
// erişimi yok demektir ve JIT sağlama zaten "eşleşen grup yoksa girme"
// diyecek. Hata döndürmek, dizin arızası ile "bu kişi burada yok"u
// karıştırırdı.
func (s *Source) Groups(ctx context.Context, id auth.Identity) ([]string, error) {
	if id.Username == "" {
		return nil, nil
	}

	conn, err := s.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	userDN, attrGroups, err := s.findUser(conn, id.Username)
	if err != nil {
		return nil, err
	}
	if userDN == "" {
		return nil, nil
	}

	if s.cfg.GroupAttribute != "" {
		return s.normalizeAll(attrGroups), nil
	}
	return s.searchGroups(conn, userDN)
}

// findUser, kullanıcının DN'ini ve (varsa) grup özniteliğini döner.
func (s *Source) findUser(conn *goldap.Conn, username string) (string, []string, error) {
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
		return "", nil, fmt.Errorf("ldap: user search: %w", err)
	}
	if len(res.Entries) == 0 {
		return "", nil, nil
	}
	if len(res.Entries) > 1 {
		// Belirsiz kimlik: hangi kişinin grupları alınacağı bilinemez.
		// Sessizce ilkini seçmek yanlış kişiye yetki vermek olurdu.
		return "", nil, fmt.Errorf("ldap: user %q matches %d entries; tighten user_filter", username, len(res.Entries))
	}

	entry := res.Entries[0]
	var groups []string
	if s.cfg.GroupAttribute != "" {
		groups = entry.GetAttributeValues(s.cfg.GroupAttribute)
	}
	return entry.DN, groups, nil
}

// searchGroups, üyeliğin grubun üstünde durduğu şemalar için.
func (s *Source) searchGroups(conn *goldap.Conn, userDN string) ([]string, error) {
	req := goldap.NewSearchRequest(
		s.cfg.GroupBase, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		0, int(dialTimeout.Seconds()), false,
		fmt.Sprintf(s.cfg.GroupFilter, goldap.EscapeFilter(userDN)),
		[]string{"dn", "cn"}, nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("ldap: group search: %w", err)
	}

	out := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		out = append(out, s.normalize(e.DN))
	}
	return out, nil
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
