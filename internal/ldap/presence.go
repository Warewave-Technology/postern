package ldap

import (
	"context"
	"fmt"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/warewave/postern/internal/auth"
)

// Dizinde VARLIK sorusu — üç değerli.
//
// NEDEN ÜÇ DEĞER: Groups tek başına bu soruyu cevaplayamıyor. Kullanıcı
// dizinde yoksa boş liste dönüyor (ve bu giriş yolunda DOĞRU davranış),
// ama periyodik senkronizasyon için "boş liste" iki bambaşka şeyin aynı
// görünümü: "bu kişi silinmiş" ve "dizine ulaşamadım". İkisini karıştıran
// bir senkronizasyon, bir LDAP kesintisinde ŞİRKETİN TÜM YETKİLERİNİ
// iptal eder.
//
// Bu yüzden ayrım burada, protokolü bilen pakette yapılıyor — kararı
// veren döngüde değil.

type Presence int

const (
	// PresenceUnknown: dizin cevap veremedi. Hiçbir şey çıkarılamaz.
	PresenceUnknown Presence = iota
	// PresencePresent: dizin cevap verdi ve kullanıcı orada.
	PresencePresent
	// PresenceAbsent: dizin BAŞARIYLA cevap verdi ve kullanıcı orada DEĞİL.
	PresenceAbsent
)

func (p Presence) String() string {
	switch p {
	case PresencePresent:
		return "present"
	case PresenceAbsent:
		return "absent"
	default:
		return "unknown"
	}
}

// LookupResult, bir kullanıcının dizindeki durumu.
type LookupResult struct {
	Presence Presence
	Groups   []string

	/*
	 * Disabled, dizinin bu hesabı KAPATTIĞINI söylemesi.
	 *
	 * ⚠️ PresencePresent İLE BİRLİKTE GELEBİLİR ve gelmesi normal:
	 * bir hesabı devre dışı bırakmak girişi silmez, grup üyeliklerini
	 * de kaldırmaz. Yalnızca gruplara bakan bir çağıran o hesabı
	 * "burada ve şu rollere sahip" diye okur — işten ayrılma ve olay
	 * müdahalesinde atılan İLK adımı görmezden gelmiş olur.
	 */
	Disabled       bool
	DisabledReason string

	// OutOfScope, kullanıcının üye olduğu ama grup KAPSAMI dışında
	// kaldığı için sayılmayan grupların ham DN'leri.
	//
	// Teşhis için: kapsam varsayılanı "direct" olduğunda, gruplarını bir
	// OU daha derinde tutan bir kurulum yükseltmeden sonra rol
	// kaybeder. Bunu sessizce yapmak, operatörü kaybolan yetkinin
	// sebebini arayarak saatlerce dolaştırırdı.
	OutOfScope []string
}

// Lookup, kullanıcının dizinde olup olmadığını ve gruplarını döner.
//
// SINIFLANDIRMA KURALI — dar tutulması bilinçli:
//
//	PresenceAbsent  YALNIZCA sunucunun BAŞARIYLA cevapladığı ve sıfır
//	                giriş döndürdüğü arama için.
//	PresenceUnknown diğer HER ŞEY: bağlantı/TLS/bind hatası, herhangi bir
//	                LDAP sonuç kodu (yanlış base DN'de gelen 32
//	                NoSuchObject dahil), ve birden fazla giriş dönmesi.
//
// 32 NoSuchObject'in Unknown sayılması özellikle önemli: yanlış ya da
// yeniden adlandırılmış bir base DN her kullanıcı için o kodu döndürür
// ve "herkes silinmiş" gibi görünür.
func (s *Source) Lookup(ctx context.Context, id auth.Identity) (LookupResult, error) {
	if id.Username == "" {
		return LookupResult{Presence: PresenceUnknown}, fmt.Errorf("ldap: empty username")
	}

	conn, err := s.connect(ctx)
	if err != nil {
		return LookupResult{Presence: PresenceUnknown}, err
	}
	defer conn.Close()

	ue, err := s.findUser(conn, id.Username)
	if err != nil {
		return LookupResult{Presence: PresenceUnknown}, err
	}
	if ue.DN == "" {
		// findUser boş DN'i yalnızca arama BAŞARILI olup sıfır giriş
		// döndürdüğünde veriyor — aranan tam da bu.
		return LookupResult{Presence: PresenceAbsent}, nil
	}

	if s.cfg.GroupAttribute != "" {
		return LookupResult{
			Presence:       PresencePresent,
			Groups:         s.normalizeAll(ue.Groups),
			OutOfScope:     ue.OutOfScope,
			Disabled:       ue.Disabled,
			DisabledReason: ue.DisabledReason,
		}, nil
	}

	groups, searchOutOfScope, err := s.searchGroups(conn, ue.DN)
	if err != nil {
		// Kullanıcıyı BULDUK ama gruplarını okuyamadık. Present demek,
		// "grupları yok" diye okunup yetkilerinin silinmesine yol açardı.
		return LookupResult{Presence: PresenceUnknown}, err
	}
	return LookupResult{Presence: PresencePresent, Groups: groups,
		OutOfScope:     searchOutOfScope,
		Disabled:       ue.Disabled,
		DisabledReason: ue.DisabledReason}, nil
}

// Probe, dizinin ŞU AN veri döndürüp döndürmediğini sorar.
//
// Test'ten farkı: Test "yapılandırma doğru mu" (taban nesnesi var mı)
// der; Probe "dizin şu an kullanıcılarıyla birlikte cevap veriyor mu"
// der. Sıfır kullanıcı döndüren bir dizin ya arızalıdır ya geri yükleme
// ortasındadır — herkesin silindiği bir şirket değildir.
//
// Senkronizasyon TEK BİR kullanıcıya bile dokunmadan önce bunu çağırır.
func (s *Source) Probe(ctx context.Context) error {
	conn, err := s.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	req := goldap.NewSearchRequest(
		s.cfg.UserBase, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		2, int(dialTimeout.Seconds()), false,
		// ⚠️ EscapeFilter YOK ve olmamalı: "*" burada JOKER, aranan bir
		// değer değil. Kaçışlanırsa "\2a" olur ve filtre düz yıldız
		// karakterini arar — hiçbir kullanıcı eşleşmez, her koşu
		// "dizin boş" diye iptal edilir ve özellik sessizce hiç
		// çalışmaz. (Ölçüldü: gerçek OpenLDAP'a karşı tam olarak bu
		// oldu.) Enjeksiyon riski yok, yıldız bizim sabitimiz.
		fmt.Sprintf(s.cfg.UserFilter, "*"), []string{"dn"}, nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		// ⚠️ Boyut sınırı aşımı BAŞARIDIR: sunucu girişleri döndürdü,
		// yalnızca hepsini değil. Bunu hata saymak, boyut sınırlı her
		// dizinde her senkronizasyonu iptal ederdi — yani özellik
		// sessizce hiç çalışmazdı.
		if goldap.IsErrorWithCode(err, goldap.LDAPResultSizeLimitExceeded) && res != nil && len(res.Entries) > 0 {
			return nil
		}
		return fmt.Errorf("ldap: directory probe failed: %w", err)
	}
	if len(res.Entries) == 0 {
		return fmt.Errorf("ldap: directory returned no users at all; refusing to treat that as deletions")
	}
	return nil
}
