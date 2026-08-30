package ldap

import (
	"context"
	"fmt"

	goldap "github.com/go-ldap/ldap/v3"
)

// maxGroupMembers, önizlemede listelenecek en fazla üye.
//
// Sınır bir güvenlik değil dürüstlük meselesi: 4000 kişilik bir grubun
// tamamını ekrana basmak kimseye yaramaz. Kesildiğinde SÖYLENİYOR —
// sessizce kırpılmış bir liste, operatörün "hepsi bu" sanmasına yol
// açardı.
const maxGroupMembers = 200

// GroupMembers, bir grubun üyelerinin KULLANICI ADLARINI döner.
type GroupMembers struct {
	// Usernames, user_filter'ın eşleştireceği adlar.
	Usernames []string
	// Truncated, dizinin daha fazla üye bildirdiği.
	Truncated bool
}

/*
 * MembersOf, grubun üyelerini bulur.
 *
 * ⚠️ BU LİSTE TEK BAŞINA BİR CEVAP DEĞİL. Kimin yönetici olacağına
 * karar veren şey, kullanıcı BAŞINA çalışan çözümleme (Lookup) ve onun
 * kapsam kuralları. Burası yalnızca ADAYLARI çıkarıyor; çağıran her
 * adayı gerçek yoldan doğrulamak zorunda, yoksa önizleme girişten
 * farklı bir gerçeği gösterir — onay ekranının yapabileceği en kötü şey.
 */
func (s *Source) MembersOf(ctx context.Context, group string) (GroupMembers, error) {
	conn, err := s.connect(ctx)
	if err != nil {
		return GroupMembers{}, err
	}
	defer conn.Close()

	// Grubu KAPSAM İÇİNDE arıyoruz: kapsam dışındaki aynı adlı bir grup
	// yönetici veremeyeceği için önizlemede de görünmemeli.
	scope := goldap.ScopeSingleLevel
	if s.cfg.GroupScope == ScopeSubtree {
		scope = goldap.ScopeWholeSubtree
	}
	req := goldap.NewSearchRequest(
		s.cfg.GroupBase, scope, goldap.NeverDerefAliases,
		2, int(dialTimeout.Seconds()), false,
		fmt.Sprintf("(cn=%s)", goldap.EscapeFilter(group)),
		[]string{"member", "uniqueMember", "memberUid"}, nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		return GroupMembers{}, fmt.Errorf("ldap: group member search: %w", err)
	}
	if len(res.Entries) == 0 {
		// Grup yok: boş liste, hata değil. Çağıran bunu "bu grupta
		// kimse yok" diye değil "böyle bir grup bulunamadı" diye
		// göstermeli — ayrımı o yapıyor.
		return GroupMembers{}, nil
	}
	if len(res.Entries) > 1 {
		return GroupMembers{}, fmt.Errorf(
			"ldap: %d groups named %q in scope; the name is ambiguous", len(res.Entries), group)
	}

	entry := res.Entries[0]
	var out GroupMembers
	add := func(v string) {
		if len(out.Usernames) >= maxGroupMembers {
			out.Truncated = true
			return
		}
		out.Usernames = append(out.Usernames, v)
	}

	// memberUid doğrudan kullanıcı adı taşır (RFC 2307).
	for _, uid := range entry.GetEqualFoldAttributeValues("memberUid") {
		add(uid)
	}
	// member / uniqueMember DN taşır; kullanıcı adını ilk RDN'den
	// çıkarıyoruz — user_filter'ın eşleştirdiği değer o.
	for _, attr := range []string{"member", "uniqueMember"} {
		for _, dn := range entry.GetEqualFoldAttributeValues(attr) {
			parsed, perr := goldap.ParseDN(dn)
			if perr != nil || len(parsed.RDNs) == 0 || len(parsed.RDNs[0].Attributes) == 0 {
				continue
			}
			add(parsed.RDNs[0].Attributes[0].Value)
		}
	}
	return out, nil
}
