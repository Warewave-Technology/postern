package ldap

import (
	"context"
	"fmt"
	"strconv"
	"strings"

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
	conn, releaseConn, err := s.connect(ctx)
	if err != nil {
		return GroupMembers{}, err
	}
	defer releaseConn()

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
		if err := s.collectMembers(conn, entry, attr, add, &out); err != nil {
			return GroupMembers{}, err
		}
	}
	return out, nil
}

/*
 * collectMembers, bir üyelik niteliğinin değerlerini toplar — GEREKİRSE
 * DİLİM DİLİM.
 *
 * ⚠️ ACTIVE DIRECTORY BÜYÜK GRUPLARDA `member` GÖNDERMİYOR.
 *
 * ÖLÇÜLDÜ (members_range_test.go): AD, yaklaşık 1500 üyeden büyük bir
 * grupta düz `member` niteliğini HİÇ vermiyor; yerine
 * `member;range=0-1499` veriyor ve kalanını ayrıca istemeni bekliyor.
 * Yalnızca `member` okuyan eski kod, 1600 kişilik bir grubu BOŞ
 * görüyordu.
 *
 * Bunun nerede patladığı önemli: bu liste YÖNETİCİ GRUBU ONAY EKRANINI
 * besliyor. Ekran EN BÜYÜK — yani en tehlikeli — grupları "kimse yok"
 * diye gösteriyor, yönetici zararsız sanıp onaylıyor, ve o gruptaki
 * herkes bir sonraki girişinde yönetici oluyor. Bu dosyanın kendi
 * yorumu bunu zaten yazmış: "önizleme girişten farklı bir gerçeği
 * gösterir — onay ekranının yapabileceği en kötü şey".
 *
 * Gerçek OpenLDAP bu davranışı üretmediği için entegrasyon testleri
 * yakalayamıyordu; sahte sunucu (ldaptest) tam olarak bunun için var.
 */
func (s *Source) collectMembers(conn *goldap.Conn, entry *goldap.Entry,
	attr string, add func(string), out *GroupMembers) error {

	addDN := func(dn string) {
		parsed, perr := goldap.ParseDN(dn)
		if perr != nil || len(parsed.RDNs) == 0 || len(parsed.RDNs[0].Attributes) == 0 {
			return
		}
		add(parsed.RDNs[0].Attributes[0].Value)
	}

	// Düz nitelik (OpenLDAP ve küçük AD grupları).
	for _, dn := range entry.GetEqualFoldAttributeValues(attr) {
		addDN(dn)
	}

	vals, next, ranged := rangedValues(entry, attr)
	if !ranged {
		return nil
	}
	for _, dn := range vals {
		addDN(dn)
	}

	/*
	 * Kalan dilimler.
	 *
	 * ⚠️ ÖNİZLEME SINIRINA ULAŞINCA DURUYORUZ. 5000 kişilik bir grubun
	 * tamamını çekmek, ekranda 200 satır göstermek için dizini beş kez
	 * dolaşmak olurdu. Kesildiği Truncated ile SÖYLENİYOR — sessizce
	 * kırpılmış bir liste, operatöre "hepsi bu" dedirtir.
	 */
	for next >= 0 && len(out.Usernames) < maxGroupMembers {
		want := fmt.Sprintf("%s;range=%d-*", attr, next)
		req := goldap.NewSearchRequest(
			entry.DN, goldap.ScopeBaseObject, goldap.NeverDerefAliases,
			1, int(dialTimeout.Seconds()), false,
			"(objectClass=*)", []string{want}, nil,
		)
		more, err := conn.Search(req)
		if err != nil {
			return fmt.Errorf("ldap: ranged member search (%s): %w", want, err)
		}
		if len(more.Entries) == 0 {
			return nil
		}
		vals, next, ranged = rangedValues(more.Entries[0], attr)
		if !ranged {
			return nil
		}
		for _, dn := range vals {
			addDN(dn)
		}
	}
	if next >= 0 {
		// Daha var ama sınıra ulaşıldı.
		out.Truncated = true
	}
	return nil
}

/*
 * rangedValues, "member;range=0-1499" biçimindeki niteliği çözer.
 *
 * next: bir sonraki dilimin başlangıcı; -1 ise bu SON dilim ("range=N-*").
 * ranged: böyle bir nitelik bulundu mu.
 */
func rangedValues(e *goldap.Entry, attr string) (vals []string, next int, ranged bool) {
	prefix := strings.ToLower(attr) + ";"
	for _, a := range e.Attributes {
		name := strings.ToLower(a.Name)
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		// Seçenekler arasında range= olanı ara: AD başka seçenek de
		// ekleyebiliyor ve konumuna güvenmek kırılgan olurdu.
		for _, opt := range strings.Split(name[len(prefix):], ";") {
			spec, found := strings.CutPrefix(opt, "range=")
			if !found {
				continue
			}
			_, hi, ok := strings.Cut(spec, "-")
			if !ok {
				continue
			}
			/*
			 * "*" son dilim demek (RFC dışı, AD sözleşmesi).
			 *
			 * Aşağıdaki Atoi zaten "*" için hata verip aynı sonucu
			 * üretiyor — bu dal FAZLALIK ve bilerek duruyor: son
			 * dilimin nasıl işaretlendiğini bir hata yolunun yan
			 * etkisine bırakmak, o yolu değiştiren kişinin farkında
			 * olmadan protokolü bozması demek olurdu.
			 */
			if hi == "*" {
				return a.Values, -1, true
			}
			end, err := strconv.Atoi(hi)
			if err != nil {
				// Anlamadığımız bir aralık: değerleri yine de
				// alıyoruz ama devamını istemiyoruz. Uydurma bir
				// sonraki dilim istemek, sonsuz döngü riskidir.
				return a.Values, -1, true
			}
			return a.Values, end + 1, true
		}
	}
	return nil, -1, false
}
