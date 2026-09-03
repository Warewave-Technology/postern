// Package ldaptest, testler için küçük bir LDAP sunucusu sağlar.
//
// ⚠️ NEDEN VAR — VE NİYE GERÇEK OpenLDAP YETMİYOR:
//
// Entegrasyon testleri gerçek OpenLDAP'a karşı koşuyor ve sıradan
// yolları iyi kapsıyor. Ama postern'in en riskli iki LDAP davranışını
// OpenLDAP ÜRETEMİYOR, çünkü ikisi de Active Directory'ye özgü:
//
//  1. ARALIKLI GETİRME (ranged retrieval). AD, ~1500 üyeden büyük bir
//     grupta `member` yerine `member;range=0-1499` döner ve DÜZ member
//     niteliğini HİÇ göndermez. Bunu bilmeyen bir istemci, 5000
//     kişilik bir grubu BOŞ görür.
//  2. YÖNLENDİRME (referral). Yanlış base DN'e sorulduğunda AD, cevap
//     yerine "şuraya sor" döner. Bunu boş sonuçla karıştıran bir
//     istemci, "kullanıcı yok" der.
//
// İkisi de sessiz ve yanlış bir cevap üretiyor — ve bu kod tabanının
// üç değerli varlık modeli (bkz. presence.go) tam olarak bunun için
// var. Test edilemeyen bir "çözülemedi" yolu, hiç yazılmamış gibidir.
package ldaptest

import (
	"fmt"
	"net"
	"strings"
	"sync"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// LDAP uygulama etiketleri (RFC 4511 §4.1.1).
const (
	appBindRequest        = 0
	appBindResponse       = 1
	appUnbindRequest      = 2
	appSearchRequest      = 3
	appSearchResultEntry  = 4
	appSearchResultDone   = 5
	appSearchResultRefRaw = 19
)

// Entry, döndürülecek bir dizin kaydı.
type Entry struct {
	DN string
	// Attrs, nitelik adı → değerler. Ad "member;range=0-1499" gibi
	// SEÇENEKLİ de olabilir — bu paketin var olma sebebi zaten o.
	Attrs map[string][]string
}

/*
 * Response, bir aramaya verilecek cevap.
 *
 * Referrals dolu ve Entries boşsa, sunucu AD'nin yaptığını yapıyor:
 * cevap yerine yönlendirme. Bu ikisini AYIRT edebilmek testin konusu.
 */
type Response struct {
	Entries   []Entry
	Referrals []string
	// ResultCode 0 dışında ise arama hatayla biter.
	ResultCode uint8
	Diagnostic string
}

// Server, tek bağlantılı basit bir LDAP dinleyicisi.
type Server struct {
	ln net.Listener

	mu sync.Mutex
	// handler, her arama isteği için çağrılıyor.
	handler func(baseDN, filter string, attrs []string) Response
	// binds, gelen bind DN'leri — testler kimliğin doğru gittiğini
	// görebilsin.
	binds []string
	// bindErr, 0 dışında ise bind reddediliyor.
	bindErr uint8
	// refuseDN dolu ise YALNIZCA o DN'in bind'i bindErr ile reddedilir;
	// diğer bind'ler (ör. okuyucu bind'i) geçer. "Yanlış parola"yı
	// gerçekçi kılmak için: arama bind'i başarılı, kullanıcı bind'i
	// başarısız.
	refuseDN string
}

// New, dinlemeye başlar ve adresi döner.
func New(handler func(baseDN, filter string, attrs []string) Response) (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Server{ln: ln, handler: handler}
	go s.accept()
	return s, nil
}

// URL, ldap:// adresi.
func (s *Server) URL() string { return "ldap://" + s.ln.Addr().String() }

// Close, dinleyiciyi kapatır.
func (s *Server) Close() error { return s.ln.Close() }

// Binds, şimdiye kadar gelen bind DN'leri.
func (s *Server) Binds() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.binds...)
}

// RefuseBinds, bind'leri verilen kodla reddettirir (49 = invalidCredentials).
func (s *Server) RefuseBinds(code uint8) {
	s.mu.Lock()
	s.bindErr = code
	s.refuseDN = ""
	s.mu.Unlock()
}

// RefuseBindFor, YALNIZCA verilen DN'in bind'ini reddeder; başka DN'ler
// geçer. Gerçek bir "yanlış parola" akışını taklit etmek için: okuyucu
// bind'i başarılı, kullanıcı bind'i başarısız.
func (s *Server) RefuseBindFor(dn string, code uint8) {
	s.mu.Lock()
	s.bindErr = code
	s.refuseDN = dn
	s.mu.Unlock()
}

func (s *Server) accept() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.serve(conn)
	}
}

func (s *Server) serve(conn net.Conn) {
	defer conn.Close()
	for {
		packet, err := ber.ReadPacket(conn)
		if err != nil {
			return
		}
		if len(packet.Children) < 2 {
			return
		}
		msgID := readInt(packet.Children[0])
		req := packet.Children[1]

		switch req.Tag {
		case appBindRequest:
			s.mu.Lock()
			var dn string
			if len(req.Children) >= 2 {
				dn = readStr(req.Children[1])
				s.binds = append(s.binds, dn)
			}
			code := s.bindErr
			if s.refuseDN != "" && dn != s.refuseDN {
				code = 0 // bu DN hedef değil: geç
			}
			s.mu.Unlock()
			if err := write(conn, bindResponse(msgID, code)); err != nil {
				return
			}

		case appUnbindRequest:
			return

		case appSearchRequest:
			resp := s.dispatch(req)
			for _, e := range resp.Entries {
				if err := write(conn, entryPacket(msgID, e)); err != nil {
					return
				}
			}
			for _, r := range resp.Referrals {
				if err := write(conn, referralPacket(msgID, r)); err != nil {
					return
				}
			}
			if err := write(conn, donePacket(msgID, resp)); err != nil {
				return
			}

		default:
			// Bilmediğimiz istek: bağlantıyı kapatmak yerine sessizce
			// geçiyoruz ki test, asıl ilgilendiği isteğe ulaşsın.
		}
	}
}

// dispatch, arama isteğini çözüp handler'a verir.
func (s *Server) dispatch(req *ber.Packet) Response {
	var base, filter string
	var attrs []string
	if len(req.Children) > 0 {
		base = readStr(req.Children[0])
	}
	if len(req.Children) > 6 {
		filter = decodeFilter(req.Children[6])
	}
	if len(req.Children) > 7 {
		for _, a := range req.Children[7].Children {
			attrs = append(attrs, readStr(a))
		}
	}
	s.mu.Lock()
	h := s.handler
	s.mu.Unlock()
	if h == nil {
		return Response{}
	}
	return h(base, filter, attrs)
}

// --- paket kurucular --------------------------------------------------

func write(conn net.Conn, p *ber.Packet) error {
	_, err := conn.Write(p.Bytes())
	return err
}

func envelope(msgID int, child *ber.Packet) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, "MessageID"))
	p.AppendChild(child)
	return p
}

// result, LDAPResult üçlüsünü (kod, matchedDN, mesaj) taşıyan gövde.
func result(tag ber.Tag, code uint8, diagnostic string, referrals []string) *ber.Packet {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "Response")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(code), "resultCode"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, diagnostic, "diagnosticMessage"))
	if len(referrals) > 0 {
		// Referral [3] — LDAPResult'ın isteğe bağlı son alanı.
		ref := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "referral")
		for _, u := range referrals {
			ref.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, u, "uri"))
		}
		p.AppendChild(ref)
	}
	return p
}

func bindResponse(msgID int, code uint8) *ber.Packet {
	return envelope(msgID, result(appBindResponse, code, "", nil))
}

func donePacket(msgID int, r Response) *ber.Packet {
	// ⚠️ Yönlendirme, SearchResultDone'ın referral alanında dönüyor —
	// go-ldap onu res.Referrals'a koyuyor. AD'nin yaptığı da bu.
	return envelope(msgID, result(appSearchResultDone, r.ResultCode, r.Diagnostic, r.Referrals))
}

// referralPacket, SearchResultReference (ayrı mesaj biçimi).
func referralPacket(msgID int, uri string) *ber.Packet {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appSearchResultRefRaw, nil, "SearchResultReference")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, uri, "uri"))
	return envelope(msgID, p)
}

func entryPacket(msgID int, e Entry) *ber.Packet {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appSearchResultEntry, nil, "SearchResultEntry")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.DN, "objectName"))

	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for name, values := range e.Attrs {
		a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attribute")
		a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "type"))
		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
		for _, v := range values {
			set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "val"))
		}
		a.AppendChild(set)
		attrs.AppendChild(a)
	}
	p.AppendChild(attrs)
	return envelope(msgID, p)
}

// --- okuma yardımcıları -----------------------------------------------

func readInt(p *ber.Packet) int {
	if v, ok := p.Value.(int64); ok {
		return int(v)
	}
	return 0
}

func readStr(p *ber.Packet) string {
	if s, ok := p.Value.(string); ok {
		return s
	}
	return string(p.ByteValue)
}

/*
 * decodeFilter, filtreyi KABACA metne çevirir.
 *
 * Tam bir çözümleyici değil ve olmamalı: handler'ların ihtiyacı
 * "hangi değer arandı" — testler filtreyi eşitlik üzerinden ayırt
 * ediyor. Tam çözümleyici yazmak, test altyapısını test edilmesi
 * gereken ikinci bir yazılıma çevirirdi.
 */
func decodeFilter(p *ber.Packet) string {
	switch p.Tag {
	case 3: // equalityMatch
		if len(p.Children) == 2 {
			return fmt.Sprintf("(%s=%s)", readStr(p.Children[0]), readStr(p.Children[1]))
		}
	case 0, 1: // and / or
		var parts []string
		for _, c := range p.Children {
			parts = append(parts, decodeFilter(c))
		}
		return "(" + strings.Join(parts, "") + ")"
	case 7: // present
		return fmt.Sprintf("(%s=*)", string(p.ByteValue))
	}
	return ""
}
