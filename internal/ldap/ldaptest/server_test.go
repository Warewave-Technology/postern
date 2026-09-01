package ldaptest

import (
	"testing"

	goldap "github.com/go-ldap/ldap/v3"
)

/*
 * ⚠️ TEST ALTYAPISININ KENDİSİ DE KANITLANMALI.
 *
 * Bu paket, postern'in LDAP kodunu sınamak için var. Kendisi bozuksa,
 * onunla yazılan her test "geçiyor" der ve hiçbir şey ölçmemiş olur —
 * yanlış bir yeşil, hiç testten kötüdür. Aşağıdakiler gerçek go-ldap
 * istemcisiyle konuşuyor: bağlanabiliyor, arayabiliyor, ve asıl
 * derdimiz olan iki AD davranışını gerçekten üretebiliyor mu?
 */

func dial(t *testing.T, s *Server) *goldap.Conn {
	t.Helper()
	c, err := goldap.DialURL(s.URL())
	if err != nil {
		t.Fatalf("sahte sunucuya bağlanılamadı: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestFakeServerSpeaksLDAP(t *testing.T) {
	s, err := New(func(base, filter string, attrs []string) Response {
		return Response{Entries: []Entry{{
			DN:    "uid=yigit," + base,
			Attrs: map[string][]string{"uid": {"yigit"}, "cn": {"Yigit"}},
		}}}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	conn := dial(t, s)
	if err := conn.Bind("cn=okuyucu,dc=test", "sifre"); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if b := s.Binds(); len(b) != 1 || b[0] != "cn=okuyucu,dc=test" {
		t.Fatalf("bind DN sunucuya ulaşmadı: %v", b)
	}

	res, err := conn.Search(goldap.NewSearchRequest(
		"dc=test", goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		0, 0, false, "(uid=yigit)", []string{"uid", "cn"}, nil))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("kayıt sayısı = %d", len(res.Entries))
	}
	if got := res.Entries[0].GetAttributeValue("cn"); got != "Yigit" {
		t.Fatalf("cn = %q", got)
	}
	if res.Entries[0].DN != "uid=yigit,dc=test" {
		t.Fatalf("DN = %q — base handler'a geçmemiş", res.Entries[0].DN)
	}
}

func TestFakeServerPassesTheFilter(t *testing.T) {
	var seen string
	s, err := New(func(base, filter string, attrs []string) Response {
		seen = filter
		return Response{}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	conn := dial(t, s)
	_ = conn.Bind("cn=a", "b")
	_, _ = conn.Search(goldap.NewSearchRequest(
		"dc=test", goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		0, 0, false, "(sAMAccountName=ayse)", nil, nil))

	if seen != "(sAMAccountName=ayse)" {
		t.Fatalf("filtre = %q — handler aranan değeri göremiyor", seen)
	}
}

/*
 * ⚠️ ARALIKLI NİTELİK GERÇEKTEN ÜRETİLEBİLİYOR MU?
 *
 * Bu paketin bütün varlık sebebi bu: OpenLDAP `member;range=0-1499`
 * göndermiyor, AD gönderiyor. Sahte sunucu bunu üretemiyorsa, onunla
 * yazılan "aralıklı getirme çalışıyor" testi hiçbir şey ölçmez.
 */
func TestFakeServerProducesRangedAttributes(t *testing.T) {
	s, err := New(func(base, filter string, attrs []string) Response {
		return Response{Entries: []Entry{{
			DN: "cn=buyuk,dc=test",
			Attrs: map[string][]string{
				"member;range=0-1": {"cn=a,dc=test", "cn=b,dc=test"},
			},
		}}}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	conn := dial(t, s)
	_ = conn.Bind("cn=a", "b")
	res, err := conn.Search(goldap.NewSearchRequest(
		"dc=test", goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		0, 0, false, "(cn=buyuk)", []string{"member"}, nil))
	if err != nil {
		t.Fatal(err)
	}

	e := res.Entries[0]
	// DÜZ member BOŞ olmalı — AD'nin davranışı tam olarak bu ve
	// postern'in eski kodunun 5000 kişilik grubu boş görmesinin sebebi.
	if v := e.GetAttributeValues("member"); len(v) != 0 {
		t.Fatalf("düz member dolu geldi (%v) — AD davranışı taklit edilmiyor", v)
	}
	var found bool
	for _, a := range e.Attributes {
		if a.Name == "member;range=0-1" && len(a.Values) == 2 {
			found = true
		}
	}
	if !found {
		t.Fatalf("aralıklı nitelik istemciye ulaşmadı: %+v", e.Attributes)
	}
}

/*
 * ⚠️ YÖNLENDİRME, BOŞ SONUÇTAN AYIRT EDİLEBİLİR OLMALI.
 *
 * AD, yanlış base DN'e sorulduğunda cevap yerine "şuraya sor" döner.
 * Bunu boş sonuçla karıştıran bir istemci "kullanıcı yok" der ve
 * erişimi yanlışlıkla keser.
 */
func TestFakeServerReturnsReferrals(t *testing.T) {
	s, err := New(func(base, filter string, attrs []string) Response {
		return Response{
			ResultCode: 10, // referral
			Referrals:  []string{"ldap://baska.example.com/DC=baska,DC=example,DC=com"},
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	conn := dial(t, s)
	_ = conn.Bind("cn=a", "b")
	res, err := conn.Search(goldap.NewSearchRequest(
		"dc=yanlis", goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		0, 0, false, "(uid=yigit)", nil, nil))
	if err != nil {
		// go-ldap referral sonuç kodunu hata sayabiliyor; testin
		// konusu referral'ın TAŞINMASI, hata sarmalanması değil.
		if !goldap.IsErrorWithCode(err, 10) {
			t.Fatalf("search: %v", err)
		}
		return
	}
	if len(res.Entries) != 0 {
		t.Fatal("yönlendirmeyle birlikte kayıt döndü")
	}
	if len(res.Referrals) == 0 {
		t.Fatal("yönlendirme istemciye ulaşmadı — boş sonuçtan ayırt edilemez")
	}
}

func TestFakeServerCanRefuseBinds(t *testing.T) {
	s, err := New(func(string, string, []string) Response { return Response{} })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.RefuseBinds(49) // invalidCredentials

	conn := dial(t, s)
	if err := conn.Bind("cn=a", "yanlis"); err == nil {
		t.Fatal("reddedilmesi gereken bind geçti")
	}
}
