package ldap

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/ldap/ldaptest"
)

/*
 * ⚠️ ACTIVE DIRECTORY'NİN ARALIKLI GETİRMESİ (ranged retrieval).
 *
 * ÖLÇÜLEN ARIZA: AD, yaklaşık 1500 üyeden büyük bir grupta `member`
 * niteliğini HİÇ göndermiyor; yerine `member;range=0-1499` gönderiyor ve
 * kalanı ayrıca istemeni bekliyor. Bunu bilmeyen istemci, 5000 kişilik
 * bir grubu BOŞ görür.
 *
 * Burada bunun ne demek olduğu önemli: MembersOf, YÖNETİCİ GRUBU ONAY
 * EKRANINI besliyor. Ekran "şu kişiler yönetici olacak" diyor ve
 * yönetici ona bakıp onaylıyor. Aralıklı getirme ele alınmazsa, ekran
 * EN BÜYÜK — yani en tehlikeli — grupları "kimse yok" diye gösterir;
 * yönetici zararsız sanıp onaylar ve 5000 kişi bir sonraki girişinde
 * yönetici olur. members.go'nun kendi yorumu bunu şöyle yazıyor:
 * "önizleme girişten farklı bir gerçeği gösterir — onay ekranının
 * yapabileceği en kötü şey".
 *
 * Gerçek OpenLDAP bu davranışı üretmiyor, o yüzden entegrasyon testleri
 * bunu YAKALAYAMAZ (bkz. ldaptest paketi).
 */
func TestRangedGroupMembersAreNotSeenAsEmpty(t *testing.T) {
	// 1500 üyeli bir AD grubu: ilk dilim range=0-1499, sonra range=1500-*.
	const first, total = 1500, 1600
	srv, err := ldaptest.New(func(base, filter string, attrs []string) ldaptest.Response {
		// Hangi dilim isteniyor? İstemci "member;range=1500-*" diye sorar.
		want := ""
		for _, a := range attrs {
			if len(a) > 7 && a[:7] == "member;" {
				want = a
			}
		}

		e := ldaptest.Entry{DN: "cn=buyuk,ou=groups,dc=test", Attrs: map[string][]string{}}
		if want == "" {
			// İlk sorgu: AD düz `member` yerine ilk dilimi veriyor.
			vals := make([]string, first)
			for i := range vals {
				vals[i] = fmt.Sprintf("cn=uye%04d,ou=people,dc=test", i)
			}
			e.Attrs["member;range=0-1499"] = vals
		} else {
			// Devam sorgusu: kalanlar ve SON dilim işareti (range=1500-*).
			vals := make([]string, total-first)
			for i := range vals {
				vals[i] = fmt.Sprintf("cn=uye%04d,ou=people,dc=test", first+i)
			}
			e.Attrs["member;range=1500-*"] = vals
		}
		return ldaptest.Response{Entries: []ldaptest.Entry{e}}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	src, err := New(Config{
		URL: srv.URL(), BindDN: "cn=okuyucu,dc=test", BindPassword: "s",
		UserBase: "ou=people,dc=test", UserFilter: "(cn=%s)",
		GroupBase: "ou=groups,dc=test", GroupFilter: "(member=%s)",
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := src.MembersOf(context.Background(), "buyuk")
	if err != nil {
		t.Fatalf("MembersOf: %v", err)
	}

	if len(got.Usernames) == 0 {
		t.Fatal("aralıklı nitelik gönderen bir grup BOŞ görüldü — onay " +
			"ekranı en büyük grupları 'kimse yok' diye gösterir ve " +
			"yönetici 1600 kişilik bir yetkiyi zararsız sanarak onaylar")
	}
	// Önizleme sınırı (maxGroupMembers) uygulanmalı AMA kesildiği
	// SÖYLENMELİ: sessizce kırpılmış liste "hepsi bu" sandırır.
	if len(got.Usernames) != maxGroupMembers {
		t.Fatalf("üye sayısı = %d, önizleme sınırı %d bekleniyordu",
			len(got.Usernames), maxGroupMembers)
	}
	if !got.Truncated {
		t.Error("liste kesildi ama Truncated=false — ekran 'hepsi bu' der")
	}
	if got.Usernames[0] != "uye0000" {
		t.Errorf("ilk üye = %q", got.Usernames[0])
	}
}

/*
 * Aralıklı olmayan (sıradan) grup eskisi gibi çalışmalı: düzeltme,
 * OpenLDAP yolunu bozmamalı.
 */
func TestPlainGroupMembersStillWork(t *testing.T) {
	srv, err := ldaptest.New(func(base, filter string, attrs []string) ldaptest.Response {
		return ldaptest.Response{Entries: []ldaptest.Entry{{
			DN: "cn=kucuk,ou=groups,dc=test",
			Attrs: map[string][]string{
				"member": {"cn=ayse,ou=people,dc=test", "cn=veli,ou=people,dc=test"},
			},
		}}}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	src, err := New(Config{
		URL: srv.URL(), BindDN: "cn=okuyucu,dc=test", BindPassword: "s",
		UserBase: "ou=people,dc=test", UserFilter: "(cn=%s)",
		GroupBase: "ou=groups,dc=test", GroupFilter: "(member=%s)",
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := src.MembersOf(context.Background(), "kucuk")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Usernames) != 2 || got.Usernames[0] != "ayse" {
		t.Fatalf("sıradan grup bozuldu: %+v", got)
	}
	if got.Truncated {
		t.Error("kesilmediği hâlde Truncated=true")
	}
}

/*
 * ⚠️ TEK DİLİM YETMEDİĞİNDE DEVAMI İSTENMELİ.
 *
 * AD'nin ilk dilimi genelde 1500 ve önizleme sınırını tek başına
 * doldurduğu için döngü fiilen bir kez çalışıyor. Ama dizin küçük
 * dilimler verirse (yapılandırılabilir bir sınır), devamını istemeyen
 * bir istemci grubun geri kalanını hiç görmez. Burada dilim BİLEREK
 * küçük.
 */
func TestSmallRangeChunksAreFollowed(t *testing.T) {
	const chunk = 5
	var queries int

	srv, err := ldaptest.New(func(base, filter string, attrs []string) ldaptest.Response {
		queries++
		// İstenen dilimin başlangıcını çıkar.
		start := 0
		for _, a := range attrs {
			if s, ok := strings.CutPrefix(strings.ToLower(a), "member;range="); ok {
				lo, _, _ := strings.Cut(s, "-")
				start, _ = strconv.Atoi(lo)
			}
		}

		e := ldaptest.Entry{DN: "cn=orta,ou=groups,dc=test", Attrs: map[string][]string{}}
		var vals []string
		for i := start; i < start+chunk && i < 12; i++ {
			vals = append(vals, fmt.Sprintf("cn=uye%02d,ou=people,dc=test", i))
		}
		last := start+chunk >= 12
		name := fmt.Sprintf("member;range=%d-%d", start, start+len(vals)-1)
		if last {
			name = fmt.Sprintf("member;range=%d-*", start)
		}
		e.Attrs[name] = vals
		return ldaptest.Response{Entries: []ldaptest.Entry{e}}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	src, err := New(Config{
		URL: srv.URL(), BindDN: "cn=okuyucu,dc=test", BindPassword: "s",
		UserBase: "ou=people,dc=test", UserFilter: "(cn=%s)",
		GroupBase: "ou=groups,dc=test", GroupFilter: "(member=%s)",
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := src.MembersOf(context.Background(), "orta")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Usernames) != 12 {
		t.Fatalf("üye sayısı = %d, 12 bekleniyordu — devam dilimleri "+
			"istenmemiş: %v", len(got.Usernames), got.Usernames)
	}
	if got.Truncated {
		t.Error("tamamı alındığı hâlde Truncated=true")
	}
	if queries < 3 {
		t.Errorf("sorgu sayısı = %d — dilimler tek seferde gelmiş olamaz", queries)
	}
}

/*
 * ⚠️ YÖNLENDİRME, "KULLANICI YOK" DEĞİLDİR.
 *
 * ÖLÇÜLEN ARIZA: yanlış base DN'e sorulduğunda AD, cevap yerine
 * "şuraya sor" döner ve sonuç kümesi BOŞ gelir. Boş sonucu "böyle bir
 * kullanıcı yok" diye okuyan bir istemci, aslında var olan bir kişiyi
 * yok sayar — ve bu kod tabanında "yok" ile "çözülemedi" farklı
 * kararlar üretiyor (presence.go).
 *
 * Bu yol ldap.go'da yazılıydı ama HİÇ test edilememişti: OpenLDAP
 * yönlendirme üretmiyor.
 */
func TestReferralIsNotReadAsAMissingUser(t *testing.T) {
	srv, err := ldaptest.New(func(base, filter string, attrs []string) ldaptest.Response {
		return ldaptest.Response{
			Referrals: []string{"ldap://baska.example.com/DC=baska,DC=example,DC=com"},
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	src, err := New(Config{
		URL: srv.URL(), BindDN: "cn=okuyucu,dc=test", BindPassword: "s",
		UserBase: "dc=yanlis", UserFilter: "(cn=%s)",
		GroupAttribute: "memberOf",
		GroupBase:      "ou=groups,dc=test",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = src.Lookup(context.Background(), auth.Identity{Username: "yigit"})
	if err == nil {
		t.Fatal("yönlendirme sessizce 'kullanıcı yok' diye okundu — var " +
			"olan bir kişi yok sayılır ve erişimi kesilir")
	}
	// Hata operatöre NE YAPACAĞINI söylemeli: teşhis edilemeyen bir
	// yönlendirme, günlerce "kullanıcı bulunamıyor" olarak yaşar.
	msg := err.Error()
	for _, want := range []string{"referral", "user_base"} {
		if !strings.Contains(msg, want) {
			t.Errorf("hata %q içermiyor: %v", want, msg)
		}
	}
}
