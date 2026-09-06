package sftpaudit

import (
	"bytes"
	"strings"
	"testing"
)

// denyPaths, verilen yolları reddeden basit bir politika.
func denyPaths(bad ...string) Decider {
	return func(r Request) (bool, string) {
		for _, b := range bad {
			if r.Path == b || r.NewPath == b {
				return false, "path is not permitted"
			}
		}
		return true, ""
	}
}

// runPolicy, paketleri politikalı bir oturumdan geçirir ve hedefe İLETİLEN
// baytları döndürür.
func runPolicy(t *testing.T, d Decider, pkts ...[]byte) (*Session, *[]Event, []byte) {
	t.Helper()

	s, got := collect(t)
	s.SetPolicy(d)

	var out []byte
	for _, pkt := range pkts {
		if err := s.fromClient.writeTo(pkt, func(b []byte) error {
			out = append(out, b...)
			return nil
		}); err != nil {
			t.Fatalf("çözümleyici hata verdi: %v", err)
		}
	}

	return s, got, out
}

// Reddedilen açma isteği hedefe HİÇ ulaşmıyor, deftere düşüyor ve
// istemciye cevabı hazırlanıyor.
func TestDeniedOpenIsRefusedRecordedAndAnswered(t *testing.T) {
	pkt := newPkt(fxpOpen).u32(7).str("/etc/shadow").u32(flagRead).u32(0).bytes()

	s, got, out := runPolicy(t, denyPaths("/etc/shadow"), pkt)

	if len(out) != 0 {
		t.Fatalf("reddedilen istekten %d bayt hedefe gitti", len(out))
	}
	if len(*got) != 1 || (*got)[0].Op != OpOpen || (*got)[0].OK {
		t.Fatalf("ret defterine düşmedi: %+v", *got)
	}
	if d := (*got)[0].Detail; !strings.Contains(d, "postern:") {
		t.Errorf("detail = %q; reddin postern'den geldiği görünmeli", d)
	}

	denials := s.TakeDenials()
	if len(denials) != 1 {
		t.Fatalf("istemciye cevap hazırlanmadı: %d", len(denials))
	}
	_, id, code, _ := parseStatus(t, denials[0], len(denials[0]))
	if id != 7 {
		t.Errorf("cevabın istek kimliği %d, 7 bekleniyordu — istemci eşleyemez", id)
	}
	if code != StatusPermissionDenied {
		t.Errorf("durum kodu %d", code)
	}
	if n := len(s.TakeDenials()); n != 0 {
		t.Errorf("cevaplar iki kez alındı: %d", n)
	}
}

/*
 * ⚠️ NORMALLEŞTİRME OLMADAN KORUMA KÂĞIT ÜZERİNDE KALIR. İstemci
 * `/veri/../etc/shadow` yazıyor, hedef bunu `/etc/shadow` olarak çözüyor;
 * politikaya ham dizgiyi verseydik eşleşme olmaz ve istek geçerdi.
 */
func TestPathIsNormalisedBeforeThePolicySeesIt(t *testing.T) {
	for _, raw := range []string{
		"/veri/../etc/shadow",
		"/etc/./shadow",
		"//etc//shadow",
		"/etc/foo/../shadow",
	} {
		pkt := newPkt(fxpOpen).u32(1).str(raw).u32(flagRead).u32(0).bytes()
		_, got, out := runPolicy(t, denyPaths("/etc/shadow"), pkt)

		if len(out) != 0 {
			t.Errorf("%q normalleştirilmeden geçti", raw)
		}
		if len(*got) != 1 || (*got)[0].OK {
			t.Errorf("%q: ret defterine düşmedi", raw)
		}
	}
}

// Mutlak olmayan yol reddediliyor: neye göre olduğunu bilmiyoruz.
func TestRelativePathIsRefused(t *testing.T) {
	pkt := newPkt(fxpOpen).u32(1).str("gizli.txt").u32(flagRead).u32(0).bytes()

	_, got, out := runPolicy(t, denyPaths("/yok"), pkt)

	if len(out) != 0 {
		t.Fatal("göreli yol geçti")
	}
	if len(*got) != 1 || !strings.Contains((*got)[0].Detail, "absolute") {
		t.Fatalf("ret sebebi açık değil: %+v", *got)
	}
}

/*
 * ⚠️ REALPATH İSTİSNA — VE BU İSTİSNA ZORUNLU. OpenSSH'in sftp istemcisi
 * oturumun İLK isteği olarak `realpath "."` gönderiyor. Onu da reddetseydik
 * politika açık her oturum daha başlarken kırılırdı. REALPATH bir ADI
 * çözüyor; ardından gelen açma isteği mutlak yolla gelip karara bağlanıyor.
 */
func TestRealpathOfARelativeNameIsAllowed(t *testing.T) {
	pkt := newPkt(fxpRealpath).u32(1).str(".").bytes()

	_, got, out := runPolicy(t, denyPaths("/yok"), pkt)

	if !bytes.Equal(out, pkt) {
		t.Fatal("realpath \".\" reddedildi; politika açık her oturum başlarken kırılırdı")
	}
	if len(*got) != 0 {
		t.Errorf("izin verilen üstveri satır üretti: %+v", *got)
	}
}

// İzin verilen üstveri sessiz kalıyor, reddedilen satır yazıyor.
func TestMetadataIsCoveredButQuietWhenAllowed(t *testing.T) {
	allowed := newPkt(fxpStat).u32(1).str("/home/u/x").bytes()
	denied := newPkt(fxpStat).u32(2).str("/etc/shadow").bytes()

	_, got, out := runPolicy(t, denyPaths("/etc/shadow"), allowed, denied)

	if !bytes.Equal(out, allowed) {
		t.Fatal("izin verilen stat iletilmedi ya da reddedilen sızdı")
	}
	if len(*got) != 1 || (*got)[0].Op != OpStat || (*got)[0].OK {
		t.Fatalf("yalnızca reddedilen stat satır yazmalıydı: %+v", *got)
	}
}

/*
 * Tanımadığımız eklenti ve tanımadığımız tür reddediliyor.
 *
 * ⚠️ copy-data@openssh.com BU TESTİN ASIL SEBEBİ: iki TANITICI alıp
 * içeriği sunucu tarafında kopyalıyor, yani tek bir yol taşımadan veri
 * taşıyor. Yol politikasının eşleşecek bir şeyi yok; geçirmek, politikayı
 * eklenti adıyla atlanabilir kılardı.
 */
func TestUnrecognisedRequestsAreRefused(t *testing.T) {
	cases := []struct {
		name string
		pkt  []byte
	}{
		{"bilinmeyen eklenti", newPkt(fxpExtended).u32(1).str("vendor@example.com").bytes()},
		{"copy-data", newPkt(fxpExtended).u32(2).str("copy-data@openssh.com").
			str("h1").u64(0).u64(16).str("h2").u64(0).bytes()},
		{"bilinmeyen tür", newPkt(22).u32(3).str("h1").bytes()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, got, out := runPolicy(t, denyPaths(), tc.pkt)

			if len(out) != 0 {
				t.Fatal("tanınmayan istek hedefe geçti")
			}
			if len(*got) != 1 || (*got)[0].OK {
				t.Fatalf("ret defterine düşmedi: %+v", *got)
			}
			if len(s.TakeDenials()) != 1 {
				t.Error("istemciye cevap hazırlanmadı; istemci askıda kalır")
			}
		})
	}
}

// Zararsız ve yol taşımayan eklentiler geçiyor: reddetmek sıradan
// istemcileri kırardı.
func TestQuietExtensionsStillPass(t *testing.T) {
	pkt := newPkt(fxpExtended).u32(1).str("fsync@openssh.com").str("h1").bytes()

	_, got, out := runPolicy(t, denyPaths(), pkt)

	if !bytes.Equal(out, pkt) {
		t.Fatal("zararsız eklenti reddedildi")
	}
	if len(*got) != 0 {
		t.Errorf("satır üretti: %+v", *got)
	}
}

/*
 * ⚠️ CLOSE HİÇBİR ZAMAN REDDEDİLMİYOR. Reddetmek tanıtıcıyı hedefte açık
 * bırakır ve transfer özetini yok ederdi — yani denetimin en çok işine
 * yarayan satırı, politikayı uygulayarak kaybederdik.
 */
func TestCloseIsNeverRefused(t *testing.T) {
	open := newPkt(fxpOpen).u32(1).str("/home/u/x").u32(flagRead).u32(0).bytes()
	closePkt := newPkt(fxpClose).u32(2).str("h1").bytes()

	s, _ := collect(t)
	s.SetPolicy(func(Request) (bool, string) { return false, "her şeyi reddet" })

	var out []byte
	fw := func(b []byte) error { out = append(out, b...); return nil }

	if err := s.fromClient.writeTo(open, fw); err != nil {
		t.Fatal(err)
	}
	out = nil
	if err := s.fromClient.writeTo(closePkt, fw); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(out, closePkt) {
		t.Fatal("CLOSE reddedildi: tanıtıcı hedefte açık kalır, transfer özeti kaybolur")
	}
}

// Nereden geldiğini bilmediğimiz tanıtıcı üzerinden okuma reddediliyor.
func TestReadOnAnUnknownHandleIsRefused(t *testing.T) {
	pkt := newPkt(fxpRead).u32(1).str("uydurma").u64(0).u32(64).bytes()

	_, got, out := runPolicy(t, denyPaths(), pkt)

	if len(out) != 0 {
		t.Fatal("tanınmayan tanıtıcıyla okuma geçti")
	}
	if len(*got) != 1 || !strings.Contains((*got)[0].Detail, "handle") {
		t.Fatalf("ret sebebi açık değil: %+v", *got)
	}
}

// Politika yokken hiçbir şey değişmiyor.
func TestNoPolicyMeansNoRefusals(t *testing.T) {
	pkt := newPkt(fxpOpen).u32(1).str("/etc/shadow").u32(flagRead).u32(0).bytes()

	s, _, out := runPolicy(t, nil, pkt)

	if !bytes.Equal(out, pkt) {
		t.Fatal("politika yokken istek engellendi")
	}
	if len(s.TakeDenials()) != 0 {
		t.Error("politika yokken cevap üretildi")
	}
}
