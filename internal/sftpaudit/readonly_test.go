package sftpaudit

import (
	"bytes"
	"strings"
	"testing"
)

// roSession, politikası olmayan ama SALT-OKUNUR bir oturum kurar.
//
// ⚠️ POLİTİKASIZ KURULUYOR ve bu kasıtlı: salt-okuma kısıtının tek başına
// çalışması gerekiyor. Yalnızca politikayla birlikte çalışsaydı,
// politikasız bir kanal sessizce yazabilirdi.
func roSession(t *testing.T) (*Session, *[]Event, func([]byte) []byte) {
	t.Helper()

	s, got := collect(t)
	s.SetReadOnly(true)

	send := func(pkt []byte) []byte {
		var out []byte
		if err := s.fromClient.writeTo(pkt, func(b []byte) error {
			out = append(out, b...)
			return nil
		}); err != nil {
			t.Fatalf("çözümleyici hata verdi: %v", err)
		}
		return out
	}

	return s, got, send
}

/*
 * Değiştiren her istek reddediliyor.
 *
 * ⚠️ LİSTE TAM OLMALI: eksik kalan tek tür, "salt-okunur" sözünü boşa
 * çıkarır. Tanımadığımız türler zaten reddediliyor (politika açık
 * sayıldığı için), yani buradaki risk TANIDIĞIMIZ ama listeye
 * konmamış bir tür.
 */
func TestReadOnlyRefusesEveryMutation(t *testing.T) {
	cases := []struct {
		name string
		pkt  []byte
	}{
		{"yazma bayraklı open", newPkt(fxpOpen).u32(1).str("/a").u32(flagWrite).u32(0).bytes()},
		{"creat", newPkt(fxpOpen).u32(1).str("/a").u32(flagCreat).u32(0).bytes()},
		{"trunc", newPkt(fxpOpen).u32(1).str("/a").u32(flagTrunc).u32(0).bytes()},
		{"append", newPkt(fxpOpen).u32(1).str("/a").u32(flagAppend).u32(0).bytes()},
		{"remove", newPkt(fxpRemove).u32(1).str("/a").bytes()},
		{"rmdir", newPkt(fxpRmdir).u32(1).str("/a").bytes()},
		{"mkdir", newPkt(fxpMkdir).u32(1).str("/a").bytes()},
		{"setstat", newPkt(fxpSetstat).u32(1).str("/a").bytes()},
		{"rename", newPkt(fxpRename).u32(1).str("/a").str("/b").bytes()},
		{"symlink", newPkt(fxpSymlink).u32(1).str("/a").str("/b").bytes()},
		{"link", newPkt(21).u32(1).str("/a").str("/b").bytes()},
		{"posix-rename", newPkt(fxpExtended).u32(1).str("posix-rename@openssh.com").str("/a").str("/b").bytes()},
		{"hardlink", newPkt(fxpExtended).u32(1).str("hardlink@openssh.com").str("/a").str("/b").bytes()},
		{"lsetstat", newPkt(fxpExtended).u32(1).str("lsetstat@openssh.com").str("/a").bytes()},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, got, send := roSession(t)

			if out := send(c.pkt); len(out) != 0 {
				t.Fatalf("%s hedefe geçti", c.name)
			}
			if len(*got) != 1 || (*got)[0].OK {
				t.Fatalf("ret defterine düşmedi: %+v", *got)
			}
			if d := (*got)[0].Detail; !strings.Contains(d, "read-only") {
				t.Errorf("gerekçe salt-okumayı söylemiyor: %q", d)
			}
			if len(s.TakeDenials()) != 1 {
				t.Error("istemciye cevap hazırlanmadı")
			}
		})
	}
}

/*
 * ⚠️ FXP_WRITE AÇIKTAN REDDEDİLİYOR, "OPEN zaten reddedildi" DİYE DEĞİL.
 *
 * Yazma tanıtıcısı oluşamayacağı için buraya gelinemez — ama o akıl
 * yürütme kısıtı HEDEFİN açma kipini uygulamasına bağlar. Bastion kendi
 * kısıtını kendi uygulamalı; test bu yüzden tanıtıcıyı okuma kipinde
 * açtırıp üzerine yazmayı deniyor.
 */
func TestReadOnlyRefusesWritingToAReadHandle(t *testing.T) {
	s, got, send := roSession(t)

	// Okuma kipinde açma: izinli.
	if out := send(newPkt(fxpOpen).u32(1).str("/a").u32(flagRead).u32(0).bytes()); len(out) == 0 {
		t.Fatal("okuma kipinde açma reddedildi")
	}
	if err := s.FromTarget(newPkt(fxpHandle).u32(1).str("h1").bytes()); err != nil {
		t.Fatal(err)
	}

	// Aynı tanıtıcıya yazma: reddedilmeli.
	out := send(newPkt(fxpWrite).u32(2).str("h1").u64(0).str("veri").bytes())
	if len(out) != 0 {
		t.Fatal("SALT-OKUNUR OTURUMDA YAZMA HEDEFE GEÇTİ")
	}

	var refused bool
	for _, e := range *got {
		if strings.HasPrefix(string(e.Op), "denied.") && strings.Contains(e.Detail, "read-only") {
			refused = true
		}
	}
	if !refused {
		t.Fatalf("ret defterine düşmedi: %+v", *got)
	}
}

// Okuma yolu bozulmuyor: gezinme ve okuma serbest.
func TestReadOnlyLeavesReadingAlone(t *testing.T) {
	s, got, send := roSession(t)

	pkts := [][]byte{
		newPkt(fxpOpen).u32(1).str("/a").u32(flagRead).u32(0).bytes(),
		newPkt(fxpOpendir).u32(2).str("/d").bytes(),
		newPkt(fxpStat).u32(3).str("/a").bytes(),
		newPkt(fxpRealpath).u32(4).str(".").bytes(),
		newPkt(fxpReadlink).u32(5).str("/a").bytes(),
	}
	for i, pkt := range pkts {
		if out := send(pkt); !bytes.Equal(out, pkt) {
			t.Fatalf("%d. okuma isteği reddedildi", i)
		}
	}
	for _, e := range *got {
		if strings.HasPrefix(string(e.Op), "denied.") {
			t.Fatalf("okuma yolunda ret: %+v", e)
		}
	}
	if n := len(s.TakeDenials()); n != 0 {
		t.Errorf("okuma yolunda %d ret cevabı", n)
	}
}

// Kısıt kapalıyken hiçbir şey değişmiyor.
func TestWithoutReadOnlyMutationsPass(t *testing.T) {
	s, got := collect(t)

	pkt := newPkt(fxpRemove).u32(1).str("/a").bytes()
	var out []byte
	if err := s.fromClient.writeTo(pkt, func(b []byte) error {
		out = append(out, b...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(out, pkt) {
		t.Fatal("kısıt kapalıyken istek engellendi")
	}
	for _, e := range *got {
		if strings.HasPrefix(string(e.Op), "denied.") {
			t.Fatalf("kısıt kapalıyken ret: %+v", e)
		}
	}
}
