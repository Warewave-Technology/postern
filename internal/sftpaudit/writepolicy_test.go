package sftpaudit

import (
	"strings"
	"testing"
)

/*
 * ⚠️ BU DOSYANIN ÖLÇTÜĞÜ ŞEY, YÜKLEMEYİ AÇMANIN ÖN KOŞULU.
 *
 * FXP_WRITE bir YOL taşımıyor, tanıtıcı taşıyor. Eskiden tanıdık bir
 * tanıtıcı görüldüğü an istek politikaya HİÇ sorulmadan geçiyordu ve
 * gerekçe "yolu açan istek zaten karara bağlandı" idi. O gerekçe eksik:
 * istemci yolu OKUMA bayrağıyla açıp (politika izin verir) aynı tanıtıcı
 * üzerine yazma gönderdiğinde, kısıtı uygulayan tek şey HEDEFİN açma
 * kipi oluyordu — yani bastion kendi kuralını hedefe emanet ediyordu.
 * Bu, hemen yanındaki salt-okuma dalının kendisi için yazdığı gerekçenin
 * aynısı.
 *
 * Panel salt-okunur olduğu sürece görünmüyordu. Yükleme açılacaksa önce
 * buranın kapanması gerekiyor.
 */

// openThenWrite, bir yolu verilen bayrakla açıp o tanıtıcıya yazar.
func openThenWrite(t *testing.T, flags uint32, d Decider) (*Session, []Denial) {
	t.Helper()

	s, _ := collect(t)
	s.SetPolicy(d)

	feedClient(t, s, newPkt(fxpInit).u32(3).bytes())
	feedTarget(t, s, newPkt(fxpVersion).u32(3).bytes())

	feedClient(t, s, newPkt(fxpOpen).u32(1).str("/tmp/dosya").u32(flags).u32(0).bytes())
	feedTarget(t, s, newPkt(fxpHandle).u32(1).str("h1").bytes())
	s.TakeDenials() // açılıştan kalan varsa temizle

	feedClient(t, s, newPkt(fxpWrite).u32(2).str("h1").u64(0).str("veri").bytes())

	return s, s.TakeDenials()
}

/*
 * ⚠️ POLİTİKA YAZMAYI YOLA GÖRE REDDEDEBİLMELİ.
 *
 * can_write bir söz: "bu rol bu ağaca yazabilir". Yazma isteği politikaya
 * hiç sorulmuyorsa o söz ölü harf olur ve geriye yalnızca hedefin dosya
 * izinleri kalır — postern'in koyduğu kural değil, hedefin koyduğu.
 */
func TestWriteIsRefusedWhenThePathIsReadOnlyForTheRole(t *testing.T) {
	var sawWrite bool
	var sawPath string
	readOnlyPath := func(r Request) (bool, string) {
		if r.Write {
			sawWrite = true
			sawPath = r.Path

			return false, "this path is read-only"
		}

		return true, ""
	}

	/*
	 * ⚠️ AÇMA **OKUMA** BAYRAĞIYLA — ve senaryonun tamamı bu.
	 *
	 * Yazma bayraklı bir açma zaten açılışta reddediliyor ve geriye
	 * yazılacak bir tanıtıcı kalmıyor; yani o yoldan test edilen şey
	 * asıl delik değil. Delik şu: yolu OKUMA için açmak politikaya
	 * uygun (izin var), ve sonra aynı tanıtıcı üzerine yazma
	 * göndermek. İşte o istek eskiden politikaya hiç sorulmuyordu.
	 */
	_, denials := openThenWrite(t, flagRead, readOnlyPath)

	if !sawWrite {
		t.Fatal("yazma isteği politikaya HİÇ sorulmadı")
	}

	/*
	 * ⚠️ YOL DA GİTMELİ. Yolsuz bir yazma isteği politikaya "hangi
	 * ağaca" sorusunu cevaplamadan gider; kural yazan kişi koyduğu
	 * sınırın uygulandığını sanar.
	 */
	if sawPath != "/tmp/dosya" {
		t.Errorf("politikaya giden yol = %q, /tmp/dosya bekleniyordu", sawPath)
	}
	if len(denials) == 0 {
		t.Fatal("ret istemciye gönderilmedi")
	}
	if !strings.Contains(denials[0].Notice, "read-only") {
		t.Errorf("gerekçe kullanıcıya ulaşmıyor: %q", denials[0].Notice)
	}
}

// Yol yazmaya İZİNLİYSE yazma geçmeli: kural bir kilit değil, bir karar.
func TestWriteIsAllowedWhenThePolicySaysSo(t *testing.T) {
	_, denials := openThenWrite(t, flagWrite|flagCreat,
		func(Request) (bool, string) { return true, "" })

	if len(denials) != 0 {
		t.Fatalf("izinli yazma reddedildi: %q", denials[0].Notice)
	}
}

// Tanımadığımız tanıtıcıya yazma politika açıkken reddedilmeye devam
// ediyor — bu davranış zaten vardı ve kaybolmamalı.
func TestWriteOnAnUnknownHandleIsStillRefused(t *testing.T) {
	s, _ := collect(t)
	s.SetPolicy(func(Request) (bool, string) { return true, "" })

	feedClient(t, s, newPkt(fxpInit).u32(3).bytes())
	feedTarget(t, s, newPkt(fxpVersion).u32(3).bytes())
	feedClient(t, s, newPkt(fxpWrite).u32(1).str("yok").u64(0).str("x").bytes())

	d := s.TakeDenials()
	if len(d) == 0 {
		t.Fatal("bilinmeyen tanıtıcıya yazma geçti")
	}
	if !strings.Contains(d[0].Notice, "not opened through this session") {
		t.Errorf("gerekçe: %q", d[0].Notice)
	}
}

/*
 * ⚠️ İZİN VERİLEN YAZMA PARÇA BAŞINA SATIR ÜRETMEMELİ.
 *
 * Bir aktarım 32 KiB'lık parçalara bölünüyor. Parça başına bir denetim
 * satırı, 300 MB'lık bir dosyada on binin üstüne çıkar ve proxy tarafında
 * journalCap oturumu ÖLDÜRÜR. Aktarımın toplamı tanıtıcı kapanırken tek
 * satır olarak yazılıyor; bu testin koruduğu şey o.
 */
func TestAllowedWritesDoNotWriteALinePerChunk(t *testing.T) {
	s, events := collect(t)
	s.SetPolicy(func(Request) (bool, string) { return true, "" })

	feedClient(t, s, newPkt(fxpInit).u32(3).bytes())
	feedTarget(t, s, newPkt(fxpVersion).u32(3).bytes())

	feedClient(t, s, newPkt(fxpOpen).u32(1).str("/tmp/y").
		u32(flagWrite|flagCreat).u32(0).bytes())
	feedTarget(t, s, newPkt(fxpHandle).u32(1).str("h1").bytes())

	const chunks = 50
	for i := range chunks {
		id := uint32(10 + i)
		feedClient(t, s, newPkt(fxpWrite).u32(id).str("h1").
			u64(uint64(i)*4).str("veri").bytes())
		feedTarget(t, s, statusOK(id))
	}

	if d := s.TakeDenials(); len(d) != 0 {
		t.Fatalf("izinli yazma reddedildi: %q", d[0].Notice)
	}

	transfers := 0
	for _, e := range *events {
		if e.Op == OpTransfer {
			transfers++
		}
	}
	if transfers != 0 {
		t.Errorf("tanıtıcı kapanmadan %d aktarım satırı yazıldı — parça başına satır", transfers)
	}

	// Kapanışta TEK satır, toplam bayt onda.
	feedClient(t, s, newPkt(fxpClose).u32(999).str("h1").bytes())
	feedTarget(t, s, statusOK(999))

	var total int64
	transfers = 0
	for _, e := range *events {
		if e.Op == OpTransfer {
			transfers++
			total = e.Wrote
		}
	}
	if transfers != 1 {
		t.Fatalf("aktarım satırı sayısı %d, 1 bekleniyordu", transfers)
	}
	if want := int64(chunks * len("veri")); total != want {
		t.Errorf("yazılan bayt = %d, %d bekleniyordu", total, want)
	}
}
