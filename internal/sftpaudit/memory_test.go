package sftpaudit

import (
	"encoding/binary"
	"strings"
	"testing"
)

/*
 * ⚠️ DÖRT BAYT, 64 KiB SATIN ALAMAZ.
 *
 * ÖLÇÜLEN AÇIK: framer, uzunluk öneki gelir gelmez BİLDİRİLEN uzunluğa göre
 * yer ayırıyordu ve ayrılan yer yalnızca paket TAMAMLANINCA bırakılıyordu —
 * saldırganın esirgediği olay tam olarak o. Bir istemci `subsystem sftp`
 * gönderip ardından sadece `00 10 00 00` yazıp susarak kanal başına 64 KiB
 * tutabiliyordu.
 *
 * Neden mevcut testler yakalamadı: TestFileBodiesAreNotBuffered
 * `cap(head) <= maxHeader` diyor ve 4 bayttan ayrılan 64 KiB bu koşulu
 * SAĞLIYOR. Tavanı ölçüyordu, yükseltmeyi değil.
 */
func TestDeclaredLengthDoesNotReserveMemory(t *testing.T) {
	s := NewSession(func(Event) {})

	// 1 MiB bildiren uzunluk öneki; tek bir gövde baytı yok.
	prefix := binary.BigEndian.AppendUint32(nil, uint32(maxPacket))
	if err := s.FromClient(prefix); err != nil {
		t.Fatalf("uzunluk öneki reddedildi: %v", err)
	}

	if c := cap(s.fromClient.head); c > 64 {
		t.Fatalf("4 bayt tel trafiği %d bayt tutturdu; bellek BİLDİRİLEN "+
			"uzunluğu takip ediyor, GELEN baytları değil", c)
	}

	// Sınır hâlâ yerinde: gerçekten gelen baytlar maxHeader'ı aşamıyor.
	if s.fromClient.keep != maxHeader {
		t.Errorf("keep = %d, %d bekleniyordu", s.fromClient.keep, maxHeader)
	}
}

// Gelen baytlar geldikçe saklanıyor: sınır kaldırılmadı, yalnızca ÖNDEN
// ayırma kaldırıldı.
func TestArrivedBytesAreStillKeptUpToTheCeiling(t *testing.T) {
	s, _ := collect(t)

	feedClient(t, s, newPkt(fxpOpen).u32(1).str("/x").u32(1).u32(0).bytes())

	if got := len(s.fromClient.head); got != 0 {
		t.Fatalf("paket bitti, başlık bırakılmadı: %d bayt", got)
	}

	// Yarım paket: gelen kadarı saklanıyor.
	half := newPkt(fxpWrite).u32(2).str("h1").u64(0).str(strings.Repeat("Z", 4096)).bytes()
	if err := s.FromClient(half[:200]); err != nil {
		t.Fatal(err)
	}
	if got := len(s.fromClient.head); got == 0 {
		t.Fatal("akış ortasında hiçbir şey saklanmamış; çözümleyici gövdeyi göremez")
	}
	if got := len(s.fromClient.head); got > 200 {
		t.Fatalf("gelen 200 bayt için %d bayt saklanmış", got)
	}
}

/*
 * Sayı sınırı bayt sınırı değildi: maxPending 4096 istekle sınırlıyordu ama
 * her yol gövde kadar (64 KiB) uzun olabiliyordu — oturum başına ~256 MiB.
 */
func TestStoredPathIsBounded(t *testing.T) {
	s, got := collect(t)

	long := "/" + strings.Repeat("u", 60000)
	feedClient(t, s, newPkt(fxpOpen).u32(1).str(long).u32(1).u32(0).bytes())

	p, ok := s.pending[1]
	if !ok {
		t.Fatal("istek bekleyenlere girmedi")
	}
	// ⚠️ İŞARET DE SINIRIN İÇİNDE: sınır artık deftere sığmanın sınırı
	// (bkz. storable_test.go), yolun bittiği yer değil.
	if len(p.path) > maxPath {
		t.Fatalf("saklanan yol %d bayt, sınır %d", len(p.path), maxPath)
	}
	if !strings.HasSuffix(p.path, "(truncated)") {
		t.Error("kesilmiş yol işaretlenmemiş; operatör onu gerçek yol sanabilir")
	}

	feedTarget(t, s, statusOK(1))
	if len(*got) != 1 {
		t.Fatalf("olay yazılmadı: %+v", *got)
	}
}

/*
 * Tanıtıcı KESİLMİYOR, reddediliyor: tanıtıcı bir tablo anahtarı ve kesmek
 * iki ayrı dosyayı aynı anahtara düşürebilirdi.
 */
func TestOverlongHandleIsRejected(t *testing.T) {
	s := NewSession(func(Event) {})

	huge := strings.Repeat("h", maxHandleLen+1)
	err := s.FromClient(newPkt(fxpRead).u32(1).str(huge).u64(0).u32(16).bytes())
	if err == nil {
		t.Fatal("protokole aykırı uzunlukta tanıtıcı kabul edildi")
	}
	if !strings.Contains(err.Error(), "handle length") {
		t.Errorf("hata mesajı sebebi söylemiyor: %v", err)
	}
}

// Finish, kanal kapandıktan sonra asılı kalan her şeyi bırakmalı: broker
// b.sftp'yi bilinçli olarak temizlemiyor, yani Session erişilebilir kalıyor.
func TestFinishReleasesPendingAndBuffers(t *testing.T) {
	s, _ := collect(t)

	feedClient(t, s, newPkt(fxpOpen).u32(1).str("/x").u32(1).u32(0).bytes())
	// Yarım paket bırak: framer başlığı dolu kalsın.
	half := newPkt(fxpWrite).u32(2).str("h9").u64(0).str(strings.Repeat("Z", 900)).bytes()
	if err := s.FromClient(half[:100]); err != nil {
		t.Fatal(err)
	}

	if len(s.pending) == 0 || len(s.fromClient.head) == 0 {
		t.Fatal("ölçüm kurulamadı: bekleyen ya da başlık boş")
	}

	s.Finish()

	if n := len(s.pending); n != 0 {
		t.Errorf("Finish sonrası %d bekleyen asılı kaldı", n)
	}
	if n := len(s.fromClient.head); n != 0 {
		t.Errorf("Finish sonrası istemci başlığı %d bayt asılı kaldı", n)
	}
	if n := len(s.fromTarget.head); n != 0 {
		t.Errorf("Finish sonrası hedef başlığı %d bayt asılı kaldı", n)
	}
}

/*
 * Tanıtıcı sınırı HEDEF tarafında da geçerli.
 *
 * ⚠️ NEDEN AYRI TEST: ilk düzeltme yalnızca addPending'i süzüyordu, yani
 * istemcinin gönderdiği tanıtıcıyı. Oysa tanıtıcı hedefin HANDLE cevabından
 * geliyor ve tablo anahtarı olarak saklanıyor — yalnızca istemciyi süzmek
 * ele geçirilmiş bir hedefe kapıyı açık bırakıyordu. Bastion'ın sınırlaması
 * gereken şey tam olarak bu.
 */
func TestOverlongHandleFromTargetIsRejected(t *testing.T) {
	s := NewSession(func(Event) {})

	if err := s.FromClient(newPkt(fxpOpen).u32(1).str("/x").u32(1).u32(0).bytes()); err != nil {
		t.Fatal(err)
	}

	huge := strings.Repeat("h", maxHandleLen+1)
	err := s.FromTarget(newPkt(fxpHandle).u32(1).str(huge).bytes())
	if err == nil {
		t.Fatal("hedeften gelen protokole aykırı tanıtıcı kabul edildi")
	}
	if !strings.Contains(err.Error(), "target handle length") {
		t.Errorf("hata mesajı kaynağı söylemiyor: %v", err)
	}
	if len(s.handles) != 0 {
		t.Errorf("%d tanıtıcı yine de saklandı", len(s.handles))
	}
}
