package sftpaudit

import (
	"strings"
	"testing"
)

/*
 * Toplu transferin sıcak yolu: TEK bir framer'dan arka arkaya geçen büyük
 * WRITE paketleri. Gerçek akış böyle: oturum boyunca bir framer, binlerce
 * paket.
 *
 * ⚠️ NEDEN DURUYOR: framer gövdeyi artık ÖNDEN ayırmıyor (uzunluk alanını
 * istemci yazıyor; ona göre ayırmak 4 baytla 64 KiB tutturmanın yoluydu).
 * İlk düzeltme her pakette yeniden büyütüyordu ve ÖLÇÜLDÜ: parçalı gelen
 * 32 KiB'lık bir gövdede 2 ayırma yerine 7, ve 3 kat süre. TCP paketi
 * gerçekte hep bölüyor, yani bu sıcak yolun ta kendisi.
 *
 * Tamponu yeniden kullanan sürüm ikisini birden çözdü. Ölçülen
 * (32K parçalı, bu makinede):
 *
 *	önden ayırma:      4907 ns/op   40992 B/op   2 allocs/op
 *	her pakette büyüt: 14513 ns/op  121377 B/op  7 allocs/op
 *	yeniden kullan:      784 ns/op     436 B/op   1 allocs/op
 *
 * Sayılar makineye göre değişir; korunması gereken SIRA ve büyüklük
 * mertebesi. Bu dosya, düzeltmenin sıcak yolu bozmadığının kanıtı.
 */
func benchStream(b *testing.B, bodyLen int) {
	payload := strings.Repeat("Z", bodyLen)
	pkt := newPkt(fxpWrite).u32(1).str("h1").u64(0).str(payload).bytes()

	f := newFramer(func(byte, *reader) error { return nil })

	b.SetBytes(int64(len(pkt)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := f.write(pkt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFramerStream4K(b *testing.B)  { benchStream(b, 4<<10) }
func BenchmarkFramerStream32K(b *testing.B) { benchStream(b, 32<<10) }

// Parçalı geliş: TCP gerçekte paketi bölüyor. Büyüme zinciri burada en
// belirgin olmalı.
func BenchmarkFramerStream32KChunked(b *testing.B) {
	payload := strings.Repeat("Z", 32<<10)
	pkt := newPkt(fxpWrite).u32(1).str("h1").u64(0).str(payload).bytes()

	f := newFramer(func(byte, *reader) error { return nil })

	b.SetBytes(int64(len(pkt)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for off := 0; off < len(pkt); off += 4096 {
			end := off + 4096
			if end > len(pkt) {
				end = len(pkt)
			}
			if err := f.write(pkt[off:end]); err != nil {
				b.Fatal(err)
			}
		}
	}
}
