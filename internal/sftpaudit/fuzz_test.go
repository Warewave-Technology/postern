package sftpaudit

// ⚠️ BU PAKET DÜŞMAN GİRDİSİ OKUYOR.
//
// Çözümleyici, veri yolundan geçen HER baytı görüyor ve okuduğu uzunluk
// alanlarının hepsi karşı taraftan geliyor. Burada bir panik, bastion'ın
// tamamını düşürür: SFTP'yi açan kurulumda herhangi bir kullanıcı,
// bozuk bir paket göndererek sunucuyu kapatabilirdi.

import (
	"encoding/binary"
	"testing"
)

/*
 * FuzzDecoderSurvivesHostileStreams, rastgele akışlarda panik ve
 * sınırsız bellek aranıyor.
 *
 * İki yön de besleniyor: alanların bir kısmı ancak karşılıklı paketler
 * eşleşince okunuyor (OPEN → HANDLE, READ → DATA) ve tek yönü fuzz'lamak
 * o kod yollarına hiç girmezdi.
 */
func FuzzDecoderSurvivesHostileStreams(f *testing.F) {
	// Tohumlar: meşru bir dizi, sonra onu bozan biçimler.
	f.Add([]byte{}, []byte{})
	f.Add(
		append(newPkt(fxpOpen).u32(1).str("/etc/passwd").u32(1).u32(0).bytes(),
			newPkt(fxpRead).u32(2).str("h1").u64(0).u32(16).bytes()...),
		append(newPkt(fxpHandle).u32(1).str("h1").bytes(),
			newPkt(fxpData).u32(2).str("0123456789abcdef").bytes()...),
	)
	// Uzunluğu devasa, gövdesi yok.
	f.Add(binary.BigEndian.AppendUint32(nil, 0x7FFFFFFF), []byte{})
	// Sıfır uzunluk.
	f.Add(binary.BigEndian.AppendUint32(nil, 0), []byte{})
	// Alan uzunluğu pakete sığmıyor.
	f.Add([]byte{0, 0, 0, 9, fxpOpen, 0, 0, 0, 1, 0xFF, 0xFF, 0xFF, 0xFF}, []byte{})
	// Cevap, hiç sorulmamış bir isteğe ait.
	f.Add([]byte{}, newPkt(fxpHandle).u32(999).str("hayalet").bytes())
	f.Add([]byte{}, newPkt(fxpData).u32(1).str("veri").bytes())

	f.Fuzz(func(t *testing.T, client, target []byte) {
		var events int
		s := NewSession(func(Event) { events++ })

		// Hata dönmesi NORMAL — bozuk akış reddedilir. Panik ise
		// bastion'ı düşürür ve kabul edilemez.
		_ = s.FromClient(client)
		_ = s.FromTarget(target)

		// Bayt bayt beslemek aynı kodu farklı durum geçişlerinden
		// geçiriyor: paket sınırları her yere düşüyor.
		s2 := NewSession(func(Event) {})
		for i := range client {
			if err := s2.FromClient(client[i : i+1]); err != nil {
				break
			}
		}
		for i := range target {
			if err := s2.FromTarget(target[i : i+1]); err != nil {
				break
			}
		}

		/*
		 * ⚠️ TABLOLAR SINIRSIZ BÜYÜMEMELİ.
		 *
		 * Cevabı hiç okumayan bir istemci, sınırsız bir bekleyenler
		 * tablosunda bellek tüketerek bastion'ı düşürebilirdi. Sınır
		 * kodun içinde; burada FİİLEN tutulduğu ölçülüyor.
		 */
		s.mu.Lock()
		pending, handles, dirs := len(s.pending), len(s.handles), len(s.dirHandles)
		headCap := cap(s.fromClient.head) + cap(s.fromTarget.head)
		s.mu.Unlock()

		if pending > maxPending {
			t.Fatalf("bekleyen istek = %d, sınır %d", pending, maxPending)
		}
		if handles+dirs > maxHandles {
			t.Fatalf("açık tanıtıcı = %d, sınır %d", handles+dirs, maxHandles)
		}
		// Saklanan gövde iki yön için de tavanın altında kalmalı:
		// aksi hâlde dosya içeriği belleğe alınıyor demektir.
		if headCap > 2*maxHeader {
			t.Fatalf("saklanan gövde = %d bayt, tavan %d", headCap, 2*maxHeader)
		}
		_ = events
	})
}

/*
 * FuzzFinishIsAlwaysSafe, akış nerede kesilirse kesilsin kapanışın
 * çalıştığını arıyor.
 *
 * Finish, yarım kalan transferleri yazan yol — yani veriyi çekip
 * bağlantıyı koparan birinin izini bırakan yer. Orada bir panik,
 * denetimden kaçmanın yolu olurdu.
 */
func FuzzFinishIsAlwaysSafe(f *testing.F) {
	f.Add([]byte{}, []byte{})
	f.Add(newPkt(fxpOpen).u32(1).str("/x").u32(1).u32(0).bytes(),
		newPkt(fxpHandle).u32(1).str("h").bytes())

	f.Fuzz(func(t *testing.T, client, target []byte) {
		s := NewSession(func(Event) {})
		_ = s.FromClient(client)
		_ = s.FromTarget(target)
		s.Finish()
		// İki kez çağrılması da güvenli olmalı: kapanış yolları
		// birden çok yerden tetiklenebiliyor.
		s.Finish()
	})
}
