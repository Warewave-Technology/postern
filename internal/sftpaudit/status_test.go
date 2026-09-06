package sftpaudit

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// parseStatus, bir STATUS paketini framer üzerinden geri okur.
//
// ⚠️ ÖLÇÜ BİLEREK BÖYLE: ürettiğimiz paketi PAKETİN KENDİ çözümleyicisinden
// geçiriyoruz. Elle yazılmış beklenen bayt dizisiyle karşılaştırmak, kurucu
// ile çözümleyici birlikte kayarsa ikisini de yeşil bırakırdı.
func parseStatus(t *testing.T, pkt []byte, chunk int) (typ byte, id, code uint32, msg string) {
	t.Helper()

	seen := 0
	f := newFramer(func(ty byte, r *reader) error {
		seen++
		typ = ty

		var err error
		if id, err = r.uint32(); err != nil {
			return err
		}
		if code, err = r.uint32(); err != nil {
			return err
		}
		if msg, err = r.str(); err != nil {
			return err
		}
		return nil
	})

	for i := 0; i < len(pkt); i += chunk {
		end := i + chunk
		if end > len(pkt) {
			end = len(pkt)
		}
		if err := f.write(pkt[i:end]); err != nil {
			t.Fatalf("kendi ürettiğimiz paket çözümlenemedi (parça %d): %v", chunk, err)
		}
	}

	if seen != 1 {
		t.Fatalf("paket sayısı %d, beklenen 1 — uzunluk öneki yanlış olabilir", seen)
	}
	return typ, id, code, msg
}

func TestStatusPacketReadsBackAsWritten(t *testing.T) {
	const id uint32 = 0x01020304
	msg := "postern: path is not permitted"

	pkt := StatusPacket(id, StatusPermissionDenied, msg)

	// ⚠️ PARÇA BOYUTLARI: tek seferde, bayt bayt ve uzunluk önekini ortadan
	// bölen bir boyut. Paket veri yolunda TCP'nin verdiği parçalarla
	// geliyor; "bir Write bir paket" varsayımı üretimde tutmuyor.
	for _, chunk := range []int{len(pkt), 1, 3, 7} {
		typ, gotID, gotCode, gotMsg := parseStatus(t, pkt, chunk)

		if typ != fxpStatus {
			t.Errorf("parça %d: tip %d, beklenen %d", chunk, typ, fxpStatus)
		}
		if gotID != id {
			t.Errorf("parça %d: istek kimliği %#x, beklenen %#x — istemci cevabı eşleyemez", chunk, gotID, id)
		}
		if gotCode != StatusPermissionDenied {
			t.Errorf("parça %d: kod %d, beklenen %d", chunk, gotCode, StatusPermissionDenied)
		}
		if gotMsg != msg {
			t.Errorf("parça %d: mesaj %q, beklenen %q", chunk, gotMsg, msg)
		}
	}
}

// TestStatusPacketLengthCoversTheWholeBody, uzunluk önekinin gövdeyi TAM
// kapsadığını ölçüyor.
//
// Bir bayt eksik ya da fazla olsaydı, istemci sonraki paketi yanlış yerden
// okumaya başlardı ve arıza bu pakette değil, ONDAN SONRAKİNDE görünürdü.
func TestStatusPacketLengthCoversTheWholeBody(t *testing.T) {
	for _, msg := range []string{"", "kısa", strings.Repeat("u", 4096)} {
		pkt := StatusPacket(1, StatusPermissionDenied, msg)

		// İki paketi arka arkaya verdiğimizde ikisi de ayrışmalı: uzunluk
		// yanlışsa ikincisi bozuk çıkar.
		var count int
		f := newFramer(func(byte, *reader) error { count++; return nil })
		if err := f.write(append(append([]byte{}, pkt...), pkt...)); err != nil {
			t.Fatalf("mesaj %d bayt: arka arkaya iki paket çözümlenemedi: %v", len(msg), err)
		}
		if count != 2 {
			t.Fatalf("mesaj %d bayt: %d paket ayrıştı, beklenen 2 — uzunluk öneki gövdeyi kapsamıyor", len(msg), count)
		}
	}
}

/*
 * Uzun mesaj kesiliyor ve paket HÂLÂ geçerli kalıyor.
 *
 * ⚠️ NEDEN ÖNEMLİ: sınır olmasaydı, reddi anlatmaya çalışan bir mesaj
 * maxPacket'i aşan bir paket üretebilirdi. İstemci onu bozuk sayıp oturumu
 * keserdi — yani "bu yol sana kapalı" demek yerine bağlantıyı koparmış
 * olurduk. Reddin ANLAŞILIR olması, reddin kendisi kadar önemli.
 */
func TestStatusPacketClampsALongMessage(t *testing.T) {
	long := strings.Repeat("a", 4*maxStatusMsg)

	pkt := StatusPacket(1, StatusPermissionDenied, long)
	_, _, _, msg := parseStatus(t, pkt, len(pkt))

	if len(msg) > maxStatusMsg {
		t.Fatalf("mesaj %d bayt, sınır %d", len(msg), maxStatusMsg)
	}
	if len(pkt) > maxPacket {
		t.Fatalf("paket %d bayt, maxPacket %d", len(pkt), maxPacket)
	}
}

/*
 * Kesme RUNE SINIRINDA oluyor.
 *
 * ⚠️ ÖLÇÜ ASCII İLE YAPILAMAZ: her rune tek bayt olsaydı kesme noktası
 * hiçbir zaman rune'u ortadan bölmezdi ve test, kesmeyi hiç kontrol
 * etmeden geçerdi. Bu yüzden çok baytlı bir karakter kullanılıyor ve
 * sınıra denk gelecek şekilde hizalanıyor.
 */
func TestStatusPacketTruncatesOnARuneBoundary(t *testing.T) {
	// 3 baytlık rune; maxStatusMsg 3'e bölünmüyor, yani kesme noktası
	// mutlaka bir rune'un ortasına denk geliyor.
	if maxStatusMsg%3 == 0 {
		t.Fatalf("bu ölçüm maxStatusMsg'in 3'e bölünmemesine dayanıyor (şu an %d)", maxStatusMsg)
	}
	long := strings.Repeat("ç€", maxStatusMsg) // 2+3 bayt

	pkt := StatusPacket(1, StatusPermissionDenied, long)
	_, _, _, msg := parseStatus(t, pkt, len(pkt))

	if !utf8.ValidString(msg) {
		t.Fatalf("kesilen mesaj geçersiz UTF-8 (%d bayt)", len(msg))
	}
	if msg == "" {
		t.Fatal("mesaj tamamen yok oldu")
	}
}
