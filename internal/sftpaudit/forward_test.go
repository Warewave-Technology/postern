package sftpaudit

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// forwarded, writeTo'nun hedefe verdiği baytları biriktirir.
type forwarded struct{ b []byte }

func (f *forwarded) fn(p []byte) error { f.b = append(f.b, p...); return nil }

// feedSplit, paketleri chunk baytlık parçalar hâlinde verir. TCP gerçekte
// böyle davranıyor; "bir Write bir paket" varsayımı üretimde tutmuyor.
func feedSplit(t *testing.T, f *framer, out *forwarded, wire []byte, chunk int) {
	t.Helper()
	for i := 0; i < len(wire); i += chunk {
		end := i + chunk
		if end > len(wire) {
			end = len(wire)
		}
		if err := f.writeTo(wire[i:end], out.fn); err != nil {
			t.Fatalf("parça %d: %v", chunk, err)
		}
	}
}

// Politika yokken hiçbir bayt kaybolmuyor ve sıra bozulmuyor.
func TestForwardingIsByteIdenticalWithoutAPolicy(t *testing.T) {
	wire := append(
		newPkt(fxpOpen).u32(1).str("/etc/passwd").u32(1).u32(0).bytes(),
		newPkt(fxpWrite).u32(2).str("h1").u64(0).str(strings.Repeat("Z", 5000)).bytes()...,
	)

	for _, chunk := range []int{len(wire), 4096, 100, 7, 1} {
		out := &forwarded{}
		f := newFramer(func(byte, *reader) error { return nil })
		feedSplit(t, f, out, wire, chunk)

		if !bytes.Equal(out.b, wire) {
			t.Fatalf("parça %d: iletilen baytlar girdiden farklı (%d vs %d)",
				chunk, len(out.b), len(wire))
		}
	}
}

/*
 * Reddedilen paketin TEK BİR BAYTI bile hedefe gitmiyor, komşuları ise
 * eksiksiz gidiyor.
 *
 * ⚠️ ORTADAKİNİ REDDETMEK ÖNEMLİ: baştakini ya da sondakini reddetmek,
 * aralığı yanlış hesaplayan bir uygulamada da tesadüfen doğru sonuç
 * verebilirdi.
 */
func TestDeniedPacketNeverReachesTheTarget(t *testing.T) {
	first := newPkt(fxpOpen).u32(1).str("/tmp/ok").u32(1).u32(0).bytes()
	denied := newPkt(fxpOpen).u32(2).str("/etc/shadow").u32(1).u32(0).bytes()
	last := newPkt(fxpClose).u32(3).str("h1").bytes()

	wire := append(append(append([]byte{}, first...), denied...), last...)
	want := append(append([]byte{}, first...), last...)

	for _, chunk := range []int{len(wire), 64, 9, 5, 1} {
		out := &forwarded{}
		var deliveredIDs []uint32

		f := newFramer(func(typ byte, r *reader) error {
			id, err := r.uint32()
			if err != nil {
				return err
			}
			deliveredIDs = append(deliveredIDs, id)
			return nil
		})
		f.decide = func(typ byte, r *reader) bool {
			if typ != fxpOpen {
				return true
			}
			if _, err := r.uint32(); err != nil {
				return false
			}
			path, err := r.str()
			if err != nil {
				return false // eksik gövde: kapalı tarafa düş
			}
			return path != "/etc/shadow"
		}

		feedSplit(t, f, out, wire, chunk)

		if bytes.Contains(out.b, []byte("/etc/shadow")) {
			t.Fatalf("parça %d: REDDEDİLEN YOL HEDEFE ULAŞTI", chunk)
		}
		if !bytes.Equal(out.b, want) {
			t.Fatalf("parça %d: iletilen akış beklenenden farklı (%d vs %d bayt)",
				chunk, len(out.b), len(want))
		}

		// Reddedilen paket deliver'a girmemeli: girseydi hiç gelmeyecek
		// bir cevabı bekleyen bir kayıt açardı.
		for _, id := range deliveredIDs {
			if id == 2 {
				t.Fatalf("parça %d: reddedilen paket deliver'a girdi", chunk)
			}
		}
		if len(deliveredIDs) != 2 {
			t.Fatalf("parça %d: deliver %d kez çağrıldı, 2 bekleniyordu", chunk, len(deliveredIDs))
		}
	}
}

/*
 * DOLGULU paket de tamamen düşüyor.
 *
 * ⚠️ ÖLÇÜLEN BAYPAS: onRequest okuduğu son alandan sonrasına bakmıyor,
 * yani bir OPEN'ın ATTRS kuyruğu istenildiği kadar şişirilebiliyor — ve
 * uzunluk alanını İSTEMCİ yazıyor. Kararı paket sonunda veren ya da
 * "uzunluk şu kadarı aşarsa akıtarak geçir" diyen her tasarım burada
 * düşer: yol okunur, politika reddeder, baytlar çoktan gitmiştir.
 */
func TestPaddedDeniedPacketIsFullyDropped(t *testing.T) {
	path := "/etc/shadow"
	pad := 200 << 10

	body := []byte{fxpOpen}
	body = binary.BigEndian.AppendUint32(body, 1)
	body = binary.BigEndian.AppendUint32(body, uint32(len(path)))
	body = append(body, path...)
	body = binary.BigEndian.AppendUint32(body, 1)
	body = binary.BigEndian.AppendUint32(body, 0)
	body = append(body, make([]byte, pad)...)

	wire := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	wire = append(wire, body...)

	tail := newPkt(fxpClose).u32(9).str("h1").bytes()
	wire = append(wire, tail...)

	out := &forwarded{}
	f := newFramer(func(byte, *reader) error { return nil })
	f.decide = func(typ byte, r *reader) bool {
		if typ != fxpOpen {
			return true
		}
		if _, err := r.uint32(); err != nil {
			return false
		}
		p, err := r.str()
		return err == nil && p != "/etc/shadow"
	}

	/*
	 * ⚠️ TEPE DEĞERİ ÖLÇÜYORUZ, SON DEĞERİ DEĞİL. Paket bittiğinde tampon
	 * zaten sıfırlanmış oluyor; sonradan bakan bir kontrol her zaman 0
	 * görür ve karar paket SONUNA alınsa bile geçerdi. (Bu testin ilk
	 * hâli tam olarak buydu ve mutasyon testinde yakalandı.)
	 */
	const chunk = 4096
	peak := 0
	for i := 0; i < len(wire); i += chunk {
		end := i + chunk
		if end > len(wire) {
			end = len(wire)
		}
		if err := f.writeTo(wire[i:end], out.fn); err != nil {
			t.Fatal(err)
		}
		if len(f.hold) > peak {
			peak = len(f.hold)
		}
	}

	if len(out.b) != len(tail) {
		t.Fatalf("dolgulu paketten %d bayt sızdı", len(out.b)-len(tail))
	}
	if !bytes.Equal(out.b, tail) {
		t.Fatal("iletilen akış yalnızca kuyruktaki paket olmalıydı")
	}

	/*
	 * Tutulan bayt, PAKETİN uzunluğuna değil KARAR BÜTÇESİNE bağlı olmalı.
	 * Bir parça taşma payı var: karar, parça yönlendirildikten SONRA
	 * veriliyor.
	 */
	if limit := decisionBudget + chunk; peak > limit {
		t.Fatalf("tepe tutulan bayt %d, sınır %d — karar paket sonunda mı "+
			"veriliyor? O zaman bellek maliyeti paketin uzunluğu kadar olur "+
			"ve uzunluğu istemci yazıyor", peak, limit)
	}
}

/*
 * Tutulan baytlar KOPYALANIYOR.
 *
 * ⚠️ NEDEN ÖLÇÜLÜYOR: io.Copy tek bir 32 KiB'lık diziyi yeniden kullanıyor.
 * Tutulan aralık p'nin kendisine bakıyor olsaydı, bir sonraki okumada
 * içerik altımızdan değişir ve hedefe BAŞKA baytlar giderdi — üstelik
 * testler tek seferlik dilimlerle çalıştığı için bu sessiz kalırdı.
 */
func TestHeldBytesAreCopiedNotAliased(t *testing.T) {
	pkt := newPkt(fxpOpen).u32(1).str("/tmp/ok").u32(1).u32(0).bytes()

	out := &forwarded{}
	f := newFramer(func(byte, *reader) error { return nil })

	buf := make([]byte, 8)

	// Paketi, çağıranın YENİDEN KULLANDIĞI bir tampondan besliyoruz.
	for i := 0; i < len(pkt); i += len(buf) {
		end := i + len(buf)
		if end > len(pkt) {
			end = len(pkt)
		}
		n := copy(buf, pkt[i:end])
		if err := f.writeTo(buf[:n], out.fn); err != nil {
			t.Fatal(err)
		}
		// Çağıran tamponu hemen yeniden kullanıyor.
		for j := range buf {
			buf[j] = 0xFF
		}
	}

	if !bytes.Equal(out.b, pkt) {
		t.Fatalf("iletilen baytlar bozuldu: tampon yeniden kullanılınca tutulan aralık değişti\n got=%x\nwant=%x", out.b, pkt)
	}
}
