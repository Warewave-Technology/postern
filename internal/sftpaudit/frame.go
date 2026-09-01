package sftpaudit

// Akış → paket sınırları.
//
// ⚠️ NEDEN AYRI BİR DURUM MAKİNESİ: bu kod bir io.Writer olarak veri
// yolunun üstüne takılıyor ve TCP'nin verdiği parçalarla besleniyor. Bir
// SFTP paketi iki Write çağrısına bölünebilir, bir Write çağrısı üç paket
// taşıyabilir. "Her Write bir pakettir" varsayan bir çözümleyici, büyük
// transferlerde sessizce yanlış olay üretirdi — ve yanlış denetim kaydı,
// olmayan denetim kaydından daha kötüdür.

import (
	"encoding/binary"
	"fmt"
)

// framer, bayt akışını paketlere böler.
//
// Gövdenin yalnızca ilk maxHeader baytını biriktiriyor, gerisini sayarak
// atıyor: dosya içeriği belleğe alınmıyor.
type framer struct {
	lenBuf  [4]byte
	lenHave int

	need int    // bu paketin gövde uzunluğu (tip baytı dahil)
	got  int    // gövdeden şimdiye kadar görülen bayt
	head []byte // gövdenin saklanan ön kısmı

	// deliver, tamamlanan her paket için çağrılıyor.
	deliver func(typ byte, body *reader) error
}

func newFramer(deliver func(byte, *reader) error) *framer {
	return &framer{deliver: deliver}
}

/*
 * write, akıştan gelen bir parçayı işler.
 *
 * Hata dönerse akış artık ÇÖZÜLEMEZ durumdadır: paket sınırı kaybolmuş
 * demektir ve sonraki her şey uydurma olur. Çağıran bunu oturumu
 * sonlandırmak için kullanıyor — "denetlenemeyen kanal geçmez" kuralı.
 */
func (f *framer) write(p []byte) error {
	for len(p) > 0 {
		// 1) Uzunluk önekini topla.
		if f.lenHave < 4 {
			n := copy(f.lenBuf[f.lenHave:], p)
			f.lenHave += n
			p = p[n:]
			if f.lenHave < 4 {
				return nil
			}
			length := binary.BigEndian.Uint32(f.lenBuf[:])
			if length == 0 {
				return fmt.Errorf("sftpaudit: zero-length packet")
			}
			if length > maxPacket {
				return fmt.Errorf("sftpaudit: packet length %d exceeds limit %d", length, maxPacket)
			}
			f.need = int(length)
			f.got = 0
			keep := f.need
			if keep > maxHeader {
				keep = maxHeader
			}
			f.head = make([]byte, 0, keep)
			continue
		}

		// 2) Gövdeyi tüket. Saklanacak kadarını biriktir, gerisini say.
		remain := f.need - f.got
		take := remain
		if take > len(p) {
			take = len(p)
		}
		if space := cap(f.head) - len(f.head); space > 0 {
			n := take
			if n > space {
				n = space
			}
			f.head = append(f.head, p[:n]...)
		}
		f.got += take
		p = p[take:]

		// 3) Paket tamamlandı mı?
		if f.got == f.need {
			body := f.head
			f.lenHave = 0
			f.head = nil
			if len(body) == 0 {
				// Uzunluk sıfır olamayacağı için buraya düşülmemeli;
				// yine de sessiz geçmiyoruz.
				return fmt.Errorf("sftpaudit: empty packet body")
			}
			typ := body[0]
			r := &reader{buf: body[1:]}
			if err := f.deliver(typ, r); err != nil {
				return err
			}
		}
	}
	return nil
}
