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
	// keep, head'in büyüyebileceği üst sınır.
	//
	// ⚠️ SINIR AYRI BİR ALAN, cap(head) DEĞİL. Eskiden sınır kapasiteydi
	// ve kapasite uzunluk öneki gelir gelmez ayrılıyordu: 4 bayt tel
	// trafiği, 64 KiB'a kadar YERLEŞİK bellek satın alıyordu. Ayrılan yer
	// yalnızca paket TAMAMLANINCA bırakılıyor — saldırganın esirgediği
	// olay tam olarak o. Şimdi head geldikçe büyüyor, yani bellek
	// BİLDİRİLEN değil GELEN baytları takip ediyor.
	keep int

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
			f.keep = f.need
			if f.keep > maxHeader {
				f.keep = maxHeader
			}
			/*
			 * ⚠️ BURADA YER AYIRMIYORUZ. Uzunluk alanını istemci yazıyor;
			 * ona göre ayırmak, 4 baytla 64 KiB tutturmanın yoluydu.
			 *
			 * Tampon YENİDEN KULLANILIYOR (kapasite duruyor, uzunluk
			 * sıfırlanıyor). Ölçüldü: her pakette yeniden büyütmek, 32 KiB'lık
			 * bir gövde parçalı geldiğinde 2 ayırma yerine 7 ve 3 kat süre
			 * demekti — TCP paketi gerçekte hep bölüyor. Yeniden kullanımda
			 * kararlı durumda gövde için hiç ayırma olmuyor.
			 */
			f.head = f.head[:0]
			continue
		}

		// 2) Gövdeyi tüket. Saklanacak kadarını biriktir, gerisini say.
		remain := f.need - f.got
		take := remain
		if take > len(p) {
			take = len(p)
		}
		if space := f.keep - len(f.head); space > 0 {
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
			/*
			 * body ile f.head aynı diziyi gösteriyor; f.head'i sıfır uzunluğa
			 * çekmek body'nin uzunluğunu değiştirmiyor. Bir sonraki append
			 * ancak deliver döndükten SONRA olabiliyor ve çözümleyici gövdeden
			 * okuduğu her dizgiyi kopyalıyor (protocol.go, str), yani diziyi
			 * elinde tutan kimse kalmıyor.
			 */
			body := f.head
			f.head = f.head[:0]
			f.lenHave = 0
			f.keep = 0
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
