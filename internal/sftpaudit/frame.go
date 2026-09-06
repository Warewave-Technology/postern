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

	// deliver, tamamlanan ve İZİN VERİLEN her paket için çağrılıyor.
	deliver func(typ byte, body *reader) error

	/*
	 * decide, bir isteğin hedefe geçip geçmeyeceğini söylüyor. nil ise
	 * her şey geçiyor (bugünkü davranış).
	 *
	 * ⚠️ KARAR PAKET SONUNDA DEĞİL, YOL OKUNUR OKUNMAZ VERİLİYOR. Paket
	 * sonunu beklemek iki kötü seçenekten birini dayatıyordu: ya paketin
	 * TAMAMINI tut (1 MiB'a kadar, oturum başına), ya da kuyruğu önden
	 * akıt ve reddi imkânsız kıl. İkincisi ölçülebilir bir baypastı:
	 * onRequest okuduğu son alandan sonrasına bakmıyor, dolayısıyla bir
	 * OPEN'ın ATTRS kuyruğu istenildiği kadar şişirilebiliyor ve uzunluk
	 * alanını İSTEMCİ yazıyor. Kararı öne almak ikisini de gereksiz
	 * kılıyor: tutulan bayt, paketin uzunluğuna değil YOLUN uzunluğuna
	 * bağlı.
	 *
	 * decide, head'in O ANKİ hâlinden okuyor. Aradığı alan gelmemişse
	 * okuyucu errShort veriyor; o durumda geri çağrının REDDETMESİ
	 * gerekiyor (kapalı tarafa düş).
	 *
	 * ⚠️ decide BLOKLAMAMALI. Session'ın tek muteksi iki yönü birden
	 * koruyor (FromClient/FromTarget), yani burada geçen her milisaniye
	 * hedef→istemci akışını da durduruyor. Bellekteki bir önek eşlemesi
	 * bunun için uygun; ağa ya da veritabanına giden bir kontrol değil.
	 */
	decide func(typ byte, body *reader) (bool, error)

	// hold, kararı beklenen paketin ham tel baytları.
	hold    []byte
	decided bool
	allow   bool

	/*
	 * sawPacket, bu yönde EN AZ BİR paketin tamamlandığı.
	 *
	 * ⚠️ "HİÇ BAŞLAMADIK" SINIR DEĞİL. Enjeksiyon sınırı bunu ayırt
	 * etmek zorunda: hedef henüz konuşmamışken istemciye yazmak,
	 * istemcinin gördüğü İLK paketin bizim cevabımız olması demek.
	 * OpenSSH'in sftp_init'i yalnızca SSH_FXP_VERSION kabul ediyor ve
	 * başka bir şey görünce fatal ile çıkıyor.
	 */
	sawPacket bool
}

/*
 * decisionBudget, karar için beklenen en fazla gövde baytı.
 *
 * İki PATH_MAX yolu (rename, symlink, link) artı alan başlıkları 8 KiB'ın
 * altında kalıyor; 16 KiB rahat bir üst sınır. Bunu aşan bir istekte karar
 * eksik gövdeyle veriliyor ve geri çağrı kapalı tarafa düşüyor — hedefte
 * zaten ENAMETOOLONG ile dönecek bir isteği geçirmemenin bedeli yok.
 */
const decisionBudget = 16 << 10

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
func (f *framer) write(p []byte) error { return f.writeTo(p, nil) }

/*
 * writeTo, write ile aynı işi yapıyor ve AYRICA iletimi üstleniyor:
 * hedefe gitmesi gereken bayt aralıklarını forward'a veriyor, reddedilen
 * paketin baytlarını hiç vermiyor. forward nil ise hiçbir şey iletilmiyor
 * (hedef yönü böyle çalışıyor).
 *
 * ⚠️ İLETİMİ FRAMER YAPIYOR, ÇAĞIRAN DEĞİL. Çağıranın kendi uzunluk-öneki
 * çözümleyicisini yazması gerekseydi, aynı baytları yürüyen ve sonsuza
 * kadar bayta bayt anlaşmak zorunda İKİ durum makinesi olurdu. Paket
 * sınırı bilgisi tek yerde duruyor.
 */
func (f *framer) writeTo(p []byte, forward func([]byte) error) error {
	// pass, iletilecek koşunun p içindeki başlangıcı; -1 ise koşu yok.
	// Koşu biriktirmek, paketin her parçası için ayrı bir Write yapmamak
	// içindir: sıradan bir akışta parça başına tek iletim oluyor.
	pass := -1

	flush := func(end int) error {
		if pass < 0 {
			return nil
		}
		b := p[pass:end]
		pass = -1
		if forward == nil || len(b) == 0 {
			return nil
		}
		return forward(b)
	}

	/*
	 * route, tüketilen [from,to) aralığını yönlendirir: karar
	 * verilmemişse TUTUYOR, izin verildiyse koşuya ekliyor, reddedildiyse
	 * atıyor.
	 *
	 * ⚠️ TUTULAN BAYTLAR KOPYALANIYOR. io.Copy tek bir 32 KiB'lık diziyi
	 * yeniden kullanıyor; p'nin kendisini saklamak, bir sonraki okumada
	 * içeriğin altımızdan değişmesi demekti.
	 */
	route := func(from, to int) error {
		if forward == nil || from >= to {
			return nil
		}
		if !f.decided {
			if err := flush(from); err != nil {
				return err
			}
			f.hold = append(f.hold, p[from:to]...)
			return nil
		}
		if !f.allow {
			return flush(from)
		}
		if pass < 0 {
			pass = from
		}
		return nil
	}

	i := 0
	for i < len(p) {
		// 1) Uzunluk önekini topla.
		if f.lenHave < 4 {
			n := copy(f.lenBuf[f.lenHave:], p[i:])
			if err := route(i, i+n); err != nil {
				return err
			}
			f.lenHave += n
			i += n
			if f.lenHave < 4 {
				break
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
		if take > len(p)-i {
			take = len(p) - i
		}
		if space := f.keep - len(f.head); space > 0 {
			n := take
			if n > space {
				n = space
			}
			f.head = append(f.head, p[i:i+n]...)
		}
		if err := route(i, i+take); err != nil {
			return err
		}
		f.got += take
		i += take

		// 3) Karar noktası: yolu okuyacak kadar gövde geldi mi?
		if !f.decided {
			want := f.need
			if want > decisionBudget {
				want = decisionBudget
			}
			if len(f.head) >= want || f.got == f.need {
				if err := f.decideNow(forward); err != nil {
					return err
				}
			}
		}

		// 4) Paket tamamlandı mı?
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

			f.sawPacket = true

			allowed := f.allow
			f.decided = false
			f.allow = false
			f.hold = f.hold[:0]

			if len(body) == 0 {
				// Uzunluk sıfır olamayacağı için buraya düşülmemeli;
				// yine de sessiz geçmiyoruz.
				return fmt.Errorf("sftpaudit: empty packet body")
			}

			/*
			 * ⚠️ REDDEDİLEN PAKET deliver'A GİRMİYOR. Girseydi bekleyenler
			 * tablosuna HİÇ GELMEYECEK bir cevabı bekleyen bir kayıt açardı:
			 * satır yazılmaz, kayıt sızar ve yeterince ret üst üste gelince
			 * maxPending'e çarpıp denetimi çökertirdi — yani politika kararı,
			 * çözümleyici arızası gibi görünürdü. Reddin denetim satırını
			 * decide geri çağrısı yazıyor.
			 */
			if !allowed {
				continue
			}

			typ := body[0]
			r := &reader{buf: body[1:]}
			if err := f.deliver(typ, r); err != nil {
				return err
			}
		}
	}

	return flush(len(p))
}

/*
 * decideNow, o ana kadar gelen gövdeden kararı alır ve tutulan baytları
 * serbest bırakır.
 *
 * ⚠️ decide, head'i ELİNDE TUTAMAZ. head paketler arasında yeniden
 * kullanılıyor; okunan dizgiler kopyalanmalı (protocol.go, str bunu
 * yapıyor). deliver'ın sözleşmesiyle aynı.
 */
func (f *framer) decideNow(forward func([]byte) error) error {
	f.decided = true
	f.allow = true

	if f.decide != nil && len(f.head) > 0 {
		allow, err := f.decide(f.head[0], &reader{buf: f.head[1:]})
		if err != nil {
			/*
			 * ⚠️ HATA REDDETMEK DEĞİL, AKIŞI BOZUK SAYMAKTIR. Politika
			 * isteğe cevap veremeyecek durumdaysa (kimliği bile
			 * okunamıyorsa) uydurma bir cevap yazmaktansa oturumu
			 * bitiriyoruz: istemcinin göndermediği bir isteğe cevap
			 * vermek onu çökertir.
			 */
			return err
		}
		f.allow = allow
	}

	if forward == nil {
		return nil
	}

	var err error
	if f.allow && len(f.hold) > 0 {
		err = forward(f.hold)
	}
	f.hold = f.hold[:0]

	return err
}
