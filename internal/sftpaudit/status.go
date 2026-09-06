package sftpaudit

// Reddedilen bir isteğe İSTEMCİYE gönderilecek cevabı üretmek.
//
// ⚠️ NEDEN BURADA, proxy'de DEĞİL. Tel biçimini bilen tek paket bu
// (protocol.go, frame.go). Kurucuyu proxy'ye koymak, uzunluk öneki ve
// alan sırası bilgisinin İKİ yerde durması demekti; ikisi zamanla
// ayrışsaydı sonuç sessiz olurdu — istemci bozuk bir paket okur ve
// oturumu postern'in arızası sanarak kapatırdı.

import (
	"encoding/binary"
	"unicode/utf8"
)

// SFTP durum kodları (draft-ietf-secsh-filexfer-02, §7).
//
// Yalnızca postern'in ÜRETEBİLECEĞİ kodlar burada. Hedeften gelenleri
// çözmek için tam listeye ihtiyaç yok: onlar olduğu gibi geçiyor.
/*
 * maxStatusMsg, mesajın üst sınırı.
 *
 * ⚠️ SINIR GÜVENLİK İÇİN, ESTETİK İÇİN DEĞİL. Uzunluk alanı uint32, Go'da
 * len() ise int: sınırsız bir mesaj hem dönüşümü taşırabilir hem de
 * maxPacket'i (1 MiB) aşan bir paket üretebilirdi. İstemci onu bozuk sayıp
 * oturumu keserdi — yani reddi ANLATMAYA çalışırken bağlantıyı koparmış
 * olurduk. Mesaj operatörün cümlesi; 1 KiB fazlasıyla yetiyor.
 */
const maxStatusMsg = 1 << 10

const (
	// StatusPermissionDenied, politikanın reddettiği istek için.
	//
	// ⚠️ FAILURE (4) DEĞİL. İstemciler bu ikisine farklı tepki veriyor:
	// sftp/scp PERMISSION_DENIED'ı "bu yol sana kapalı" diye gösterip
	// devam ediyor, FAILURE ise çoğu istemcide "sunucu arızası" gibi
	// okunuyor. Reddin kullanıcıya DOĞRU görünmesi, reddin kendisi kadar
	// önemli: yanlış kod, yöneticiye açılmış bir arıza kaydı demek.
	StatusPermissionDenied uint32 = 3

	/*
	 * StatusOpUnsupported, TANIMADIĞIMIZ bir işlem için.
	 *
	 * ⚠️ REDDİN SEBEBİ DOĞRU SÖYLENMELİ. Tanımadığımız bir uzantıya
	 * "bu yola iznin yok" demek yalan: sorun yol değil, postern'in o fiili
	 * modellememesi. Taslak (draft-ietf-secsh-filexfer-02 §8) tanınmayan
	 * extended-request için bu kodu ŞART koşuyor.
	 *
	 * Pratik faydası da var: istemciler bu kodu görünce standart işlemlere
	 * geri düşüyor — yani postern'in DENETLEYEBİLDİĞİ fiillere. 3 dönseydik
	 * istemci yolu suçlar, geri düşmez ve kullanıcı neden çalışmadığını
	 * anlamazdı.
	 */
	StatusOpUnsupported uint32 = 8
)

/*
 * StatusPacket, tek bir SSH_FXP_STATUS paketini tel biçiminde üretir.
 *
 * Biçim (v3):
 *
 *	uint32 uzunluk        (tip baytından itibaren, kendisi hariç)
 *	byte   101            SSH_FXP_STATUS
 *	uint32 istek kimliği
 *	uint32 durum kodu
 *	string mesaj          UTF-8
 *	string dil etiketi
 *
 * ⚠️ İSTEK KİMLİĞİ REDDEDİLEN İSTEĞİNKİYLE AYNI OLMALI. İstemci
 * cevapları kimliğe göre eşliyor; başka bir kimlikle cevap vermek, o
 * isteği sonsuza kadar cevapsız bırakır — yani reddetmek yerine
 * istemciyi askıda bırakmış oluruz.
 *
 * ⚠️ DİL ETİKETİ BOŞ. RFC boş bırakmaya izin veriyor ve istemciler
 * yok sayıyor; uydurma bir etiket ("en") göndermek, mesajın gerçekten
 * o dilde olduğu iddiası olurdu.
 */
func StatusPacket(id uint32, code uint32, msg string) []byte {
	/*
	 * ⚠️ RUNE SINIRINDA KESİLİYOR. RFC mesajı UTF-8 diyor; ortadan kesmek
	 * geçersiz UTF-8 üretir ve katı bir istemci paketi reddedebilir.
	 * En fazla üç bayt geri gidiliyor.
	 */
	if len(msg) > maxStatusMsg {
		msg = msg[:maxStatusMsg]
		for len(msg) > 0 && !utf8.ValidString(msg) {
			msg = msg[:len(msg)-1]
		}
	}

	// 1 (tip) + 4 (id) + 4 (kod) + 4+len(msg) + 4 (boş dil etiketi)
	// #nosec G115 -- msg yukarıda maxStatusMsg'e (1 KiB) sınırlandı; dönüşüm
	// taşamaz. gosec o sınırlamayı akış üzerinden göremiyor.
	body := uint32(len(msg)) + 17

	p := make([]byte, 0, 4+int(body))
	p = binary.BigEndian.AppendUint32(p, body)
	p = append(p, fxpStatus)
	p = binary.BigEndian.AppendUint32(p, id)
	p = binary.BigEndian.AppendUint32(p, code)
	p = binary.BigEndian.AppendUint32(p, body-17)
	p = append(p, msg...)
	p = binary.BigEndian.AppendUint32(p, 0)

	return p
}
