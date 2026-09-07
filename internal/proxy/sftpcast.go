package proxy

// SFTP olaylarının oturum KAYDINA yazılması.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Warewave-Technology/postern/internal/sftpaudit"
)

/*
 * NEDEN VAR: SFTP oturumunun kaydı BOŞTU ve zincir o boşluğu mühürlüyordu.
 *
 * Ham SFTP baytları kayda hiç girmiyor ve bu doğru — kanalı baştan kapalı
 * tutan gerekçe tam olarak buydu: 80x24'lük bir başlığın altına ikili
 * protokol koymak, oynatılamayan ve okunamayan bir dosya üretiyor. Ama o
 * karar, oturumun kaydını da boş bırakıyordu: bir tarama ya da aktarım
 * oturumunun `.cast` dosyası yalnızca başlık satırından ibaretti, zincir
 * tek halkalıydı, ve o oturumun GERÇEK kanıtı olan `session_files`
 * satırları zincirin hiç uzanmadığı bir yerde duruyordu.
 *
 * Buraya yazılan şey ham protokol DEĞİL: çözülmüş, insanın okuyabileceği
 * bir anlatı. Yani "ham protokol kayda girmez" kuralı çiğnenmiyor, ve
 * kazanılan üç şey var:
 *
 *   1. Zincir kendiliğinden kapsıyor — ayrı bir mühür mekanizması
 *      gerekmiyor. (Ayrı bir DB zinciri neredeyse hiçbir şey satın
 *      almazdı: zincirin değeri hash'in kendisinde değil, başın makinenin
 *      ULAŞAMADIĞI arşive yazılmasında. Veritabanına yazabilen biri bir
 *      DB zincirini de yeniden hesaplar.)
 *   2. Oturum mevcut oynatıcıda İZLENEBİLİR oluyor.
 *   3. Tek bir doğrulama komutu ("session verify") iki oturum türü için
 *      de aynı şeyi söylüyor.
 *
 * ⚠️ BU DOSYANIN ASIL İŞİ TEMİZLEMEK. Yol ve gerekçe metinleri KARŞI
 * TARAFTAN geliyor: dosya adını hedefteki kullanıcı koyuyor, gerekçe
 * metnini hedefin sftp-server'ı yazıyor. Bir terminal kaydına giren metin
 * OYNATILDIĞINDA TERMİNALDE ÇALIŞIR — içinde ESC dizisi olan bir dosya
 * adı, kaydı izleyen denetçinin ekranını boyayabilir, imleci oynatabilir,
 * satırları silebilir. Yani kaydı okunmaz ya da YANILTICI kılabilir.
 * Kayda giren her metin bu yüzden buradan geçiyor.
 */

// maxCastField, kayda yazılan tek bir alanın tavanı.
//
// ⚠️ Yol uzunluğu zaten sınırlı (sftpaudit.maxPath) ama gerekçe metni
// hedeften geliyor ve sınırı hedef koyuyor. Kayıt satırının uzunluğu
// zincire giren bayt sayısıdır; sınırsız bırakmak, tek bir isteğin
// kaydı şişirmesine izin vermek olurdu.
const maxCastField = 512

/*
 * castSafe, karşı taraftan gelen metni bir terminal kaydına konabilir
 * hâle getirir.
 *
 * ⚠️ YAZDIRILABİLİR OLMAYAN HER ŞEY ATILIYOR, kaçırılmıyor. Kaçırmak
 * (örneğin "\x1b" yazmak) metni okunur tutardı ama satırı uzatır ve
 * "gerçekten ne vardı" sorusunu cevaplamaz; atmak, ekranda görünenin
 * dosyada olanla aynı olmasını sağlıyor. Atılan bir şey olduğunu
 * kaybetmemek için sonuna işaret konuyor.
 */
func castSafe(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	dropped := false
	for _, r := range s {
		switch {
		case r == utf8.RuneError:
			// Bozuk UTF-8: hedefin dosya adı geçerli UTF-8 olmak
			// zorunda değil.
			dropped = true
		case r < 0x20 || r == 0x7f:
			// C0 kontrol baytları ve DEL: ESC, CR, LF, BS burada.
			dropped = true
		case r >= 0x80 && r <= 0x9f:
			// C1: tek baytlık ESC eşdeğerleri. UTF-8 çözümünden sonra
			// bunlar ancak kasten konmuş olabilir.
			dropped = true
		default:
			if b.Len() >= maxCastField {
				dropped = true
				continue
			}
			b.WriteRune(r)
		}
	}

	out := b.String()
	if out == "" {
		// ⚠️ BOŞLUK KONTROLÜ ATMA İŞARETİNDEN ÖNCE. Tersi sırada
		// tümüyle atılmış bir alan "…" olarak çıkıyordu — teknik
		// olarak boş değil ama denetçiye hiçbir şey söylemiyor.
		// Tümü atıldıysa alanın VAR OLDUĞUNU söyle: boş bırakmak
		// "yol yoktu" demek olurdu.
		return "(unprintable)"
	}
	if dropped {
		out += "…"
	}

	return out
}

// castVerb, olayı kayıtta görünecek fiile çevirir.
//
// ⚠️ Transfer YÖNÜYLE yazılıyor: "transfer" tek başına, bir dosyanın
// hedefe mi gittiğini yoksa hedeften mi geldiğini söylemiyor — ve bir
// denetçinin ilk sorduğu şey o.
func castVerb(e sftpaudit.Event) string {
	if denied, ok := strings.CutPrefix(string(e.Op), "denied."); ok {
		return "denied " + denied
	}
	if e.Op == sftpaudit.OpTransfer {
		switch {
		case e.Wrote > 0 && e.Read > 0:
			return "transfer"
		case e.Wrote > 0:
			return "put"
		case e.Read > 0:
			return "get"
		default:
			// Açılmış ama tek bayt taşınmamış dosya. "get 0 B" demek
			// bir aktarım olduğunu düşündürürdü.
			return "opened"
		}
	}

	return string(e.Op)
}

// castBytes, taşınan baytı okunur hâle getirir.
func castBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for n/div >= unit && exp < 4 {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}

/*
 * castLine, bir denetim olayının kayda yazılacak satırı.
 *
 * Biçim kasten sabit ve okunur: "postern sftp: <fiil> <yol>[ → <yeni>]
 * [(<bayt>)][ — <gerekçe>]". Satır sonu "\r\n" çünkü kayıt bir TERMİNAL
 * kaydı ve oynatıcı satır başı bekliyor (recordIntent'teki kalıbın aynısı).
 */
func castLine(e sftpaudit.Event) string {
	var b strings.Builder
	b.WriteString("postern sftp: ")
	b.WriteString(castVerb(e))

	if e.Path != "" {
		b.WriteString(" ")
		b.WriteString(castSafe(e.Path))
	}
	if e.NewPath != "" {
		b.WriteString(" → ")
		b.WriteString(castSafe(e.NewPath))
	}

	switch {
	case e.Read > 0 && e.Wrote > 0:
		b.WriteString(" (↓" + castBytes(e.Read) + " ↑" + castBytes(e.Wrote) + ")")
	case e.Read > 0:
		b.WriteString(" (" + castBytes(e.Read) + ")")
	case e.Wrote > 0:
		b.WriteString(" (" + castBytes(e.Wrote) + ")")
	}

	// ⚠️ BAŞARISIZLIK GÖRÜNÜR OLMAK ZORUNDA. "Kimse denemedi" ile
	// "denedi ve reddedildi" ayrı bulgular ve kayıt ikincisini
	// göstermezse denetçi ilkini varsayar.
	if !e.OK && !strings.HasPrefix(string(e.Op), "denied.") {
		b.WriteString(" [failed]")
	}
	if e.Detail != "" {
		b.WriteString(" — ")
		b.WriteString(castSafe(e.Detail))
	}
	b.WriteString("\r\n")

	return b.String()
}

/*
 * emitSFTP, bir denetim olayını hem deftere hem oturum KAYDINA yazar.
 *
 * ⚠️ SIRA: ÖNCE KAYIT, SONRA DEFTER. Defter yazamadığında oturum biter
 * ("denetlenemiyorsa geçmez") ve o yol fail() ile hemen tetikleniyor;
 * kaydı ondan sonra yazmaya kalkmak, oturumun SON olayını kaydın dışında
 * bırakırdı — yani en çok merak edilecek satırı.
 *
 * ⚠️ KAYIT YAZMASI OTURUMU DÜŞÜRMÜYOR. Kaydın kendi arıza yolu ayrı ve
 * zaten kurulu (record.Writer.OnFailure → lifecycle). Buradan ikinci bir
 * arıza yolu açmak, aynı arızayı iki kez cezalandırmak olurdu.
 */
func (b *Broker) emitSFTP(e sftpaudit.Event) {
	b.castSFTP(e)

	if b.sftpSink != nil {
		b.sftpSink.Emit(e)
	}
}

// castSFTP, olayı kayda yazar ve mühür özetine katar.
func (b *Broker) castSFTP(e sftpaudit.Event) {
	if b.rec == nil {
		return
	}

	line := castLine(e)

	b.castMu.Lock()
	defer b.castMu.Unlock()

	// Yazma hatası yutuluyor: kaydın arıza yolu OnFailure.
	_, _ = b.rec.OutputStream().Write([]byte(line))

	/*
	 * ⚠️ ÖZET SIRADAN BAĞIMSIZ: her satırın kendi özeti XOR'lanıyor,
	 * zincirlenmiyor. Sebebi defterin kendisi — satırlar toplu yazılıyor
	 * ve `id` ile sıralanıyor, yani aynı olay kümesi farklı sırada
	 * okunabiliyor. Sıraya bağlı bir özet, hiçbir şey değişmemişken
	 * tutmayabilirdi. Özetin cevapladığı soru "aynı olaylar mı";
	 * "aynı sırada mı" değil — sıranın kanıtı zaten satırların kendisi
	 * ve onları zincir kapsıyor.
	 */
	sum := sha256.Sum256([]byte(line))
	for i := range b.castDigest {
		b.castDigest[i] ^= sum[i]
	}
	b.castEvents++
}

/*
 * sealSFTPCast, kaydın sonuna mühür özetini yazar.
 *
 * ⚠️ NİYE AYRI BİR SATIR. Zincir dosyanın DEĞİŞMEDİĞİNİ gösteriyor;
 * göstermediği şey KAÇ olayın olması gerektiği. Kaydı baştan sona yeniden
 * yazabilen biri zinciri de yeniden hesaplar — o sınır SECURITY.md'de
 * yazılı ve bu satır onu değiştirmiyor. Değiştirdiği şey daha dar ve
 * gerçek: satır sayısıyla özet tutmuyorsa kaydın ORTASINDAN satır
 * çıkarılmış demektir, ki bu zinciri yeniden hesaplamadan yapılabilecek
 * en kolay müdahale.
 */
func (b *Broker) sealSFTPCast() {
	if b.rec == nil {
		return
	}

	b.castMu.Lock()
	defer b.castMu.Unlock()
	if b.castEvents == 0 {
		// Olay yoksa mühür de yok: boş bir özet satırı, olmayan bir
		// oturumu varmış gibi gösterirdi.
		return
	}

	_, _ = fmt.Fprintf(b.rec.OutputStream(),
		"postern sftp: %d events, digest sha256:%s\r\n",
		b.castEvents, hex.EncodeToString(b.castDigest[:]))
}
