/*
 * Package sftpcast, bir SFTP denetim olayının oturum KAYDINA yazılan
 * satırını üretir ve o satırların mühür özetini tutar.
 *
 * ⚠️ NİYE AYRI BİR PAKET — VE GEREKÇESİ SONRADAN ORTAYA ÇIKTI. Satır
 * biçimi proxy'nin içinde duruyordu, çünkü tek yazan oydu. Sonra ikinci
 * bir okuyucu çıktı: defterdeki satırların mührü YENİDEN hesaplanıyor
 * (internal/verify) ve "aynı olaylar mı" sorusu ancak İKİ TARAF DA AYNI
 * BAYTLARI üretirse sorulabiliyor. Biçimi ikinci kez yazmak, bir gün
 * sessizce ayrışan iki uygulama demekti: özet tutmaz, kontrol her
 * oturumu "değiştirilmiş" diye raporlar, ve alarmın kendisi hatalı olur.
 *
 * ⚠️ BU PAKETİN ÇIKTISI BİR BİÇİM SÖZLEŞMESİ. Satır değişirse eski
 * kayıtların mührü yeniden hesaplanamaz; yani buradaki her düzeltme,
 * o tarihe kadarki bütün oturumların defter kontrolünü bozar. Yeni bir
 * alan eklemek gerekirse yeni bir mühür sürümü açılmalı, bu satırlar
 * oynatılmamalı — record/chain.go'daki domainSep kararının aynısı.
 *
 * ⚠️ ASIL İŞİ TEMİZLEMEK. Yol ve gerekçe metinleri KARŞI TARAFTAN
 * geliyor: dosya adını hedefteki kullanıcı koyuyor, gerekçe metnini
 * hedefin sftp-server'ı yazıyor. Bir terminal kaydına giren metin
 * OYNATILDIĞINDA TERMİNALDE ÇALIŞIR — içinde ESC dizisi olan bir dosya
 * adı, kaydı izleyen denetçinin ekranını boyayabilir, imleci
 * oynatabilir, satırları silebilir. Yani kaydı okunmaz ya da YANILTICI
 * kılabilir. Kayda giren her metin bu yüzden buradan geçiyor.
 */
package sftpcast

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Warewave-Technology/postern/internal/sftpaudit"
)

// maxField, kayda yazılan tek bir alanın tavanı.
//
// ⚠️ Yol uzunluğu zaten sınırlı (sftpaudit.maxPath) ama gerekçe metni
// hedeften geliyor ve sınırı hedef koyuyor. Kayıt satırının uzunluğu
// zincire giren bayt sayısıdır; sınırsız bırakmak, tek bir isteğin
// kaydı şişirmesine izin vermek olurdu.
const maxField = 512

/*
 * Safe, karşı taraftan gelen metni bir terminal kaydına konabilir
 * hâle getirir.
 *
 * ⚠️ YAZDIRILABİLİR OLMAYAN HER ŞEY ATILIYOR, kaçırılmıyor. Kaçırmak
 * (örneğin "\x1b" yazmak) metni okunur tutardı ama satırı uzatır ve
 * "gerçekten ne vardı" sorusunu cevaplamaz; atmak, ekranda görünenin
 * dosyada olanla aynı olmasını sağlıyor. Atılan bir şey olduğunu
 * kaybetmemek için sonuna işaret konuyor.
 */
func Safe(s string) string {
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
		case r == 0x200e || r == 0x200f ||
			(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069):
			/*
			 * ⚠️ İKİ YÖNLÜ YAZI DENETİMLERİ: SATIRI BOYAMIYOR, YALAN
			 * SÖYLETİYOR.
			 *
			 * Kaçış dizileri ekranı yeniden yazıyor; bunlar daha
			 * sinsi — satır olduğu gibi duruyor ama BAŞKA okunuyor.
			 * "fatura<U+202E>gnp.exe" adlı bir dosyayı alan bir
			 * oturumun kaydında satır "fatura exe.png ... (0 B)" diye
			 * görünüyor: denetçi bir resim indirildiğini sanıyor.
			 * Kayıt, "kim hangi dosyayı aldı" sorusunun cevabı; o
			 * cevabın yanlış OKUNMASI, kaydın okunmaz olmasından kötü.
			 *
			 * Canlı denemede bulundu: dosya adı panelin arşivinde
			 * temizleniyordu ama kayda olduğu gibi giriyordu.
			 */
			dropped = true
		default:
			if b.Len() >= maxField {
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

// verb, olayı kayıtta görünecek fiile çevirir.
//
// ⚠️ Transfer YÖNÜYLE yazılıyor: "transfer" tek başına, bir dosyanın
// hedefe mi gittiğini yoksa hedeften mi geldiğini söylemiyor — ve bir
// denetçinin ilk sorduğu şey o.
func verb(e sftpaudit.Event) string {
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

// bytesOf, taşınan baytı okunur hâle getirir.
func bytesOf(n int64) string {
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
 * Line, bir denetim olayının kayda yazılacak satırı.
 *
 * Biçim kasten sabit ve okunur: "postern sftp: <fiil> <yol>[ → <yeni>]
 * [(<bayt>)][ — <gerekçe>]". Satır sonu "\r\n" çünkü kayıt bir TERMİNAL
 * kaydı ve oynatıcı satır başı bekliyor (recordIntent'teki kalıbın aynısı).
 */
func Line(e sftpaudit.Event) string {
	var b strings.Builder
	b.WriteString("postern sftp: ")
	b.WriteString(verb(e))

	if e.Path != "" {
		b.WriteString(" ")
		b.WriteString(Safe(e.Path))
	}
	if e.NewPath != "" {
		b.WriteString(" → ")
		b.WriteString(Safe(e.NewPath))
	}

	switch {
	case e.Read > 0 && e.Wrote > 0:
		b.WriteString(" (↓" + bytesOf(e.Read) + " ↑" + bytesOf(e.Wrote) + ")")
	case e.Read > 0:
		b.WriteString(" (" + bytesOf(e.Read) + ")")
	case e.Wrote > 0:
		b.WriteString(" (" + bytesOf(e.Wrote) + ")")
	}

	// ⚠️ BAŞARISIZLIK GÖRÜNÜR OLMAK ZORUNDA. "Kimse denemedi" ile
	// "denedi ve reddedildi" ayrı bulgular ve kayıt ikincisini
	// göstermezse denetçi ilkini varsayar.
	if !e.OK && !strings.HasPrefix(string(e.Op), "denied.") {
		b.WriteString(" [failed]")
	}
	if e.Detail != "" {
		b.WriteString(" — ")
		b.WriteString(Safe(e.Detail))
	}
	b.WriteString("\r\n")

	return b.String()
}

/*
 * Seal, kayda giren SFTP satırlarının mührü: kaç satır ve hangi
 * satırlar.
 *
 * ⚠️ ÖZET SIRADAN BAĞIMSIZ: her satırın kendi özeti XOR'lanıyor,
 * zincirlenmiyor. Sebebi defterin kendisi — satırlar toplu yazılıyor ve
 * `id` ile sıralanıyor, yani aynı olay kümesi farklı sırada okunabiliyor.
 * Sıraya bağlı bir özet, hiçbir şey değişmemişken tutmayabilirdi.
 * Özetin cevapladığı soru "aynı olaylar mı"; "aynı sırada mı" değil —
 * sıranın kanıtı zaten satırların kendisi ve onları zincir kapsıyor.
 *
 * ⚠️ XOR'UN BEDELİ: BİRBİRİNİN AYNI İKİ SATIR BİRBİRİNİ GÖTÜRÜR. Aynı
 * satırdan çift sayıda silmek özeti değiştirmez. Bu yüzden özet TEK
 * BAŞINA kullanılmıyor: sayı da karşılaştırılıyor (verify.JournalOf) ve
 * çift silme sayıyı iki azaltır. İkisi birlikte, tek tek
 * yakalayamadıklarını yakalıyor — ve hangisinin neyi yakaladığını
 * bilmeden ikisinden birini atmak, kontrolü sessizce zayıflatır.
 */
type Seal struct {
	events int64
	digest [sha256.Size]byte
}

// Add, kayda yazılmış bir satırı mühüre katar.
func (s *Seal) Add(line string) {
	sum := sha256.Sum256([]byte(line))
	for i := range s.digest {
		s.digest[i] ^= sum[i]
	}
	s.events++
}

// Events, mühürlenen satır sayısı.
func (s *Seal) Events() int64 { return s.events }

// Head, özetin onaltılık gösterimi.
//
// ⚠️ HİÇ OLAY YOKKEN DE BİR DEĞER DÖNER (sıfırların onaltılığı) ve o
// değer "mühür yok" demek DEĞİL. Boş bir oturumun mühür satırı hiç
// yazılmıyor; çağıran bu ayrımı Events()'e bakarak koruyor.
func (s *Seal) Head() string { return hex.EncodeToString(s.digest[:]) }

/*
 * Line, kaydın sonuna yazılan mühür satırı.
 *
 * ⚠️ NİYE AYRI BİR SATIR. Zincir dosyanın DEĞİŞMEDİĞİNİ gösteriyor;
 * göstermediği şey KAÇ olayın olması gerektiği. Kaydı baştan sona
 * yeniden yazabilen biri zinciri de yeniden hesaplar — o sınır
 * SECURITY.md'de yazılı ve bu satır onu değiştirmiyor. Değiştirdiği şey
 * daha dar ve gerçek: satır sayısıyla özet tutmuyorsa kaydın
 * ORTASINDAN satır çıkarılmış demektir, ki bu zinciri yeniden
 * hesaplamadan yapılabilecek en kolay müdahale.
 *
 * ⚠️ "1 events" YAZIYOR VE ÖYLE KALIYOR. Tekil/çoğul düzeltmesi bir
 * biçim değişikliğidir: o günden önceki kayıtların mührü bir daha
 * okunamazdı. Bu satır insan için değil, karşılaştırma için.
 */
func (s *Seal) Line() string {
	return fmt.Sprintf("postern sftp: %d events, digest sha256:%s\r\n",
		s.events, s.Head())
}
