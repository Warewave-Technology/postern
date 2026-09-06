package record

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
)

/*
 * Kayıt zinciri: "bu .cast dosyası postern'in yazdığının aynısı" sorusunu
 * cevaplayabilmek için.
 *
 * ⚠️ NEDEN VAR. Bu ürünün en büyük iddiası oturumların kaydedildiği. Ama
 * "kayıt olan bitendir" cümlesi bugün KANITSIZ: dosyayı düzenleyen biri
 * hiçbir iz bırakmıyor. Rakiplerin durumu da aynı ve bunu kendi belgeleri
 * yazıyor — Teleport'un eBPF kaydı için "not a substitute for a Linux
 * Security Module" ve ayrıcalıklı kullanıcıların kaydı bozabileceği,
 * Boundary için kaydın PATH/kabuk manipülasyonuyla aldatılabileceği. Yani
 * sektörün tamamında bu bir iddia; burada kanıta çevriliyor.
 *
 * TANIM — doğrulayıcı bunu birebir uygulamalı:
 *
 *	H(0) = SHA-256(domainSep)
 *	H(n) = SHA-256(H(n-1) ‖ satır_n)          satır_n sondaki '\n' DAHİL
 *	baş  = hex(H(N))
 *
 * ⚠️ SATIRIN SONUNDAKİ '\n' ZİNCİRE DAHİL. Doğrulayıcı dosyayı okuyup
 * satır sonlarından ayırıyor; ayıracı dışarıda bırakmak, "satır" kavramını
 * iki tarafta iki farklı şey yapardı. Dahil etmek, zincirin kapsadığı
 * baytlarla dosyadaki baytları BİREBİR aynı kılıyor.
 *
 * ⚠️ ALAN AYIRICI (domainSep) BOŞ ZİNCİR İÇİN DEĞİL, KARIŞMA İÇİN. H(0)
 * sıfır olsaydı, bir zincir başı başka bir bağlamda hesaplanmış bir
 * SHA-256 ile karıştırılabilirdi. Ayrıca hiç olay yazılmamış bir kaydın
 * da tanımlı ve sıfırdan farklı bir başı oluyor.
 *
 * ⚠️ NE KANITLAR, NE KANITLAMAZ — bu ayrımı belgede de aynı sertlikte
 * yazacağız. Zincir, dosyanın yazıldıktan SONRA değiştirilmediğini
 * gösterir. Bastion'da root olan biri hem dosyayı hem de veritabanındaki
 * başı yeniden yazabilir; zincirin tek başına kapattığı şey bu değil.
 * Kapatan şey, başın makinenin ULAŞAMADIĞI bir yere de yazılması — arşiv
 * kovası ve isteğe bağlı dış uç. Zincir o çapanın taşıdığı değerdir.
 */

// domainSep, H(0)'ın tohumu. Değeri DEĞİŞTİRİLEMEZ: değişirse eski
// kayıtların başları doğrulanamaz hale gelir. Sürüm gerekirse yeni bir
// sabitle yeni bir zincir sürümü açılır, bu satır oynatılmaz.
const domainSep = "postern-recording-chain-v1"

// chainWriter, alttaki yazıcıya giden HER baytı zincire katar.
//
// ⚠️ SARMALAMAK, KANCA KOYMAKTAN DAHA GÜVENLİ. Olay yazan yolların her
// birine tek tek zincir çağrısı eklemek, ileride eklenecek yeni bir yazma
// yolunun sessizce zincir dışında kalmasına açıktı. Burada zincirin
// kapsamı "dosyaya giden baytlar" olarak tanımlı; yeni bir yol eklemek
// onu atlayamaz.
type chainWriter struct {
	w     io.WriteCloser
	sum   [sha256.Size]byte
	links int64
}

func newChainWriter(w io.WriteCloser) *chainWriter {
	return &chainWriter{w: w, sum: sha256.Sum256([]byte(domainSep))}
}

/*
 * Write, önce alttaki yazıcıya yazar, SONRA zincire katar.
 *
 * ⚠️ SIRA ÖNEMLİ VE BU YÖNDE. Önce zincirleyip sonra yazsaydık, başarısız
 * bir yazma zincire dosyada olmayan bir satır koyardı ve kayıt daha
 * yazılırken doğrulanamaz hale gelirdi. Bu yönde ise zincir, dosyaya
 * GERÇEKTEN ULAŞAN baytları kapsıyor.
 *
 * Kısmi yazmada da aynı kural: yalnızca n bayt katılıyor, çünkü dosyada
 * duran o kadar.
 */
func (c *chainWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if n > 0 {
		c.sum = sha256.Sum256(append(c.sum[:], p[:n]...))
		c.links++
	}

	return n, err
}

func (c *chainWriter) Close() error { return c.w.Close() }

// head, zincirin o anki başı ve halka sayısı.
func (c *chainWriter) head() (string, int64) {
	return hex.EncodeToString(c.sum[:]), c.links
}

/*
 * VerifyChain, bir kaydı baştan okuyup zinciri yeniden hesaplar ve
 * beklenen başla karşılaştırır.
 *
 * ⚠️ SATIR SINIRI DOSYADAN YENİDEN KURULUYOR. Yazma tarafında her Write
 * çağrısı tam bir satırdı; burada dosya '\n' sonrasından ayrılıyor.
 * İkisinin aynı sonucu vermesi, asciicast yazıcısının "satır başına tek
 * yazma" değişmezine dayanıyor ve o değişmez ayrı bir testle çivili
 * (TestEveryWriteIsExactlyOneLine).
 *
 * Dönen halka sayısı, kısa kalmış bir dosyayı teşhis etmeye yarıyor:
 * baş tutmuyorsa "kaç halkaya kadar tuttuğu" sorusunun cevabı çağırana
 * lazım oluyor.
 */
func VerifyChain(r io.Reader, wantHead string) (ok bool, links int64, err error) {
	sum := sha256.Sum256([]byte(domainSep))

	buf := make([]byte, 0, 64*1024)
	tmp := make([]byte, 32*1024)

	for {
		n, rerr := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)

			for {
				i := indexByte(buf, '\n')
				if i < 0 {
					break
				}
				sum = sha256.Sum256(append(sum[:], buf[:i+1]...))
				links++
				buf = buf[i+1:]
			}
		}

		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return false, links, rerr
		}
	}

	/*
	 * ⚠️ SON SATIRIN '\n'İ YOKSA O DA BİR HALKA. Yazma yolu her satırı
	 * '\n' ile bitiriyor, ama kısmi bir yazma (disk dolması) sonuncuyu
	 * yarım bırakabilir. O yarım baytları zincirin dışında bırakmak,
	 * kesilmiş bir kaydı "tam ve doğru" göstermenin yolu olurdu.
	 */
	if len(buf) > 0 {
		sum = sha256.Sum256(append(sum[:], buf...))
		links++
	}

	return hex.EncodeToString(sum[:]) == wantHead, links, nil
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}

	return -1
}
