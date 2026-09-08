package proxy

// SFTP olaylarının oturum KAYDINA yazılması.

import (
	"fmt"
	"strings"
	"sync"

	"github.com/Warewave-Technology/postern/internal/sftpaudit"
	"github.com/Warewave-Technology/postern/internal/sftpcast"
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
 * ⚠️ SATIRIN BİÇİMİ VE MÜHÜR ARTIK internal/sftpcast'TE. Taşınmasının
 * sebebi ikinci bir okuyucu: defterdeki satırların mührü yeniden
 * hesaplanıyor (internal/verify) ve iki taraf AYNI BAYTLARI üretmek
 * zorunda. Biçimi burada tutup orada bir kez daha yazmak, bir gün
 * sessizce ayrışan iki uygulama demekti — ve ayrıştıkları gün kontrol,
 * dokunulmamış her oturumu "değiştirilmiş" diye raporlardı.
 *
 * Burada kalan şey BROKER'IN İŞİ: satırı kayda yazmak, kilidi tutmak,
 * ve mührü oturum kapanırken çağırana vermek.
 */

/*
 * castStderr, HEDEFİN stderr'inin kayda giden kopyası.
 *
 * ⚠️ NEDEN VAR: bu dosyanın kuralı "kayda giren her metin castSafe'ten
 * geçer" idi ve stderr o kuralın DIŞINDA kalmıştı — broker akışı
 * doğrudan hem panele hem kayda veriyordu. İki ayrı zarar veriyordu:
 *
 *  1. KAÇIŞ DİZİLERİ. Kayıt bir TERMİNAL kaydı; içindeki ESC dizisi
 *     oynatıldığında ÇALIŞIR. Hedefin stderr'ine yazabilen biri, kaydı
 *     izleyen denetçinin ekranını boyayabilir, satır silebilir, imleci
 *     oynatabilirdi.
 *
 *  2. SAHTE DENETİM SATIRI — ve bu daha kötüsü. Bir SFTP oturumunun
 *     kaydında ham protokol YOK: içindeki her satırı postern yazıyor
 *     ("postern sftp: …", bkz. castLine). Hedefin stderr'i o satırların
 *     arasına HAM giriyordu, yani hedef "postern sftp: get /etc/passwd
 *     (1.2 KiB)" yazıp kayda hiç olmamış bir denetim satırı
 *     ekleyebilirdi. Kaçış dizilerini temizlemek bunu KAPATMAZ; metin
 *     zaten yazdırılabilir.
 *
 * O yüzden temizlemek yetmiyor, ATFETMEK gerekiyor: her satır postern'in
 * kendi önekiyle ve "target wrote:" damgasıyla giriyor. Damgayı postern
 * yazıyor, sonrası alıntı. Hedef damgayı kendine veremiyor — kendi
 * yazdığı "target wrote:" de alıntının İÇİNDE kalır.
 *
 * ⚠️ YALNIZCA SFTP OTURUMUNDA. Kabuk ya da exec kanalında kayıt zaten
 * hedefin ham stdout'unu taşıyor — kaydın var olma sebebi kullanıcının
 * GÖRDÜĞÜNÜ yeniden üretmek. Orada stderr'i tek başına temizlemek
 * hiçbir şey satın almaz (aynı diziyi stdout'tan yazmak serbest) ama
 * kaydın sadakatini bozar. Ayrım, kaydın ne olduğuna göre: anlatı mı,
 * ekran kaydı mı.
 */
type castStderr struct {
	b *Broker

	/*
	 * ⚠️ MUTEKS ŞART, tek yazıcı olmasına rağmen. Baytları stderr boru
	 * hattı yazıyor ama yarım kalan son satırı Run boşaltıyor
	 * (flushStderrCast) ve o goroutine hedefin akışını okurken beklemeye
	 * devam edebiliyor — yani ikisi gerçekten aynı anda buradalar.
	 */
	mu sync.Mutex
	// line, satır sonu beklerken biriken baytlar.
	line []byte
	// over, satırın tavanı aştığı — kalanı satır sonuna kadar atılıyor.
	over bool

	/*
	 * held, kanalın TÜRÜ belli olmadan gelen baytlar; heldOver ise
	 * tavana çarpıp atılan olduğu (bkz. Write'ın kararsız pencere notu).
	 */
	held     []byte
	heldOver bool
}

func newCastStderr(b *Broker) *castStderr { return &castStderr{b: b} }

/*
 * maxCastStderrLine, tek bir stderr satırında biriktirilecek bayt.
 *
 * ⚠️ TAVAN BELLEK İÇİN, castSafe'in kendi 512'si yerine geçmiyor. Satır
 * sonu hiç göndermeyen bir hedef, tamponu sınırsız büyütebilirdi; bunu
 * yapan bir hedefin kayıtta ne yazdığı zaten castSafe'in tavanına
 * takılıyor, ama tamponun kendisi süreçte duruyor.
 */
const maxCastStderrLine = 4 * sftpcast.MaxField

func (w *castStderr) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	/*
	 * ⚠️ KAPI HER YAZMADA SORULUYOR, KURULUMDA DEĞİL. Kanalın SFTP'ye
	 * geçmesi `subsystem sftp` işlenince oluyor ve bu boru hattı ondan
	 * önce başlıyor — kurulumda bakmak, kararı her zaman "kabuk" tarafına
	 * düşürürdü. Aynı kapı sftpTap.Write'da da böyle soruluyor.
	 */
	if w.b.sftp.Load() != nil {
		// Bekletilenler de aynı satır makinesinden geçiyor.
		for _, c := range w.takeHeld() {
			w.feed(c)
		}
		for _, c := range p {
			w.feed(c)
		}

		return len(p), nil
	}

	/*
	 * ⚠️ KARARSIZ PENCEREDE KAYDA HİÇBİR ŞEY YAZILMIYOR, BEKLETİLİYOR.
	 *
	 * Kanalın türü, oturumu başlatan istek (shell/exec/subsystem)
	 * işlenene kadar belli değil (broker.startGate) — ve bu boru hattı
	 * ondan ÖNCE çalışmaya başlıyor. O pencerede hedefin stderr'ini
	 * kayda ham yazmak, atıfsız bir satır sokmanın yoluydu: hedef
	 * "postern sftp: get /etc/shadow (1.2 KiB)" yazıyor ve satır gerçek
	 * denetim satırlarının arasında duruyordu. Kaçış dizilerini atmak
	 * bunu kapatmıyor; sahte satır zaten yazdırılabilir.
	 *
	 * Kabuk kaydında ham bayt DOĞRU — o dosyanın tamamı zaten ham. O
	 * yüzden karar verilmeden yazmak yerine, karar verilene kadar
	 * tutuluyor: SFTP olursa atıflı ve temizlenmiş, kabuk olursa ham.
	 *
	 * ⚠️ SIRA ÖNEMLİ ve tersi ölçüldü: kapıya ÖNCE bakan bir sürüm,
	 * `b.sftp` dolu ama başlangıç kapısı henüz açılmamışken (ikisi aynı
	 * istek işlenirken sırayla oluyor) SFTP satırlarını da bekletiyordu
	 * ve uçtan uca testler düştü. `b.sftp` doluysa kanal zaten
	 * kararlaşmıştır.
	 */
	if !w.b.started() {
		return w.hold(p), nil
	}

	// Kabuk: beklettiğimiz baytlar da ham çıkıyor.
	if held := w.takeHeld(); len(held) > 0 {
		_, _ = w.b.rec.OutputStream().Write(held)
	}

	return w.b.rec.OutputStream().Write(p)
}

/*
 * hold, kanal türü belli olmadan gelen baytları tutar.
 *
 * ⚠️ TAVAN VAR ve aşan bayt ATILIYOR. Hiçbir program başlatmadan
 * kilobaytlarca stderr yazan bir hedef meşru değil; sınırsız tutmak,
 * kararı hiç vermeyen bir istemciyle birlikte belleği hedefin eline
 * verirdi. Atıldığı da kayboluyor değil: SFTP yolunda satırın sonundaki
 * işaret bunu söylüyor.
 */
func (w *castStderr) hold(p []byte) int {
	room := maxCastStderrLine - len(w.held)
	if room <= 0 {
		w.heldOver = true
		return len(p)
	}
	if len(p) > room {
		w.held = append(w.held, p[:room]...)
		w.heldOver = true
		return len(p)
	}
	w.held = append(w.held, p...)

	return len(p)
}

// takeHeld, bekletilen baytları alır ve tamponu boşaltır.
func (w *castStderr) takeHeld() []byte {
	held := w.held
	w.held = nil
	if w.heldOver {
		w.over = true
		w.heldOver = false
	}

	return held
}

// feed, tek bir baytı satır makinesine verir.
func (w *castStderr) feed(c byte) {
	if c == '\n' {
		w.emitLine()
		return
	}

	/*
	 * ⚠️ CR ATILIYOR, satır sonu sayılmıyor. Satırı postern kendi
	 * "\r\n"siyle kapatıyor; hedefin CRLF'i geçseydi kayıtta çift
	 * satır başı olurdu. Tek başına gelen CR de bir şey taşımıyor:
	 * bu satır bir anlatının içine ALINTI olarak giriyor, üzerine
	 * yazılacak bir ekran satırı değil.
	 */
	if c == '\r' {
		return
	}

	if len(w.line) >= maxCastStderrLine {
		w.over = true
		return
	}
	w.line = append(w.line, c)
}

/*
 * flush, satır sonu görmeden biten son satırı yazar.
 *
 * ⚠️ ÇAĞRILMAZSA SESSİZ KAYIP. Hedefin son cümlesi çoğu zaman satır
 * sonuyla bitmiyor ("connection closed" gibi) ve tamponda kalan şey
 * kayda hiç girmezdi.
 */
func (w *castStderr) flush() {
	if w == nil {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	/*
	 * ⚠️ HİÇ KARAR VERİLMEDEN KAPANAN OTURUM. Hedef stderr'e yazdı ama
	 * istemci hiçbir program başlatmadı: bekletilen baytlar hâlâ elimizde
	 * ve kayda girmeliler. ATIFLI yoldan giriyorlar — ham yazmak,
	 * pencerede kapattığımız açığı kapanışta geri açardı.
	 */
	for _, c := range w.takeHeld() {
		w.feed(c)
	}

	if len(w.line) == 0 && !w.over {
		return
	}
	w.emitLine()
}

// flushStderrCast, kayıt kapalıyken de çağrılabilen sarmalayıcı.
func (b *Broker) flushStderrCast() { b.castErr.flush() }

// emitLine, biriken satırı postern'in damgasıyla kayda yazar. w.mu
// TUTULUYOR OLMALI.
func (w *castStderr) emitLine() {
	line, over := string(w.line), w.over
	w.line, w.over = w.line[:0], false

	text := sftpcast.Safe(line)
	if over {
		/*
		 * castSafe kendi tavanına takıldıysa işareti zaten koydu; buraya
		 * ancak satır tamponu taştığında geliyoruz ve o durumda da
		 * atılmış bir şey olduğu söylenmeli.
		 */
		if !strings.HasSuffix(text, "…") {
			text += "…"
		}
	}

	b := w.b
	b.castMu.Lock()
	defer b.castMu.Unlock()

	/*
	 * ⚠️ MÜHÜR ÖZETİNE KATILMIYOR. Özetin cevapladığı soru "aynı denetim
	 * OLAYLARI mı" ve bu bir olay değil, hedefin bir cümlesi. Katsaydık
	 * sayaç "kaç istek denetlendi" sorusunu artık cevaplamazdı. Satırın
	 * kaydın içinde durduğunun kanıtı zincirin kendisi.
	 */
	/*
	 * ⚠️ ÖNEK KANALIN GERÇEĞİNİ SÖYLÜYOR. Bu satır, hiçbir program
	 * başlatmadan kapanan bir oturumda da yazılabiliyor (flush) ve orada
	 * "sftp" demek, postern'in KENDİ hakkında yanlış bir cümlesi olurdu.
	 */
	who := "postern:"
	if b.sftp.Load() != nil {
		who = "postern sftp:"
	}
	_, _ = fmt.Fprintf(b.rec.OutputStream(), "%s target wrote: %s\r\n", who, text)
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

	line := sftpcast.Line(e)

	b.castMu.Lock()
	defer b.castMu.Unlock()

	// Yazma hatası yutuluyor: kaydın arıza yolu OnFailure.
	_, _ = b.rec.OutputStream().Write([]byte(line))

	/*
	 * ⚠️ MÜHÜRE YAZILAN ŞEY, KAYDA YAZILAN SATIRIN AYNISI — aynı
	 * değişkenden. İki ayrı çağrıyla üretilseydi, biçimi değiştiren bir
	 * düzeltme ikisini ayırabilirdi ve mühür, dosyada duran satırları
	 * değil başka bir şeyi mühürlerdi.
	 */
	b.seal.Add(line)
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
	if b.seal.Events() == 0 {
		// Olay yoksa mühür de yok: boş bir özet satırı, olmayan bir
		// oturumu varmış gibi gösterirdi.
		return
	}

	_, _ = b.rec.OutputStream().Write([]byte(b.seal.Line()))
}

/*
 * SFTPSeal, kaydın mühür satırındaki iki sayı: kaç olay ve özetleri.
 *
 * ⚠️ RUN DÖNDÜKTEN SONRA OKUNMALI: mühür satırı Run'ın içinde yazılıyor
 * (sealSFTPCast) ve daha önce okunan değer, o oturumun son olaylarını
 * saymaz.
 *
 * ⚠️ MÜHÜRÜN TÜKETİCİSİ VARDI AMA PROGRAMATİK DEĞİLDİ: satır yalnızca
 * .cast dosyasının içinde duruyordu, yani ona bakmanın tek yolu kaydı
 * açıp gözle okumaktı. Defterin eksik ya da DEĞİŞTİRİLMİŞ olup
 * olmadığını söyleyen kontrol (verify.JournalOf) bu iki sayıyı istiyor;
 * oturumun satırına yazılmaları buradan başlıyor.
 *
 * ⚠️ OLAY YOKKEN ÖZET BOŞ DÖNÜYOR, SIFIRLARIN ONALTILIĞI DEĞİL. Kayda
 * mühür satırı da yazılmıyor (yukarısı); veritabanına bir özet yazmak,
 * dosyada karşılığı olmayan bir değeri "kayıt böyle diyor" diye
 * saklamak olurdu.
 */
func (b *Broker) SFTPSeal() (events int64, digest string) {
	b.castMu.Lock()
	defer b.castMu.Unlock()

	if b.seal.Events() == 0 {
		return 0, ""
	}

	return b.seal.Events(), b.seal.Head()
}
