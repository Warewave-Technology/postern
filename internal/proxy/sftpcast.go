package proxy

// SFTP olaylarının oturum KAYDINA yazılması.

import (
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
