package proxy

// SFTP kanalının denetlenmesi.
//
// NEDEN VAR: `subsystem sftp` uzun süre reddedildi ve gerekçesi
// ölçülmüştü (requests.go dosya başı): transfer terminal kaydına ham
// ikili protokol olarak düşüyor, 1 GB'lık bir indirme 1 GB'lık bir
// "terminal kaydı" üretiyor ve "kim hangi dosyayı aldı" sorusu cevapsız
// kalıyordu. Burası o sorunun cevaplandığı yer; kanal ancak bu yüzden
// açılabiliyor.
//
// ⚠️ POSTERN ARAYA SFTP SUNUCUSU KOYMUYOR. Baytlar hedefe olduğu gibi
// gidiyor; yalnızca kopyaları çözümleniyor. Protokolü yeniden uygulamak,
// kendi hatalarımızı kullanıcıyla hedefin arasına koymak olurdu.

import (
	"io"
	"sync/atomic"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/sftpaudit"
)

// SFTPSink, üretilen dosya olaylarının gideceği yer.
//
// Emit veri yolundan çağrılıyor: yavaş olmamalı. Kalıcılaştırma
// (veritabanına yazım) çağıranın işi.
type SFTPSink interface {
	Emit(sftpaudit.Event)
}

/*
 * beginSFTP, `subsystem sftp` isteği HEDEFE İLETİLMEDEN ÖNCE denetimi
 * kurar. Kurduysa true döner (bkz. cancelSFTP).
 *
 * ⚠️ SIRA TERSİNEYDİ VE DENETİMDE DELİK AÇIYORDU.
 *
 * Denetim, istek iletildikten SONRA kuruluyordu ve gerekçesi şu
 * protokol iddiasıydı: "SSH'ta veri ancak subsystem kabul edildikten
 * sonra akmaya başlar". RFC 4254 böyle bir sıra dayatmıyor — kanal
 * açıldığı anda istemcinin bir penceresi var ve CHANNEL_DATA'yı
 * istediği zaman, subsystem cevabını beklemeden gönderebiliyor.
 * OpenSSH bu baytları tamponlayıp sftp-server başlayınca stdin'ine
 * veriyor.
 *
 * Pencere en az bir hedef gidiş-dönüşü kadar genişti: forwardRequest
 * hedefin cevabını beklerken down→up borusu çoktan akıyor ve tap,
 * `b.sftp` hâlâ nil olduğu için baytları çözümleyiciye HİÇ vermiyordu.
 * Çözümleyici bunu fark edemiyor: framer saf uzunluk-önekli bir
 * tarayıcı, akış herhangi bir paket sınırından başlarsa temiz
 * ayrışıyor ve öncesini sessizce atlıyor. Yani boru hattı yapan bir
 * istemcinin ilk OPEN/READ'i hedefte çalışıyor, session_files'a hiç
 * yazılmıyor ve dosya listesi kendini eksiksiz sanıyordu.
 *
 * Artık kurulum iletimden önce; hedef subsystem'i reddederse çağıran
 * cancelSFTP ile geri alıyor.
 *
 * ⚠️ PENCERE DARALDI, KAPANMADI — ve bu ölçüldü, tahmin değil.
 *
 * Kurulum, isteği İSTEMCİ YÖNÜNDEKİ TEK relay goroutine'i sıradan
 * ALDIĞI an oluyor; kanalın açıldığı an değil. İstemci `subsystem
 * sftp`'den önce geçerli başka bir istek koyarsa (örneğin
 * `env LANG=C`, varsayılan listede kabul ediliyor), kurulum o isteğin
 * hedef gidiş-dönüşü kadar gecikiyor ve aradaki baytlar yine
 * denetimsiz geçiyor. Ölçüldü: hedef ilk isteği 500 ms tuttuğunda,
 * boru hattıyla gelen OPEN hedefte çalıştı ve tek olay üretmedi.
 *
 * Kalıcı çözüm kurulumu KANAL AÇILIŞINA bağlamak olurdu (subsystem
 * beklemeden), ama o, SFTP olmayan her kanala da çözümleyici takmak
 * demek. Kararı vermeden önce ölçmek gerekiyor; şimdilik bilinen ve
 * yazılı bir sınır.
 */
func (b *Broker) beginSFTP(req *ssh.Request) bool {
	if b.sftpSink == nil || req.Type != "subsystem" {
		return false
	}
	if subsystemName(req.Payload) != "sftp" {
		return false
	}
	if b.sftp.Load() != nil {
		// Aynı kanalda ikinci bir subsystem olmaz; olduysa ilkini
		// bozmuyoruz ve durumu görünür kılıyoruz.
		b.logger.Warn("second sftp subsystem on one channel ignored")
		return false
	}
	b.sftp.Store(sftpaudit.NewSession(b.sftpSink.Emit))
	b.logger.Info("sftp session audited")
	return true
}

/*
 * cancelSFTP, hedef subsystem'i reddettiğinde kurulan denetimi geri alır.
 *
 * ⚠️ GERİ ALMAK ŞART, çünkü kurulum artık cevaptan önce oluyor.
 * Bırakılsaydı iki şey bozulurdu: kanal SFTP sanılacağı için
 * sayGoodbye kullanıcıya sebebi yazmaktan vazgeçerdi, ve aynı kanalda
 * açılan bir kabuğun baytları çözümleyiciye SFTP diye girip denetimi
 * çökertirdi — yani hedefin "hayır"ı, oturumu kesen bir arızaya
 * dönüşürdü.
 */
func (b *Broker) cancelSFTP() {
	b.sftp.Store(nil)
	b.logger.Warn("sftp subsystem refused by target; audit not started")
}

/*
 * finishSFTP, kanal kapanırken yarım kalan transferleri yazdırır.
 *
 * ⚠️ ŞART: bağlantı transfer ortasında koparsa CLOSE hiç gelmez. Bu
 * çağrı olmadan, veriyi çekip bağlantıyı koparmak izi silmenin yolu
 * olurdu.
 */
func (b *Broker) finishSFTP() {
	if s := b.sftp.Load(); s != nil {
		s.Finish()
	}
}

// sftpTap, veri yolunun üstüne takılan kopya alıcı.
type sftpTap struct {
	dst io.Writer
	// rec, SFTP AKTİF DEĞİLKEN yazılacak kayıt akışı; nil olabilir.
	rec io.Writer
	// dir, hangi yönü taşıdığımız. Çözümleyiciyi besleme SIRASINI
	// belirliyor — bkz. Write.
	dir direction

	b *Broker
}

// feed, kopyayı çözümleyiciye taşıdığımız yöne göre verir.
func (t *sftpTap) feed(s *sftpaudit.Session, p []byte) error {
	if t.dir == fromClient {
		return s.FromClient(p)
	}
	return s.FromTarget(p)
}

/*
 * Write, baytı karşı uca geçirir ve kopyasını çözümleyiciye yönlendirir.
 *
 * ⚠️ İSTEMCİ YÖNÜNDE ÇÖZÜMLEYİCİ ÖNCE BESLENİYOR — SIRA BİR DENETİM
 * KARARI, PERFORMANS KARARI DEĞİL.
 *
 * Eskiden her iki yönde de önce hedefe yazılıyordu ("araya gecikme
 * koymamak için"). Bunun bedeli ölçüldü ve ağır: istek hedefe ulaşıp
 * CEVABI GERİ GELEBİLİYOR, çözümleyici o isteği henüz görmeden. Cevap
 * eşleşecek bekleyen istek bulamıyor ve sessizce atılıyor
 * (sftpaudit: takePending).
 *
 * Görüntüsü, bir denetim aracı için en kötüsü: /etc/shadow açılıp
 * okunuyor ve session_files'da TEK SATIR olmuyor; ya da satır oluşuyor
 * ama `read=0` diyor — "açtı, hiçbir şey almadı". İkisi de dosya
 * listesini eksiksiz sanan bir ekranda görünmüyor.
 *
 * ÖLÇÜLDÜ: anında cevap veren bir hedefle 20 koşuda 20 kayıp. Deponun
 * kendi testleri de bu yarışı 300 koşuda 4-5 kez kaybediyordu — daha
 * önce "koşumdaki gürültü" sanılan kararsızlığın sebebi buydu.
 *
 * ⚠️ HEDEF YÖNÜ ESKİSİ GİBİ: önce yaz, sonra besle. O yönde istek zaten
 * kaydedilmiş oluyor (istemci yönü artık besleme-önce), ve cevabı
 * kullanıcıya geciktirmemek doğru olan.
 *
 * ⚠️ İSTEMCİ YÖNÜNDE ARTIK FAIL-CLOSED: çözümleme hata verirse baytlar
 * hedefe HİÇ GİTMİYOR. Bozuk bir akış yollayarak denetimi kapatıp işe
 * devam etmek mümkün değil.
 *
 * Bedeli: yükleme yolunda çözümleme süresi baytların önüne geçiyor.
 * Denetimin doğruluğu bunun karşılığı.
 *
 * ⚠️ SFTP AKTİFKEN KAYDA YAZILMIYOR. Yazılsaydı, bu kanalın
 * reddedilmesine sebep olan kusur aynen geri gelirdi: oynatılamayan,
 * transfer boyutunda şişen bir .cast dosyası.
 *
 * ⚠️ ÇÖZÜMLEME HATASI OTURUMU BİTİRİR. Paket sınırı kaybolduysa sonraki
 * her olay uydurma olur. Kaydın açılamamasında verilen kararın aynısı:
 * denetlenemeyen bir kanal geçmez (bkz. lifecycle.go, Records.Create).
 */
func (t *sftpTap) Write(p []byte) (int, error) {
	s := t.b.sftp.Load()

	if s != nil && t.dir == fromClient {
		if err := t.feed(s, p); err != nil {
			t.b.abortAudit(err)
			return 0, err
		}
		return t.dst.Write(p)
	}

	n, err := t.dst.Write(p)
	if err != nil {
		return n, err
	}
	if s != nil {
		if err := t.feed(s, p[:n]); err != nil {
			t.b.abortAudit(err)
			return n, err
		}
		return n, nil
	}
	if t.rec != nil {
		if _, err := t.rec.Write(p[:n]); err != nil {
			return n, err
		}
	}
	return n, nil
}

// sftpState, broker'a takılan çalışma anı durumu.
//
// atomic: subsystem isteği request goroutine'inden gelirken borular
// zaten akıyor.
type sftpState = atomic.Pointer[sftpaudit.Session]

/*
 * abortAudit, denetim çöktüğünde oturumu KAPATIR.
 *
 * ⚠️ NEDEN AÇIKÇA KAPATIYORUZ: istemci→hedef borusu bittiğinde oturum
 * kendiliğinden kapanmıyor ve bu BİLİNÇLİ — kullanıcı girdisini
 * kapattığında (`cat f | ssh host 'wc -l'`) oturumun devam etmesi
 * gerekiyor. Ama o davranış burada tam ters etki yapıyordu: çözümleme
 * hatasında boru hata döndürüp susuyor, oturum ise akmaya devam
 * ediyordu. ÖLÇÜLDÜ — bu çağrı eklenmeden önce bozuk bir uzunluk
 * başlığı göndermek, denetimi kapatıp transferi sürdürmenin yoluydu.
 *
 * Once: iki yön aynı anda hata verebilir; kapatma bir kez.
 */
func (b *Broker) abortAudit(err error) {
	b.abortOnce.Do(func() {
		b.logger.Error("sftp audit failed; ending session", "error", err)
		// ⚠️ SEBEP SAKLANIYOR: Run bunu ÇAĞIRANA döndürüyor. Yalnızca
		// loglamak, oturumu denetim çöktüğü için kapattığımızı
		// çağıranın hiç öğrenememesi demekti (bkz. Run'ın dönüşü).
		b.abortErr = err
		close(b.aborted)
		b.down.Close()
		b.up.Close()
	})
}
