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
 * beginSFTP, `subsystem sftp` hedefe geçtikten sonra denetimi başlatır.
 *
 * Sıra önemli: istek hedefe İLETİLDİKTEN sonra kuruluyor. SSH'ta veri
 * ancak subsystem kabul edildikten sonra akmaya başladığı için ilk SFTP
 * paketi (INIT) bu noktadan sonra gelir — yani hiçbir bayt denetimsiz
 * geçmiyor.
 */
func (b *Broker) beginSFTP(req *ssh.Request) {
	if b.sftpSink == nil || req.Type != "subsystem" {
		return
	}
	if subsystemName(req.Payload) != "sftp" {
		return
	}
	if b.sftp.Load() != nil {
		// Aynı kanalda ikinci bir subsystem olmaz; olduysa ilkini
		// bozmuyoruz ve durumu görünür kılıyoruz.
		b.logger.Warn("second sftp subsystem on one channel ignored")
		return
	}
	b.sftp.Store(sftpaudit.NewSession(b.sftpSink.Emit))
	b.logger.Info("sftp session audited")
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
//
// Her Write'ta önce GERÇEK hedefe yazıyor (kullanıcı ile hedef arasına
// gecikme koymamak için), sonra kopyayı ilgili tarafa veriyor.
type sftpTap struct {
	dst io.Writer
	// rec, SFTP AKTİF DEĞİLKEN yazılacak kayıt akışı; nil olabilir.
	rec io.Writer
	// feed, kopyayı çözümleyiciye veren yön (FromClient / FromTarget).
	feed func(*sftpaudit.Session, []byte) error

	b *Broker
}

/*
 * Write, baytı hedefe geçirir ve kopyasını yönlendirir.
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
	n, err := t.dst.Write(p)
	if err != nil {
		return n, err
	}
	if s := t.b.sftp.Load(); s != nil {
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

func feedFromClient(s *sftpaudit.Session, p []byte) error { return s.FromClient(p) }
func feedFromTarget(s *sftpaudit.Session, p []byte) error { return s.FromTarget(p) }

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
