package proxy

// SFTP dosya olaylarının kalıcılaştırılması (store.session_files).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Warewave-Technology/postern/internal/sftpaudit"
	"github.com/Warewave-Technology/postern/internal/store"
)

/*
 * journalCap, henüz yazılamamış olay tavanı.
 *
 * ⚠️ AŞILDIĞINDA OLAY DÜŞÜRÜLMÜYOR, OTURUM DÜŞÜYOR. Sessizce atılan bir
 * denetim satırı en kötü sonucu verir: kayıt eksik olduğu hâlde tam
 * görünür. Veritabanı olayları yazamayacak kadar geride kaldıysa doğru
 * cevap "denetlenemiyorsa geçmez" — kaydın açılamamasında verilen
 * kararın aynısı.
 */
const journalCap = 10000

// flushEvery, biriken olayların yazılma sıklığı.
//
// Anında yazmıyoruz: Emit veri yolundan çağrılıyor ve olay başına bir
// veritabanı turu, denetimi transferin hız sınırı hâline getirirdi.
const flushEvery = 2 * time.Second

/*
 * fileWriter, denetim satırlarını yazan şey.
 *
 * ⚠️ ARAYÜZ TÜKETİCİ TARAFINDA ve sebebi ölçüldü: `*store.Store` somut
 * tipiyle, "yazma çöktüğünde grup geri konuyor mu" sorusu ancak gerçek
 * bir veritabanı ayağa kaldırılarak sınanabilirdi — ve pratikte hiç
 * sınanmadı. Mutasyon bunu gösterdi: putBack'in kendi testi geçiyordu,
 * flush'ın onu ÇAĞIRDIĞINI ölçen bir şey yoktu. Bu depoda tekrar eden
 * arıza tam olarak bu.
 */
type fileWriter interface {
	AddSessionFiles(ctx context.Context, sessionID string, files []store.SessionFile) error
}

// sftpJournal, olayları biriktirip toplu yazan SFTPSink.
type sftpJournal struct {
	store     fileWriter
	sessionID string
	log       *slog.Logger

	// fail, denetim yazılamadığında oturumu bitiren geri çağrı.
	fail func(error)

	mu  sync.Mutex
	buf []store.SessionFile
	// total, yazılmış olay sayısı; dropped, yazılamadığı için ATILMIŞ
	// satır sayısı. İkincisi ayrı duruyor çünkü toplama katılsaydı
	// "kaç olay kaydedildi" cümlesi, kaydedilmemiş satırları da
	// kaydedilmiş gösterirdi.
	total   int
	dropped int
	stopped bool

	stop chan struct{}
	done chan struct{}
}

func newSFTPJournal(st *store.Store, sessionID string, log *slog.Logger, fail func(error)) *sftpJournal {
	j := &sftpJournal{
		store: st, sessionID: sessionID, log: log, fail: fail,
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	go j.loop()
	return j
}

// Emit, veri yolundan çağrılıyor: yalnızca tampona yazıyor.
func (j *sftpJournal) Emit(e sftpaudit.Event) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.buf) >= journalCap {
		// Tampon dolduysa yazım geride kalmış demektir. Olayı atmak
		// yerine oturumu bitiriyoruz (bkz. journalCap).
		if j.fail != nil {
			j.fail(fmt.Errorf("sftp journal backlog exceeded %d events", journalCap))
		}
		return
	}
	j.buf = append(j.buf, store.SessionFile{
		At: e.At, Op: string(e.Op), Path: e.Path, NewPath: e.NewPath,
		Flags: e.Flags, Read: e.Read, Wrote: e.Wrote, OK: e.OK, Detail: e.Detail,
	})
}

func (j *sftpJournal) loop() {
	defer close(j.done)
	t := time.NewTicker(flushEvery)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			j.flush()
		case <-j.stop:
			return
		}
	}
}

func (j *sftpJournal) take() []store.SessionFile {
	j.mu.Lock()
	defer j.mu.Unlock()
	b := j.buf
	j.buf = nil
	return b
}

/*
 * flush, biriken olayları yazar.
 *
 * ⚠️ YAZILAMAYAN GRUP GERİ KONUYOR — VE KONMUYORDU. take() tamponu
 * boşaltıyor; AddSessionFiles sonra çökerse elde tutulan grup öylece
 * kayboluyordu. Oturum ölüyor (doğrusu bu: denetlenemeyen kanal
 * geçmez) ama SessionFiles daha sonra yazılabilmiş olanları EKSİKSİZ
 * bir liste gibi döndürüyordu — yarım bir denetim kaydı, tam bir
 * denetim kaydı gibi okunuyordu.
 *
 * Geri koymak anlık arızayı kurtarıyor: bir sonraki tik ya da
 * Close'daki son flush aynı grubu yeniden deniyor. Veritabanı kalıcı
 * olarak erişilemezse olaylar yine kayboluyor ve bunu bu katmanda
 * çözmenin yolu yok — ama o hâlde oturum da zaten bitiyor ve sebebi
 * log'da duruyor.
 *
 * ⚠️ GERİ KONAN ŞEY YALNIZCA GEÇİCİ ARIZADA YAZILAMAYANLAR. Bir satır
 * DEĞERİ yüzünden reddedilmişse geri konmuyor: yeniden denemek onu
 * tamponun başında sonsuza kadar tutmak, yani bütün defteri tıkamak
 * olurdu (bkz. writeBatch).
 *
 * ⚠️ GRUP BAŞA KONUYOR. Sona eklemek olayları zaman sırasından
 * çıkarırdı; denetim satırlarının sırası, "önce açtı sonra okudu"
 * cümlesinin kendisi.
 */
// putBack, yazılamayan grubu tamponun BAŞINA geri koyar.
//
// ⚠️ Tavan yine geçerli: geri konan grup tamponu journalCap'in üstüne
// çıkarabilir ve o hâlde Emit oturumu bitiriyor — yani kayıp yerine
// oturumun bitmesi. Bu, dosyanın en başındaki kararın aynısı.
func (j *sftpJournal) putBack(batch []store.SessionFile) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.buf = append(batch, j.buf...)
}

func (j *sftpJournal) flush() {
	batch := j.take()
	if len(batch) == 0 {
		return
	}
	// ⚠️ Oturum context'i KULLANILMIYOR. Bu yazım oturum bittikten
	// sonra da tamamlanmalı; iptal edilmiş bir context'e bağlansaydı
	// oturumun son olayları — yani kapanış anındaki yarım transferler —
	// tam da yazılmaları gereken anda iptal edilirdi.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	left, err := j.writeBatch(ctx, batch)
	if err != nil {
		j.log.Error("sftp audit rows could not be written", "error", err,
			"events", len(left))
		j.putBack(left)
		if j.fail != nil {
			j.fail(err)
		}
	}
}

/*
 * writeBatch, grubu yazar ve YAZILAMAYAN SATIRI AYIKLAR.
 *
 * ⚠️ ZEHİRLİ SATIR BÜTÜN DEFTERİ TIKIYORDU. Grup tek transaction: içinde
 * asla yazılamayacak tek bir satır varsa (2704 baytı aşan bir yol,
 * geçersiz UTF-8 içeren bir dosya adı) grubun TAMAMI reddediliyor,
 * putBack onu tamponun başına geri koyuyor ve bir sonraki boşaltma aynı
 * satıra çarpıyordu. Oturumun bütün dosya olayları o satırın arkasında
 * birikip kayboluyordu — üstelik kaybın büyüklüğü hiçbir yerde
 * görünmüyordu.
 *
 * Bölerek ayıklıyoruz: reddedilen grup ikiye ayrılıp yeniden deneniyor,
 * yazılamayan satır tek başına kalınca atılıp SAYILIYOR. Maliyet
 * yalnızca arıza yolunda ve satır başına log(n) turdan fazla değil.
 *
 * Patolojik hâlin (her satır yazılamaz) tavanı flush'ın 10 saniyelik
 * context'i: süre dolunca hatalar artık ErrInvalid olmuyor, kalan grup
 * geçici arıza sayılıp tampona geri konuyor. Yani bölme kendi kendine
 * duruyor, bir yazma fırtınasına dönüşmüyor.
 *
 * ⚠️ AYRIM ŞART, YOKSA BU BÖLME BİR VERİ KAYBI MAKİNESİ OLURDU.
 * Veritabanı düştüğünde de her yazma başarısız olur; bölme onu tek tek
 * satırlara indirir ve HEPSİNİ "yazılamaz" diye atardı. Bu yüzden
 * yalnızca store'un "bu değer kabul edilmiyor" dediği hata bölünüyor
 * (ErrInvalid, bkz. store.AddSessionFiles); geçici arıza olduğu gibi
 * çağırana dönüyor ve grup tampona geri konuyor.
 *
 * Dönen dilim, YAZILAMAMIŞ ama yazılabilir satırlar: çağıran onları geri
 * koymalı. Hata nil ise geriye bir şey kalmamıştır.
 */
func (j *sftpJournal) writeBatch(ctx context.Context, batch []store.SessionFile) ([]store.SessionFile, error) {
	err := j.store.AddSessionFiles(ctx, j.sessionID, batch)
	switch {
	case err == nil:
		j.mu.Lock()
		j.total += len(batch)
		j.mu.Unlock()
		return nil, nil

	case !errors.Is(err, store.ErrInvalid):
		// Geçici: grup olduğu gibi geri.
		return batch, err

	case len(batch) == 1:
		j.dropRow(ctx, batch[0], err)
		return nil, nil
	}

	mid := len(batch) / 2
	left, lerr := j.writeBatch(ctx, batch[:mid])
	if lerr != nil {
		/*
		 * İlk yarıda geçici bir arıza: ikinci yarı HİÇ DENENMEDİ, o da
		 * geri konmalı. Yeni bir dilim kuruluyor — append ile batch'in
		 * kendi dizisine yazmak, geri koyacağımız satırların üstünü
		 * çizerdi.
		 */
		rest := make([]store.SessionFile, 0, len(left)+len(batch)-mid)
		rest = append(rest, left...)
		rest = append(rest, batch[mid:]...)
		return rest, lerr
	}
	return j.writeBatch(ctx, batch[mid:])
}

/*
 * dropRow, yazılamayan satırı atar — SESSİZCE DEĞİL.
 *
 * ⚠️ ATILAN SATIRIN İZİ DEFTERE DÜŞÜYOR. Kayıp yalnızca log'da kalsaydı,
 * yalnızca veritabanına bakan bir denetçi eksik listeyi tam liste sanardı
 * — bu deponun her yerinde reddedilen şey tam olarak bu. Yerine konan
 * satır olayın ZAMANINI ve İŞLEMİNİ koruyor, yolu ise kayda giren metnin
 * temizliğinden geçiriyor (castSafe): yazılamayan şey çoğu zaman yolun
 * kendisi olduğu için, işareti onunla birlikte yazmaya çalışmak işareti
 * de kaybetmek olurdu.
 *
 * ⚠️ OTURUM YİNE ÖLÜYOR. Atılan satır bir denetim kaybıdır ve bu deponun
 * kuralı değişmedi: denetlenemeyen kanal geçmez. Değişen tek şey, geri
 * kalan satırların artık o kaybın arkasında birikmemesi.
 */
func (j *sftpJournal) dropRow(ctx context.Context, f store.SessionFile, cause error) {
	j.mu.Lock()
	j.dropped++
	j.mu.Unlock()

	j.log.Error("sftp audit row dropped; the database refuses this value",
		"op", f.Op, "path", castSafe(f.Path), "error", cause)

	marker := store.SessionFile{
		At: f.At, Op: castSafe("dropped." + f.Op), OK: false,
		Path:   castSafe(f.Path),
		Detail: castSafe("postern: this audit row could not be stored: " + cause.Error()),
	}
	if err := j.store.AddSessionFiles(ctx, j.sessionID, []store.SessionFile{marker}); err != nil {
		// İşaret de yazılamadı: elde log'dan başka bir şey kalmıyor.
		j.log.Error("the dropped audit row could not be marked either",
			"op", f.Op, "error", err)
	}

	if j.fail != nil {
		j.fail(cause)
	}
}

// Close, kalanları yazar; yazılmış ve ATILMIŞ olay sayısını döner.
//
// ⚠️ İKİ SAYI AYRI DÖNÜYOR. Tek bir toplam, atılan satırları da
// kaydedilmiş gösterirdi; oysa çağıranın operatöre söyleyeceği cümle
// tam olarak "şu kadarı kaydedilemedi".
//
// Broker'ın finishSFTP'si Run içinde çalıştığı için, buraya gelindiğinde
// yarım kalan transfer özetleri tampona çoktan girmiş oluyor.
func (j *sftpJournal) Close() (written, dropped int) {
	j.mu.Lock()
	if j.stopped {
		j.mu.Unlock()
		return j.total, j.dropped
	}
	j.stopped = true
	j.mu.Unlock()

	close(j.stop)
	<-j.done
	j.flush()

	j.mu.Lock()
	defer j.mu.Unlock()

	return j.total, j.dropped
}
