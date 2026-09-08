package proxy

// SFTP dosya olaylarının kalıcılaştırılması (store.session_files).

import (
	"context"
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
 *
 * ⚠️ AMA OTURUMU BİTİRMEK, OLAYI KURTARMIYOR — VE ELDEKİ SESSİZLİK TAM
 * OLARAK BURADAYDI. fail() sync.Once ile korunuyor (sftp.go,
 * abortAudit): ilk taşmadan sonraki her taşma hiçbir yere yazılmadan
 * geri dönüyordu. Kapanış ile teardown arasında akmaya devam eden bir
 * transfer, defterde HİÇ görünmeyen ama kayıtta duran onlarca olay
 * bırakabiliyordu. Artık her düşürme sayılıyor, sayı oturumun satırına
 * yazılıyor (store.MarkSFTPJournal) ve `session verify` ile panelin
 * oturum ayrıntısı onu söylüyor.
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

	/*
	 * recorded, bu oturumun bir KAYDI olduğu.
	 *
	 * ⚠️ SATIRA İŞLENİYOR (SessionFile.InRecording) ÇÜNKÜ KONTROLÜN
	 * DAYANAĞI O. Kayıt kapalıyken mühür satırı hiç yazılmıyor
	 * (sftpcast.go, b.rec == nil); satırları yine de "kayıtta var" diye
	 * işaretlemek, mühürsüz bir oturumu "mühür sıfır diyor ama defterde
	 * N satır var" diye suçlardı.
	 */
	recorded bool

	mu      sync.Mutex
	buf     []store.SessionFile
	total   int64
	stopped bool

	/*
	 * dropped, tavan yüzünden deftere HİÇ giremeyen olay sayısı.
	 *
	 * ⚠️ SAYMAK, TEK BAŞINA BİR ÖZELLİK. Düşen olay kayda ÇOKTAN
	 * yazılmış oluyor (emitSFTP: önce kayıt, sonra defter), yani her
	 * düşürme kaydın mühründe sayılıp defterde görünmeyen bir olay
	 * bırakıyor. Sayı olmadan o fark "birileri satır sildi" ile aynı
	 * görünür.
	 */
	dropped int64

	// warned, ilk düşürmenin log'a yazıldığı.
	//
	// ⚠️ HER DÜŞÜRME LOGLANMIYOR. Tavan taşmışsa istemci saniyede
	// binlerce olay üretiyor demektir; her biri için satır yazmak,
	// asıl sinyali kendi gürültümüzle gömmek olurdu. Toplam sayı
	// kapanışta bir kez yazılıyor ve oturumun satırına işleniyor.
	warned bool
	// lateWarned, kapanış SONRASI kaybın bir kez yazıldığı.
	lateWarned bool

	stop chan struct{}
	done chan struct{}
}

func newSFTPJournal(st *store.Store, sessionID string, log *slog.Logger,
	recorded bool, fail func(error)) *sftpJournal {
	j := &sftpJournal{
		store: st, sessionID: sessionID, log: log, recorded: recorded, fail: fail,
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	go j.loop()
	return j
}

// Emit, veri yolundan çağrılıyor: yalnızca tampona yazıyor.
func (j *sftpJournal) Emit(e sftpaudit.Event) {
	j.mu.Lock()
	defer j.mu.Unlock()

	/*
	 * ⚠️ KAPANDIKTAN SONRA GELEN OLAY TAMPONA KONMUYOR.
	 *
	 * Konsaydı hiç kimse okumazdı: loop durmuş, son boşaltma yapılmış ve
	 * Close sayıları çoktan döndürmüş oluyor. Yani olay ne yazılır ne
	 * sayılır — tam olarak bu PR'ın kapattığını söylediği sessiz kayıp,
	 * kapanış penceresinde geri gelirdi.
	 *
	 * ⚠️ SAYI OTURUMUN SATIRINA ULAŞMIYOR ve bu söylenmeli: satır
	 * Close'un döndürdüğü sayılarla yazılıyor, o da bu noktada geçmişte
	 * kaldı. Buradan kazanılan şey kaybın SESSİZ olmaması; sayının
	 * satıra girmesi, olayın hiç geç gelmemesini gerektiriyor ve bu
	 * kanalın kapanış sırasıyla ilgili ayrı bir iş.
	 */
	if j.stopped {
		j.dropped++
		if !j.lateWarned {
			j.lateWarned = true
			j.log.Error("sftp event arrived after the journal closed; it is lost",
				"session", j.sessionID, "op", string(e.Op))
		}

		return
	}

	if len(j.buf) >= journalCap {
		// Tampon dolduysa yazım geride kalmış demektir. Oturumu
		// bitiriyoruz (bkz. journalCap) — ama olay yine de deftere
		// giremiyor, o yüzden düşürme sayılıyor ve kapanışta oturumun
		// satırına yazılıyor.
		j.drop()
		return
	}
	j.buf = append(j.buf, store.SessionFile{
		At: e.At, Op: string(e.Op), Path: e.Path, NewPath: e.NewPath,
		Flags: e.Flags, Read: e.Read, Wrote: e.Wrote, OK: e.OK, Detail: e.Detail,
		InRecording: j.recorded,
	})
}

/*
 * drop, tavana çarpan bir olayı sayar ve oturumu bitirir.
 *
 * ⚠️ ÇAĞIRAN mu'YU TUTUYOR (Emit). Sayaç aynı kilidin altında artıyor
 * ki kapanışta okunan sayı, yazan goroutine'lerin gördüğüyle aynı
 * olsun.
 *
 * ⚠️ fail HER DÜŞÜRMEDE ÇAĞRILIYOR, İLKİNDE DEĞİL — ve bu bilinçli:
 * sync.Once'ı çağıran taraf tutuyor (abortAudit). Kapıyı buraya da
 * koymak, "oturum zaten bitiyor" varsayımını iki yerde tutmak olurdu
 * ve o varsayım değişirse ikincisi sessizce yanlış kalırdı.
 */
func (j *sftpJournal) drop() {
	j.dropped++

	if !j.warned {
		j.warned = true
		/*
		 * ⚠️ SATIR "SESSİZ KAYIP" DEMEK ZORUNDA. Bunun log'da yalnızca
		 * abortAudit'in "sftp audit failed" satırı vardı ve o satır
		 * denetimin ÇÖKTÜĞÜNÜ söylüyor, olayların KAYBOLDUĞUNU değil.
		 * Okuyan kişi oturumun kesildiğini görüp defterin tam olduğunu
		 * varsayıyordu.
		 */
		j.log.Error("sftp journal is full; events are being lost",
			"cap", journalCap, "session", j.sessionID)
	}

	if j.fail != nil {
		j.fail(fmt.Errorf("sftp journal backlog exceeded %d events", journalCap))
	}
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

	if err := j.store.AddSessionFiles(ctx, j.sessionID, batch); err != nil {
		j.log.Error("sftp audit rows could not be written", "error", err,
			"events", len(batch))
		j.putBack(batch)
		if j.fail != nil {
			j.fail(err)
		}
		return
	}
	j.mu.Lock()
	j.total += int64(len(batch))
	j.mu.Unlock()
}

/*
 * Close, kalanları yazar; deftere GİREN ve GİREMEYEN olay sayısını döner.
 *
 * Broker'ın finishSFTP'si Run içinde çalıştığı için, buraya gelindiğinde
 * yarım kalan transfer özetleri tampona çoktan girmiş oluyor.
 *
 * ⚠️ lost İKİ AYRI KAYBI TOPLUYOR ve ikisi de aynı sonucu veriyor:
 * kayıtta duran, defterde durmayan bir olay. Tavana çarpıp atılanlar
 * (dropped) ve son flush'tan sonra elde kalanlar. İkincisi gerçek:
 * flush yazamadığında grubu tampona geri koyuyor (putBack) ve kapanışta
 * yeniden denenecek bir tik kalmıyor.
 *
 * ⚠️ SAYIYI DÖNDÜRMEK ŞART, LOG'LAMAK YETMEZ. Çağıran bunu oturumun
 * satırına yazıyor (store.MarkSFTPJournal); yalnızca log'a yazılan bir
 * kayıp, aylar sonra kaydı doğrulayan denetçinin eline geçmiyor —
 * elindeki tek şey defter ile kayıt arasındaki açıklanamamış fark
 * oluyor.
 */
func (j *sftpJournal) Close() (written, lost int64) {
	j.mu.Lock()
	if j.stopped {
		defer j.mu.Unlock()
		return j.total, j.dropped + int64(len(j.buf))
	}
	j.stopped = true
	j.mu.Unlock()

	close(j.stop)
	<-j.done
	j.flush()

	j.mu.Lock()
	defer j.mu.Unlock()

	return j.total, j.dropped + int64(len(j.buf))
}
