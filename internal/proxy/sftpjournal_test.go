package proxy

import (
	"context"
	"errors"
	"testing"

	"github.com/Warewave-Technology/postern/internal/sftpaudit"
	"github.com/Warewave-Technology/postern/internal/store"
)

/*
 * ⚠️ YAZILAMAYAN DENETİM GRUBU KAYBOLMAMALI.
 *
 * take() tamponu boşaltıyor; yazma sonra çökerse elde tutulan grup
 * öylece kayboluyordu. Oturum ölüyor (doğrusu bu: denetlenemeyen kanal
 * geçmez) ama SessionFiles daha sonra yazılabilmiş olanları EKSİKSİZ
 * bir liste gibi döndürüyordu — yarım bir denetim kaydı, tam bir
 * denetim kaydı gibi.
 *
 * ⚠️ SIRA DA KORUNUYOR. Sona eklemek olayları zaman sırasından
 * çıkarırdı ve denetim satırlarının sırası, "önce açtı sonra okudu"
 * cümlesinin kendisi.
 */
func TestJournalPutsBackABatchItCouldNotWrite(t *testing.T) {
	j := &sftpJournal{}

	j.buf = []store.SessionFile{{Op: "transfer", Path: "/sonra"}}
	j.putBack([]store.SessionFile{
		{Op: "open", Path: "/once-1"},
		{Op: "open", Path: "/once-2"},
	})

	if len(j.buf) != 3 {
		t.Fatalf("tampon = %d olay, 3 bekleniyordu", len(j.buf))
	}
	want := []string{"/once-1", "/once-2", "/sonra"}
	for i, w := range want {
		if j.buf[i].Path != w {
			t.Errorf("sıra bozuldu: buf[%d] = %q, %q bekleniyordu", i, j.buf[i].Path, w)
		}
	}
}

// failingFiles, her yazmayı reddeden bir fileWriter.
type failingFiles struct {
	calls int
	err   error
}

func (f *failingFiles) AddSessionFiles(context.Context, string, []store.SessionFile) error {
	f.calls++
	return f.err
}

/*
 * ⚠️ flush GERÇEKTEN GERİ KOYUYOR MU.
 *
 * putBack'in kendi testi vardı ve geçiyordu; flush'ın onu ÇAĞIRDIĞINI
 * ölçen hiçbir şey yoktu — çağrıyı silen bir mutasyon testi
 * düşürmüyordu. Bu deponun tekrar eden arızası tam olarak bu:
 * yazılmış, test edilmiş ve kablosu ölçülmemiş.
 *
 * store alanı bu yüzden arayüz: somut tiple bu testi yazmak gerçek bir
 * veritabanı gerektirirdi ve pratikte hiç yazılmazdı.
 */
func TestFlushKeepsTheBatchWhenTheWriteFails(t *testing.T) {
	w := &failingFiles{err: errors.New("database is down")}
	failed := make(chan error, 1)
	j := &sftpJournal{
		store: w,
		log:   testLogger(),
		fail:  func(e error) { failed <- e },
	}

	j.buf = []store.SessionFile{
		{Op: "open", Path: "/etc/shadow"},
		{Op: "transfer", Path: "/etc/shadow"},
	}
	j.flush()

	if w.calls != 1 {
		t.Fatalf("yazma denenmedi: %d çağrı", w.calls)
	}

	// ⚠️ OTURUM YİNE ÖLÜYOR: denetlenemeyen kanal geçmez. Geri koymak
	// bu kararı değiştirmiyor, yalnızca satırların kaybolmamasını
	// sağlıyor.
	select {
	case <-failed:
	default:
		t.Error("yazma çöktü ama oturum bitirilmedi")
	}

	j.mu.Lock()
	kept := len(j.buf)
	j.mu.Unlock()
	if kept != 2 {
		t.Fatalf("DENETİM SATIRLARI KAYBOLDU: tamponda %d olay kaldı, 2 bekleniyordu", kept)
	}
}

// Başarılı yazmada tampon boşalmalı: geri koyma her turda tekrar
// yazılan bir kuyruk üretmemeli.
func TestFlushClearsTheBufferOnSuccess(t *testing.T) {
	w := &okFiles{}
	j := &sftpJournal{store: w, log: testLogger()}
	j.buf = []store.SessionFile{{Op: "open", Path: "/a"}}

	j.flush()

	j.mu.Lock()
	kept := len(j.buf)
	j.mu.Unlock()
	if kept != 0 {
		t.Fatalf("başarılı yazmadan sonra tamponda %d olay kaldı", kept)
	}
	if j.total != 1 {
		t.Errorf("toplam sayaç = %d, 1 bekleniyordu", j.total)
	}
}

type okFiles struct{}

func (okFiles) AddSessionFiles(context.Context, string, []store.SessionFile) error { return nil }

/*
 * ⚠️ DÜŞEN OLAY SAYILMALI — VE HİÇ SAYILMIYORDU.
 *
 * Tampon tavana çarptığında Emit olayı atıp dönüyordu. fail() oturumu
 * bitiriyor ama o çağrı sync.Once ile korunuyor (abortAudit), yani İLK
 * düşürmeden sonrakiler hiçbir yere yazılmadan kayboluyordu. Kapanış
 * ile teardown arasında akmaya devam eden bir transfer, defterde hiç
 * görünmeyen ama kayıtta duran onlarca olay bırakabiliyordu — ve
 * kaydın mühür satırı onları saydığı için, geriye açıklanamayan bir
 * fark kalıyordu.
 *
 * Bu testin ölçtüğü şey sayının kendisi: kaç olayın kaybolduğunu
 * bilmeden, "postern kaybetti" ile "birileri satır sildi" ayırt
 * edilemiyor.
 */
func TestEmitCountsEveryDroppedEvent(t *testing.T) {
	var fails int
	j := &sftpJournal{
		log:  testLogger(),
		fail: func(error) { fails++ },
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	// Tampon tavanda: bundan sonraki her olay düşüyor.
	j.buf = make([]store.SessionFile, journalCap)

	const attempts = 5
	for range attempts {
		j.Emit(sftpaudit.Event{Op: sftpaudit.OpOpen, Path: "/etc/shadow", OK: true})
	}

	j.mu.Lock()
	dropped := j.dropped
	buffered := len(j.buf)
	j.mu.Unlock()

	if dropped != attempts {
		t.Errorf("DÜŞEN OLAYLAR SAYILMADI: dropped = %d, %d bekleniyordu", dropped, attempts)
	}
	if buffered != journalCap {
		t.Errorf("tampon tavanın üstüne çıktı: %d olay", buffered)
	}

	// ⚠️ OTURUM YİNE BİTİYOR: sayma kararı, "denetlenemiyorsa geçmez"
	// kuralının yerine geçmiyor — onun üstüne biniyor.
	if fails == 0 {
		t.Error("olay düştü ama oturum bitirilmedi")
	}
}

// testJournal, kapanışı sınanabilen bir günlükçü kurar.
//
// newSFTPJournal *store.Store istiyor (gerçek bir veritabanı); buradaki
// soru depoyla değil, Close'un DÖNDÜRDÜĞÜ sayılarla ilgili.
func testJournal(w fileWriter) *sftpJournal {
	j := &sftpJournal{
		store: w, log: testLogger(),
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	go j.loop()

	return j
}

/*
 * ⚠️ KAPANIŞ, KAYBI ÇAĞIRANA SÖYLEMEK ZORUNDA.
 *
 * Close yalnızca YAZILAN satır sayısını döndürüyordu; kaybedilenler
 * hiçbir yere gitmiyordu. Çağıran (lifecycle) o sayıyı oturumun
 * satırına yazıyor — yazamadığında, aylar sonra kaydı doğrulayan
 * denetçinin elinde defter ile mühür arasındaki açıklanamayan farktan
 * başka bir şey kalmıyor.
 */
func TestCloseReportsWhatTheJournalCouldNotWrite(t *testing.T) {
	j := testJournal(&failingFiles{err: errors.New("database is down")})
	j.fail = func(error) {}

	// Tavana çarpan iki olay…
	j.mu.Lock()
	j.buf = make([]store.SessionFile, journalCap)
	j.mu.Unlock()
	j.Emit(sftpaudit.Event{Op: sftpaudit.OpOpen, Path: "/a", OK: true})
	j.Emit(sftpaudit.Event{Op: sftpaudit.OpOpen, Path: "/b", OK: true})

	written, lost := j.Close()

	if written != 0 {
		t.Errorf("yazma çöktüğü hâlde %d satır yazıldı sayıldı", written)
	}
	/*
	 * ⚠️ İKİ AYRI KAYIP AYNI TOPLAMDA. Tavana çarpanlar (2) ve son
	 * flush'tan sonra elde kalanlar (journalCap). İkisi de aynı sonucu
	 * veriyor: kayıtta duran, defterde durmayan bir olay. Yalnızca
	 * birini saymak, kaydın mühründeki sayıyla defteri karşılaştıran
	 * kontrolü yanlış tarafa çevirirdi — postern'in kendi kaybını
	 * "satır silinmiş" diye raporlardı.
	 */
	if want := int64(journalCap + 2); lost != want {
		t.Errorf("KAYIP EKSİK SAYILDI: lost = %d, %d bekleniyordu", lost, want)
	}
}

/*
 * ⚠️ SATIR, KAYITTA KARŞILIĞI OLUP OLMADIĞINI TAŞIMALI.
 *
 * Defterle mührü karşılaştıran kontrolün dayanağı bu damga: kayıt
 * kapalıyken mühür satırı hiç yazılmıyor (sftpcast.go, b.rec == nil).
 * Damgayı koşulsuz basmak, mührü olmayan bir oturumu "mühür sıfır
 * diyor ama defterde N satır var" diye suçlardı.
 */
func TestRowsSayWhetherTheyAreInTheRecording(t *testing.T) {
	for _, tc := range []struct {
		name     string
		recorded bool
	}{
		{"kayıt açık", true},
		{"kayıt kapalı", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := &sftpJournal{log: testLogger(), recorded: tc.recorded}
			j.Emit(sftpaudit.Event{Op: sftpaudit.OpOpen, Path: "/a", OK: true})

			if len(j.buf) != 1 {
				t.Fatalf("tamponda %d olay var, 1 bekleniyordu", len(j.buf))
			}
			if j.buf[0].InRecording != tc.recorded {
				t.Errorf("InRecording = %v, %v bekleniyordu",
					j.buf[0].InRecording, tc.recorded)
			}
		})
	}
}
