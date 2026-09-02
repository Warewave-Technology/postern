package proxy

import (
	"context"
	"errors"
	"testing"

	"github.com/warewave/postern/internal/store"
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
