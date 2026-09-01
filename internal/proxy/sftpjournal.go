package proxy

// SFTP dosya olaylarının kalıcılaştırılması (store.session_files).

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/warewave/postern/internal/sftpaudit"
	"github.com/warewave/postern/internal/store"
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

// sftpJournal, olayları biriktirip toplu yazan SFTPSink.
type sftpJournal struct {
	store     *store.Store
	sessionID string
	log       *slog.Logger

	// fail, denetim yazılamadığında oturumu bitiren geri çağrı.
	fail func(error)

	mu      sync.Mutex
	buf     []store.SessionFile
	total   int
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
		if j.fail != nil {
			j.fail(err)
		}
		return
	}
	j.mu.Lock()
	j.total += len(batch)
	j.mu.Unlock()
}

// Close, kalanları yazar ve toplam olay sayısını döner.
//
// Broker'ın finishSFTP'si Run içinde çalıştığı için, buraya gelindiğinde
// yarım kalan transfer özetleri tampona çoktan girmiş oluyor.
func (j *sftpJournal) Close() int {
	j.mu.Lock()
	if j.stopped {
		j.mu.Unlock()
		return j.total
	}
	j.stopped = true
	j.mu.Unlock()

	close(j.stop)
	<-j.done
	j.flush()

	j.mu.Lock()
	defer j.mu.Unlock()
	return j.total
}
