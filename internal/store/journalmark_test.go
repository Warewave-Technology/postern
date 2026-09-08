package store

// Defterin durumunun oturum satırına yazılması (göç 037).

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/model"
)

/*
 * ⚠️ SATIRIN "KAYITTA KARŞILIĞI VAR" DAMGASI GERİ OKUNABİLMELİ.
 *
 * Defteri kaydın mührüyle karşılaştıran kontrol (verify.JournalOf) bu
 * damgaya göre süzüyor: bu tabloya kanal düzeyindeki ret defteri de
 * yazıyor (proxy/lifecycle.go) ve o satırların kayıtta karşılığı yok.
 * Damga yazılıp okunmazsa, hiç kurcalanmamış bir oturumun hem sayısı
 * hem özeti tutmaz — yani kontrolün kendisi yanlış alarm üretir.
 */
func TestInRecordingSurvivesTheRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	startFileSession(t, s, "sess-journal-1")

	now := time.Now().Truncate(time.Second)
	if err := s.AddSessionFiles(ctx, "sess-journal-1", []SessionFile{
		{At: now, Op: "open", Path: "/etc/shadow", OK: true, InRecording: true},
		{At: now, Op: "transfer", Path: "/etc/shadow", Read: 12, OK: true, InRecording: true},
		// Kanal düzeyindeki ret: deftere giriyor, kayda girmiyor.
		{At: now, Op: "denied.x11-req", OK: false, Detail: "x11 forwarding is off"},
	}); err != nil {
		t.Fatalf("AddSessionFiles: %v", err)
	}

	rows, err := s.SessionFiles(ctx, "sess-journal-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("satır sayısı = %d", len(rows))
	}

	var flagged int
	for _, r := range rows {
		if r.InRecording {
			flagged++
		}
		if strings.HasPrefix(r.Op, "denied.x11") && r.InRecording {
			t.Error("KANAL RETİ KAYITTA GİBİ İŞARETLENDİ: mühürle karşılaştırma yanlış alarm verir")
		}
	}
	if flagged != 2 {
		t.Errorf("damgalı satır = %d, 2 bekleniyordu", flagged)
	}
}

/*
 * ⚠️ ÖLÇÜLMEMİŞ OTURUM "SIFIR OLAY" DEĞİL.
 *
 * Kaydı olmayan bir oturumda mühür satırı hiç yazılmıyor. Oraya 0
 * yazmak, defteri dolu bir oturumu "mühür sıfır diyor ama defterde N
 * satır var" diye suçlardı — göç 034'ün boş zincir başı için verdiği
 * kararın aynısı.
 */
func TestMarkSFTPJournalKeepsUnmeasuredApartFromZero(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	startFileSession(t, s, "sess-journal-2")

	// Yükseltmeden hemen sonra: hiç işaretlenmemiş oturum.
	fresh, err := s.Session(ctx, "sess-journal-2")
	if err != nil {
		t.Fatal(err)
	}
	if fresh.SFTPJournal.Measured {
		t.Error("hiç işaretlenmemiş oturum ölçülmüş görünüyor")
	}

	if err := s.MarkSFTPJournal(ctx, "sess-journal-2",
		model.SFTPJournal{Measured: false, Events: 0, Lost: 4}); err != nil {
		t.Fatalf("MarkSFTPJournal: %v", err)
	}

	got, err := s.Session(ctx, "sess-journal-2")
	if err != nil {
		t.Fatal(err)
	}
	if got.SFTPJournal.Measured {
		t.Error("KAYITSIZ OTURUM ÖLÇÜLMÜŞ SAYILDI: mühür yokken sayı yazılmış")
	}
	// Kayıp yine de kaydediliyor: mühür olmasa da postern'in kendi
	// kaybı bir bulgu.
	if got.SFTPJournal.Lost != 4 {
		t.Errorf("Lost = %d, 4 bekleniyordu", got.SFTPJournal.Lost)
	}
}

// Ölçülmüş bir oturum sayıyı olduğu gibi geri vermeli.
func TestMarkSFTPJournalRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	startFileSession(t, s, "sess-journal-3")

	if err := s.MarkSFTPJournal(ctx, "sess-journal-3",
		model.SFTPJournal{Measured: true, Events: 12, Lost: 3}); err != nil {
		t.Fatalf("MarkSFTPJournal: %v", err)
	}

	got, err := s.Session(ctx, "sess-journal-3")
	if err != nil {
		t.Fatal(err)
	}
	if !got.SFTPJournal.Measured || got.SFTPJournal.Events != 12 || got.SFTPJournal.Lost != 3 {
		t.Errorf("okunan işaret = %+v", got.SFTPJournal)
	}
}
