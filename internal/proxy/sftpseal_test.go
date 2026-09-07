package proxy

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/record"
)

/*
 * ⚠️ BU DOSYANIN İLK TESTİ BİR GERİLEME KORUMASI.
 *
 * SFTP olaylarını oturum kaydına yazmak, kayda dokunan bir değişiklik ve
 * kayıt bu ürünün en büyük iddiası. SFTP'si OLMAYAN bir kabuk oturumunun
 * kaydı bundan ETKİLENMEMELİ — ne fazladan satır, ne değişmiş sıra.
 * Ölçmenin tek dürüst yolu iki kaydı yan yana koymak.
 */
func TestShellRecordingIsUnchangedBySFTPSealing(t *testing.T) {
	run := func(allowSFTP bool) string {
		t.Helper()

		down, feedDown, _ := newFakeChannel()
		up, feedUp, _ := newFakeChannel()
		downR := make(chan *ssh.Request)
		upR := make(chan *ssh.Request)

		sink := &memCloser{}
		rec, err := record.NewWriter(sink, 80, 24, nil)
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		b := New(down, downR, up, upR, rec, true,
			RequestPolicy{AllowSFTP: allowSFTP}, testLogger()).
			WithSFTP(&memSink{})
		done := make(chan error, 1)
		go func() { done <- b.Run(ctx) }()

		downR <- &ssh.Request{Type: "shell"}

		/*
		 * ⚠️ HER OLAYIN KAYDA DÜŞMESİ BEKLENİYOR, sonra sonraki
		 * yazılıyor — ve bu testin doğru olabilmesinin şartı.
		 *
		 * İki yön iki ayrı goroutine: hedef→istemci ve istemci→hedef.
		 * İkisini aynı anda beslersek kayıttaki SIRALARI koşudan
		 * koşuya değişiyor, ve karşılaştırma bunu "SFTP mühürlemesi
		 * kabuk kaydını değiştirdi" diye okuyor. Ölçmek istediğim şey
		 * sıra değil, mühürlemenin kayda bir şey EKLEYİP EKLEMEDİĞİ.
		 */
		mustWrite(t, feedUp, "merhaba\r\n")
		waitForRecorded(t, sink, `"o","merhaba`)

		mustWrite(t, feedDown, "ls\r")
		/*
		 * ⚠️ GİRDİNİN KAYDA DÜŞMESİNİ BEKLE — hedefe ulaşmasını değil.
		 *
		 * İki ayrı an ve arada iptal edilebilecek bir boşluk var:
		 * aktarım döngüsü önce hedefe yazıyor, sonra kaydediyor.
		 * İlk hâli hedefi bekliyordu ve üç koşudan biri düşüyordu;
		 * ondan önceki hâli hiç beklemiyordu. Testin kendi yarışı,
		 * ölçtüğü şey hakkında kendinden emin bir yanlış cevap
		 * veriyordu: "SFTP mühürlemesi kabuk kaydını değiştirdi."
		 */
		waitForRecorded(t, sink, `"i","ls`)

		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("Run dönmedi")
		}
		if err := rec.Close(); err != nil {
			t.Fatal(err)
		}

		return sink.String()
	}

	on, off := run(true), run(false)

	// Zaman damgaları ve süreler iki koşuda farklı; karşılaştırma
	// bunları çıkararak yapılıyor. Ölçülen şey İÇERİK ve SIRA.
	strip := func(s string) string {
		s = regexp.MustCompile(`"timestamp":\d+`).ReplaceAllString(s, `"timestamp":0`)
		return regexp.MustCompile(`\[[0-9.]+,`).ReplaceAllString(s, "[0,")
	}

	if strip(on) != strip(off) {
		t.Errorf("SFTP açıkken kabuk oturumunun kaydı DEĞİŞTİ.\nAÇIK:\n%s\nKAPALI:\n%s", on, off)
	}
	if strings.Contains(on, "postern sftp:") {
		t.Error("SFTP olmayan oturumun kaydına sftp satırı düştü")
	}
}

/*
 * Mühür satırı YALNIZCA olay varsa yazılıyor. Boş bir özet satırı,
 * olmayan bir oturumu varmış gibi gösterirdi — ve bir denetim kaydında
 * "hiçbir şey olmadı" ile "burada bir şey vardı ama sayısı sıfır" ayrı
 * cümleler.
 */
func TestSealLineOnlyWhenThereAreEvents(t *testing.T) {
	down, feedDown, _ := newFakeChannel()
	up, feedUp, _ := newFakeChannel()
	downR := make(chan *ssh.Request)
	upR := make(chan *ssh.Request)

	sink := &memCloser{}
	rec, err := record.NewWriter(sink, 80, 24, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b := New(down, downR, up, upR, rec, true,
		RequestPolicy{AllowSFTP: true}, testLogger()).WithSFTP(&memSink{})
	done := make(chan error, 1)
	go func() { done <- b.Run(ctx) }()

	// Alt sistem açılıyor ama TEK BİR istek bile gönderilmiyor.
	downR <- &ssh.Request{Type: "subsystem", Payload: sshString("sftp")}
	waitForSFTP(t, b)
	_ = feedDown
	_ = feedUp

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run dönmedi")
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	if strings.Contains(sink.String(), "digest sha256:") {
		t.Errorf("olay yokken mühür satırı yazıldı:\n%s", sink.String())
	}
}

/*
 * ⚠️ MÜHÜR SATIRI KAYDIN İÇİNDE OLMAK ZORUNDA.
 *
 * Kaydı lifecycle kapatıyor ve bunu Run döndükten SONRA yapıyor. Mühür
 * Run'dan sonra yazılsaydı dosyanın dışında kalır ve hiçbir şeyi
 * mühürlemezdi — üstelik bu, testlerden geçen türden bir hata: satır
 * bir yerlere yazılıyor, sadece doğru yere değil.
 */
func TestSealLineIsInsideTheRecording(t *testing.T) {
	down, feedDown, _ := newFakeChannel()
	up, feedUp, _ := newFakeChannel()
	downR := make(chan *ssh.Request)
	upR := make(chan *ssh.Request)

	sink := &memCloser{}
	rec, err := record.NewWriter(sink, 80, 24, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b := New(down, downR, up, upR, rec, true,
		RequestPolicy{AllowSFTP: true}, testLogger()).WithSFTP(&memSink{})
	done := make(chan error, 1)
	go func() { done <- b.Run(ctx) }()

	downR <- &ssh.Request{Type: "subsystem", Payload: sshString("sftp")}
	waitForSFTP(t, b)

	// Bir dizin açılıp kapanıyor: tek bir denetim olayı.
	sendClient(t, feedDown, up, sftpPkt(11, uint32(1), "/tmp"))
	mustWrite(t, feedUp, string(sftpPkt(102, uint32(1), "d1")))
	sendClient(t, feedDown, up, sftpPkt(4, uint32(2), "d1"))
	mustWrite(t, feedUp, string(sftpPkt(101, uint32(2), uint32(0), "", "")))

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run dönmedi")
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	cast := sink.String()
	if !strings.Contains(cast, "postern sftp: opendir /tmp") {
		t.Errorf("olay satırı kayda düşmemiş:\n%s", cast)
	}
	if !strings.Contains(cast, "digest sha256:") {
		t.Fatalf("mühür satırı kayda düşmemiş:\n%s", cast)
	}

	// Zincir mührü KAPSIYOR: mühür, kaydın son satırından önce gelmeli
	// (yani dosyanın içinde), sonrasında değil.
	if !strings.Contains(cast, "1 events") {
		t.Errorf("mühür olay sayısını yanlış yazıyor:\n%s", cast)
	}
}

/*
 * waitForRecorded, kaydın belirli bir metni İÇERMESİNİ bekler.
 *
 * Kaydın kendisini beklemek şart: bir baytın hedefe ulaşmış olması,
 * kaydedilmiş olması demek değil.
 */
func waitForRecorded(t *testing.T, sink *memCloser, want string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(sink.String(), want) {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("kayda düşmedi: %q\n%s", want, sink.String())
}
