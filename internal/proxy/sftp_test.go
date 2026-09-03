package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/record"
	"github.com/warewave/postern/internal/sftpaudit"
)

// --- yardımcılar ------------------------------------------------------

type memSink struct {
	mu     sync.Mutex
	events []sftpaudit.Event
}

func (m *memSink) Emit(e sftpaudit.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
}

func (m *memSink) all() []sftpaudit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]sftpaudit.Event(nil), m.events...)
}

// sftpPkt, uzunluk önekli bir SFTP paketi kurar.
func sftpPkt(typ byte, fields ...any) []byte {
	body := []byte{typ}
	for _, f := range fields {
		switch v := f.(type) {
		case uint32:
			body = binary.BigEndian.AppendUint32(body, v)
		case uint64:
			body = binary.BigEndian.AppendUint64(body, v)
		case string:
			body = binary.BigEndian.AppendUint32(body, uint32(len(v)))
			body = append(body, v...)
		default:
			panic("bilinmeyen alan tipi")
		}
	}
	out := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	return append(out, body...)
}

// waitForSFTP, subsystem isteğinin işlenmesini bekler.
//
// Uyku yerine gerçek duruma bakıyoruz: request goroutine'i ile veri
// boruları paralel çalışıyor ve sabit bir bekleme ya yavaş ya kırılgan
// olurdu.
func waitForSFTP(t *testing.T, b *Broker) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if b.sftp.Load() != nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("subsystem sftp işlenmedi — denetim oturumu kurulmadı")
}

// --- süzgeç -----------------------------------------------------------

func TestSFTPPassesOnlyWhenEnabled(t *testing.T) {
	req := &ssh.Request{Type: "subsystem", Payload: sshString("sftp")}

	if ok, reason := (RequestPolicy{}).allow(fromClient, req); ok {
		t.Error("varsayılan yapılandırmada sftp geçti — yükseltme yapan " +
			"operatör habersiz bir veri çıkış yolu kazanır")
	} else if !strings.Contains(reason, "session.sftp") {
		t.Errorf("sebep ayarı işaret etmiyor: %q", reason)
	}

	if ok, _ := (RequestPolicy{AllowSFTP: true}).allow(fromClient, req); !ok {
		t.Error("açıkken sftp geçmedi")
	}
}

/*
 * ⚠️ BAYRAK BİR SUBSYSTEM ANAHTARI DEĞİL.
 *
 * Denetim yalnızca SFTP'nin tel biçimini biliyor. AllowSFTP tüm
 * altsistemleri açsaydı, adını bile çözemediğimiz bir kanal
 * "denetleniyor" iddiasıyla geçerdi.
 */
func TestEnablingSFTPDoesNotOpenOtherSubsystems(t *testing.T) {
	p := RequestPolicy{AllowSFTP: true}
	for _, name := range []string{"netconf", "subsystem", "sftp-extra", ""} {
		req := &ssh.Request{Type: "subsystem", Payload: sshString(name)}
		if ok, _ := p.allow(fromClient, req); ok {
			t.Errorf("subsystem %q sftp açıkken geçti", name)
		}
	}
}

// --- köprü: asıl iddia ------------------------------------------------

/*
 * ⚠️ BU TESTİN ÖLÇTÜĞÜ ŞEY, KANALIN NİYE KAPALI OLDUĞUDUR.
 *
 * ÖLÇÜLEN ARIZA (requests.go dosya başı): süzgeç yazılmadan önce
 * `subsystem sftp` uçtan uca çalışıyordu ve transfer .cast dosyasına HAM
 * İKİLİ olarak düşüyordu — 1 GB'lık indirme 1 GB'lık "terminal kaydı",
 * oynatınca anlamsız. Kanalı geri açan değişiklik, o kusuru geri
 * getirmemeli: baytlar kayda GİRMEMELİ, yerine dosya olayları çıkmalı.
 */
func TestSFTPBytesStayOutOfTheRecording(t *testing.T) {
	down, feedDown, _ := newFakeChannel()
	up, feedUp, _ := newFakeChannel()
	downR := make(chan *ssh.Request)
	upR := make(chan *ssh.Request)

	castSink := &memCloser{}
	rec, err := record.NewWriter(castSink, 80, 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	files := &memSink{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b := New(down, downR, up, upR, rec, true, RequestPolicy{AllowSFTP: true}, testLogger()).
		WithSFTP(files)
	done := make(chan error, 1)
	go func() { done <- b.Run(ctx) }()

	downR <- &ssh.Request{Type: "subsystem", Payload: sshString("sftp")}
	waitForSFTP(t, b)

	// Gizli dosyanın içeriği hedeften kullanıcıya akıyor.
	secret := strings.Repeat("KOKPIT-SIFRESI-", 200)
	mustWrite(t, feedDown, string(sftpPkt(3, uint32(1), "/etc/shadow", uint32(1), uint32(0))))
	mustWrite(t, feedUp, string(sftpPkt(102, uint32(1), "h1")))
	mustWrite(t, feedDown, string(sftpPkt(5, uint32(2), "h1", uint64(0), uint32(len(secret)))))
	mustWrite(t, feedUp, string(sftpPkt(103, uint32(2), secret)))
	mustWrite(t, feedDown, string(sftpPkt(4, uint32(3), "h1")))
	mustWrite(t, feedUp, string(sftpPkt(101, uint32(3), uint32(0), "", "")))

	// Baytlar hedefe/kullanıcıya AYNEN geçmiş olmalı: postern araya
	// bir SFTP sunucusu koymuyor.
	waitForContent(t, down.dataW, secret)

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run dönmedi")
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	cast := castSink.String()
	if strings.Contains(cast, "KOKPIT-SIFRESI") {
		t.Error("SFTP verisi terminal kaydına düştü — kanalın " +
			"reddedilmesine sebep olan kusur geri gelmiş")
	}

	// ...ve yerine dosya seviyesinde denetim çıkmış olmalı.
	var transfer *sftpaudit.Event
	for i, e := range files.all() {
		if e.Op == sftpaudit.OpTransfer {
			transfer = &files.all()[i]
		}
	}
	if transfer == nil {
		t.Fatalf("transfer olayı üretilmedi: %+v", files.all())
	}
	if transfer.Path != "/etc/shadow" {
		t.Errorf("yol = %q", transfer.Path)
	}
	if transfer.Read != int64(len(secret)) {
		t.Errorf("Read = %d, %d bekleniyordu", transfer.Read, len(secret))
	}
}

/*
 * ⚠️ ÇÖZÜMLENEMEYEN AKIŞ GEÇMEZ.
 *
 * Paket sınırı kaybolduysa sonraki her denetim satırı uydurma olur.
 * Kaydın açılamamasında verilen kararın aynısı: denetlenemeyen kanal
 * kapanır (lifecycle.go). Aksi hâlde bozuk bir başlık yollamak,
 * denetimi kapatmanın yolu olurdu.
 */
func TestUndecodableSFTPStreamEndsTheSession(t *testing.T) {
	down, feedDown, _ := newFakeChannel()
	up, _, _ := newFakeChannel()
	downR := make(chan *ssh.Request)
	upR := make(chan *ssh.Request)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b := New(down, downR, up, upR, nil, false, RequestPolicy{AllowSFTP: true}, testLogger()).
		WithSFTP(&memSink{})
	done := make(chan error, 1)
	go func() { done <- b.Run(ctx) }()

	downR <- &ssh.Request{Type: "subsystem", Payload: sshString("sftp")}
	waitForSFTP(t, b)

	// "uzunluk = 4 GB": sınır olmasa çözümleyici sonsuza dek beklerdi.
	hdr := binary.BigEndian.AppendUint32(nil, 0xFFFFFFFF)
	mustWrite(t, feedDown, string(hdr))

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("çözümlenemeyen akışta oturum kapanmadı — " +
			"denetim bozuk bir başlıkla susturulabiliyor")
	}
}

/*
 * ⚠️ YARIM KALAN TRANSFER KANAL KAPANINCA YAZILMALI.
 *
 * CLOSE hiç gelmezse özet de hiç yazılmaz; o hâlde veriyi çekip
 * bağlantıyı koparmak, izi silmenin yolu olurdu.
 */
func TestInterruptedSFTPTransferIsWrittenOnChannelClose(t *testing.T) {
	down, feedDown, _ := newFakeChannel()
	up, feedUp, _ := newFakeChannel()
	downR := make(chan *ssh.Request)
	upR := make(chan *ssh.Request)

	files := &memSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b := New(down, downR, up, upR, nil, false, RequestPolicy{AllowSFTP: true}, testLogger()).
		WithSFTP(files)
	done := make(chan error, 1)
	go func() { done <- b.Run(ctx) }()

	downR <- &ssh.Request{Type: "subsystem", Payload: sshString("sftp")}
	waitForSFTP(t, b)

	payload := strings.Repeat("v", 5000)
	mustWrite(t, feedDown, string(sftpPkt(3, uint32(1), "/data/dump.sql", uint32(1), uint32(0))))
	mustWrite(t, feedUp, string(sftpPkt(102, uint32(1), "h1")))
	mustWrite(t, feedDown, string(sftpPkt(5, uint32(2), "h1", uint64(0), uint32(len(payload)))))
	mustWrite(t, feedUp, string(sftpPkt(103, uint32(2), payload)))
	waitForContent(t, down.dataW, payload)

	// CLOSE göndermeden bağlantıyı kopar.
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run dönmedi")
	}

	var found bool
	for _, e := range files.all() {
		if e.Op == sftpaudit.OpTransfer && e.Path == "/data/dump.sql" {
			found = true
			if e.Read != 5000 {
				t.Errorf("Read = %d, 5000 bekleniyordu", e.Read)
			}
			if e.OK {
				t.Error("yarım transfer tamamlanmış gibi yazıldı")
			}
		}
	}
	if !found {
		t.Fatalf("koparılan transfer kayda girmedi: %+v", files.all())
	}
}

// SFTP kapalıyken veri yolu ESKİSİ GİBİ çalışmalı: kayıt tee'si yerinde.
func TestNonSFTPSessionStillTeesToTheRecording(t *testing.T) {
	down, _, _ := newFakeChannel()
	up, feedUp, _ := newFakeChannel()
	downR := make(chan *ssh.Request)
	upR := make(chan *ssh.Request)

	castSink := &memCloser{}
	rec, err := record.NewWriter(castSink, 80, 24, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// SFTP açık ve sink bağlı — ama kanal sftp'ye GEÇMEDİ.
	b := New(down, downR, up, upR, rec, false, RequestPolicy{AllowSFTP: true}, testLogger()).
		WithSFTP(&memSink{})
	done := make(chan error, 1)
	go func() { done <- b.Run(ctx) }()

	mustWrite(t, feedUp, "normal kabuk ciktisi\n")
	waitForContent(t, down.dataW, "normal kabuk ciktisi")

	cancel()
	<-done
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(castSink.String(), "normal kabuk ciktisi") {
		t.Error("sftp yeteneği açıkken normal oturum kayda düşmüyor — " +
			"denetim, kullanılmayan bir özellik yüzünden kaybolmuş")
	}
}

/*
 * ⚠️ CEVAP BEKLEMEYEN İSTEMCİNİN İLK PAKETLERİ DE DENETLENMELİ.
 *
 * Denetim, `subsystem sftp` isteği hedefe İLETİLDİKTEN sonra
 * kuruluyordu ve gerekçesi bir protokol iddiasıydı: "veri ancak
 * subsystem kabul edildikten sonra akar". Öyle değil — kanal
 * açıldığında istemcinin penceresi var ve paketleri cevabı beklemeden
 * gönderebiliyor. Aradaki pencere bir hedef gidiş-dönüşü kadar geniş.
 *
 * Kaybın görünmemesi arızanın en kötü tarafı: framer saf uzunluk-önekli
 * bir tarayıcı, akış herhangi bir paket sınırından başlarsa temiz
 * ayrışıyor. Yani ilk OPEN hedefte çalışıyor, denetime hiç girmiyor ve
 * dosya listesi kendini eksiksiz sanıyordu.
 *
 * ⚠️ BU TEST waitForSFTP KULLANMIYOR — bilerek. Paketten önce onu
 * çağıran diğer testler, üretim kodunun maruz kaldığı pencereyi tam
 * olarak senkronize edip yok ediyor.
 */
func TestPipelinedSFTPPacketsAreAudited(t *testing.T) {
	down, feedDown, _ := newFakeChannel()
	up, feedUp, _ := newFakeChannel()
	downR := make(chan *ssh.Request)
	upR := make(chan *ssh.Request)

	files := &memSink{}

	// Hedef subsystem'i hemen cevaplamıyor: gerçek bir gidiş-dönüş.
	entered, release := up.holdRequests()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b := New(down, downR, up, upR, nil, false, RequestPolicy{AllowSFTP: true}, testLogger()).
		WithSFTP(files)
	done := make(chan error, 1)
	go func() { done <- b.Run(ctx) }()

	downR <- &ssh.Request{Type: "subsystem", Payload: sshString("sftp")}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("subsystem isteği hedefe iletilmedi")
	}

	// ⚠️ CEVAP HENÜZ YOLDA. Kusurlu sürümde b.sftp burada nil'di ve
	// bu paket çözümleyiciye hiç uğramadan hedefe geçiyordu.
	mustWrite(t, feedDown, string(sftpPkt(3, uint32(1), "/etc/shadow", uint32(1), uint32(0))))

	release()

	// Kalan alışveriş normal sırada: hedef tanıtıcıyı veriyor, dosya
	// okunuyor, kapanıyor.
	secret := strings.Repeat("KOKPIT-SIFRESI-", 20)
	mustWrite(t, feedUp, string(sftpPkt(102, uint32(1), "h1")))
	mustWrite(t, feedDown, string(sftpPkt(5, uint32(2), "h1", uint64(0), uint32(len(secret)))))
	mustWrite(t, feedUp, string(sftpPkt(103, uint32(2), secret)))
	mustWrite(t, feedDown, string(sftpPkt(4, uint32(3), "h1")))
	mustWrite(t, feedUp, string(sftpPkt(101, uint32(3), uint32(0), "", "")))

	// ⚠️ ÇIKTI BAYTINI DEĞİL, OLAYI BEKLİYORUZ. İçerik CLOSE
	// alışverişinden önce geliyor; onu beklemek, kapatma paketleri
	// hâlâ yoldayken cancel'a izin verirdi.
	waitForContent(t, down.dataW, secret)
	waitForEvent(t, files, sftpaudit.OpTransfer)

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run dönmedi")
	}

	var transfer *sftpaudit.Event
	all := files.all()
	for i, e := range all {
		if e.Op == sftpaudit.OpTransfer {
			transfer = &all[i]
		}
	}
	if transfer == nil {
		t.Fatalf("BORU HATTI YAPAN İSTEMCİNİN AÇTIĞI DOSYA DENETİME HİÇ GİRMEDİ; "+
			"üretilen olaylar: %+v", all)
	}
	if transfer.Path != "/etc/shadow" {
		t.Errorf("yol = %q, /etc/shadow bekleniyordu", transfer.Path)
	}
}

/*
 * ⚠️ SUBSYSTEM HEDEFE GEÇMEZSE DENETİM GERİ ALINMALI.
 *
 * Kurulum artık cevaptan ÖNCE olduğu için, "hayır" cevabından sonra
 * kanal SFTP sanılmaya devam ederdi. Bedeli iki taraflı: sayGoodbye
 * kullanıcıya sebebi yazmaktan vazgeçer, ve aynı kanalda açılan bir
 * kabuğun baytları çözümleyiciye SFTP diye girip denetimi çökertir —
 * yani hedefin reddi, oturumu kesen bir arızaya dönüşürdü.
 */
func TestRefusedSFTPSubsystemLeavesNoAuditArmed(t *testing.T) {
	down, _, _ := newFakeChannel()
	up, _, _ := newFakeChannel()
	downR := make(chan *ssh.Request)
	upR := make(chan *ssh.Request)

	up.failRequests(errors.New("target has no sftp-server"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b := New(down, downR, up, upR, nil, false, RequestPolicy{AllowSFTP: true}, testLogger()).
		WithSFTP(&memSink{})
	done := make(chan error, 1)
	go func() { done <- b.Run(ctx) }()

	downR <- &ssh.Request{Type: "subsystem", Payload: sshString("sftp")}

	// İkinci bir istek, birincisinin işlenmiş olduğunu garanti ediyor:
	// request akışı sıralı, yani bu okunduğunda öncekinin cevabı
	// verilmiş demek.
	downR <- &ssh.Request{Type: "env", Payload: sshString("TERM")}

	if s := b.sftp.Load(); s != nil {
		t.Error("hedef subsystem'i reddetti ama denetim kurulu kaldı: " +
			"kanal SFTP sanılır, kullanıcıya kapanış sebebi yazılmaz " +
			"ve kabuk baytları çözümleyiciyi çökertir")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run dönmedi")
	}
}

/*
 * ⚠️ CEVAP İSTEMEYEN BİR SUBSYSTEM İSTEĞİ DENETİMİ KAPATAMAMALI.
 *
 * ÖLÇÜLEN ARIZA — VE BU DEPONUN KENDİ AÇTIĞI BİR ARIZAYDI. Denetimi
 * iletimden önce kurma düzeltmesi, "hedef reddederse geri al"
 * koşulunu yalnızca `!res` diye yazmıştı. x/crypto'da SendRequest,
 * cevap istenmediğinde hedefte ne olursa olsun `false, nil` dönüyor
 * (ssh/channel.go). Yani `subsystem sftp`'yi want_reply=0 ile
 * gönderen bir istemcide geri alma HER SEFERİNDE çalışıyor, istek
 * hedefe gidiyor ve tek bir denetim satırı yazılmıyordu.
 *
 * Gerçek OpenSSH want_reply=0'ı onurlandırıp sftp-server'ı başlatıyor,
 * yani atlatma kullanıcının seçebileceği bir şeydi: denetlenen tarafın
 * denetlenip denetlenmeyeceğine karar vermesi — SFTP denetiminin var
 * olma sebebinin tam tersi.
 */
func TestSFTPWithoutReplyIsStillAudited(t *testing.T) {
	down, feedDown, _ := newFakeChannel()
	up, feedUp, _ := newFakeChannel()
	downR := make(chan *ssh.Request)
	upR := make(chan *ssh.Request)

	files := &memSink{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b := New(down, downR, up, upR, nil, false, RequestPolicy{AllowSFTP: true}, testLogger()).
		WithSFTP(files)
	done := make(chan error, 1)
	go func() { done <- b.Run(ctx) }()

	// ⚠️ WantReply YOK. Tek fark bu.
	downR <- &ssh.Request{Type: "subsystem", Payload: sshString("sftp")}
	waitForSFTP(t, b)

	secret := strings.Repeat("KOKPIT-SIFRESI-", 20)
	mustWrite(t, feedDown, string(sftpPkt(3, uint32(1), "/etc/shadow", uint32(1), uint32(0))))
	mustWrite(t, feedUp, string(sftpPkt(102, uint32(1), "h1")))
	mustWrite(t, feedDown, string(sftpPkt(5, uint32(2), "h1", uint64(0), uint32(len(secret)))))
	mustWrite(t, feedUp, string(sftpPkt(103, uint32(2), secret)))
	mustWrite(t, feedDown, string(sftpPkt(4, uint32(3), "h1")))
	mustWrite(t, feedUp, string(sftpPkt(101, uint32(3), uint32(0), "", "")))

	// ⚠️ ÇIKTI BAYTINI DEĞİL, OLAYI BEKLİYORUZ. İçerik CLOSE
	// alışverişinden önce geliyor; onu beklemek, kapatma paketleri
	// hâlâ yoldayken cancel'a izin verirdi.
	waitForContent(t, down.dataW, secret)
	waitForEvent(t, files, sftpaudit.OpTransfer)

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run dönmedi")
	}

	var transfer *sftpaudit.Event
	all := files.all()
	for i, e := range all {
		if e.Op == sftpaudit.OpTransfer {
			transfer = &all[i]
		}
	}
	if transfer == nil {
		t.Fatalf("CEVAP İSTEMEYEN SUBSYSTEM İSTEĞİ DENETİMİ KAPATTI: "+
			"kullanıcı tek bir bayrağı düşürerek denetimsiz dosya taşıyabilir; "+
			"üretilen olaylar: %+v", all)
	}
	if transfer.Path != "/etc/shadow" {
		t.Errorf("yol = %q", transfer.Path)
	}
}

/*
 * ⚠️ GERİ ALMA KARARININ DÖRT HÂLİ.
 *
 * Bu tablo, denetimi kapatan tek satırın doğrudan ölçümü. Köprünün
 * sahte kanalıyla "hedef hayır dedi" hâli kurulamıyor (o yolda broker
 * req.Reply çağırıyor ve o gerçek bir bağlantı istiyor), dolayısıyla
 * karar saf bir fonksiyona alındı ve dördü de burada sınanıyor.
 *
 * İkinci satır, üretime çıkmış bir denetim atlatmasının ta kendisi.
 */
func TestUndoArmNeedsAnActualRefusal(t *testing.T) {
	boom := errors.New("iletilemedi")
	for _, c := range []struct {
		name      string
		wantReply bool
		res       bool
		err       error
		want      bool
		why       string
	}{
		{
			name: "cevap istendi ve hedef reddetti", wantReply: true, res: false,
			want: true,
			why:  "hedef açıkça hayır dedi: kurduğumuz denetim geri alınmalı",
		},
		{
			name: "cevap İSTENMEDİ", wantReply: false, res: false,
			want: false,
			why: "x/crypto cevap istenmediğinde her zaman false dönüyor; " +
				"bunu ret saymak, istemciye denetimi kapatma düğmesi verir",
		},
		{
			name: "cevap istendi ve hedef kabul etti", wantReply: true, res: true,
			want: false,
			why:  "kabul edilen subsystem denetlenmeye devam etmeli",
		},
		{
			name: "iletim hata verdi", wantReply: false, res: false, err: boom,
			want: true,
			why:  "istek hedefe hiç ulaşmadı: denetlenecek bir akış yok",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := undoArm(c.wantReply, c.res, c.err); got != c.want {
				t.Errorf("undoArm(%v,%v,%v) = %v, %v bekleniyordu — %s",
					c.wantReply, c.res, c.err, got, c.want, c.why)
			}
		})
	}
}
