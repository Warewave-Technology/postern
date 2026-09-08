package proxy

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/sftpaudit"
)

// startPolicySession, politikalı bir SFTP kanalı kurar.
func startPolicySession(t *testing.T, d sftpaudit.Decider) (
	down, up *fakeChannel, feedDown, feedUp *pipeFeeder, files *memSink, stop func(),
) {
	t.Helper()

	down, fd, _ := newFakeChannel()
	up, feedDown, feedUp, files, stop = startPolicySessionOn(t, d, down, down, fd)

	return down, up, feedDown, feedUp, files, stop
}

/*
 * startPolicySessionOn, istemci ucunu ÇAĞIRANIN verdiği aynı kurulumu
 * yapar.
 *
 * ⚠️ UÇ DIŞARIDAN GELİYOR, çünkü ölçülecek şeylerden biri postern'in
 * kendi cevabını HANGİ uçtan yazdığı: köken etiketini taşıyabilen bir
 * kanal ile taşıyamayan bir kanal aynı kurulumdan geçmeli, yoksa iki
 * yolun biri sınanmadan kalır.
 */
func startPolicySessionOn(
	t *testing.T, d sftpaudit.Decider, downCh ssh.Channel, down *fakeChannel, fd *io.PipeWriter,
) (up *fakeChannel, feedDown, feedUp *pipeFeeder, files *memSink, stop func()) {
	t.Helper()

	up, fu, _ := newFakeChannel()
	downR := make(chan *ssh.Request)
	upR := make(chan *ssh.Request)

	files = &memSink{}

	ctx, cancel := context.WithCancel(context.Background())

	b := New(downCh, downR, up, upR, nil, false, RequestPolicy{AllowSFTP: true}, testLogger()).
		WithSFTP(files).
		WithSFTPPolicy(d)

	done := make(chan error, 1)
	go func() { done <- b.Run(ctx) }()

	downR <- &ssh.Request{Type: "subsystem", Payload: sshString("sftp")}
	waitForSFTP(t, b)

	/*
	 * ⚠️ SÜRÜM ANLAŞMASI ATLANMIYOR. postern, hedef henüz konuşmamışken
	 * istemciye kendi cevabını YAZMIYOR (bkz. TargetAtBoundary): aksi
	 * hâlde istemcinin gördüğü ilk paket bizim STATUS'umuz olurdu ve
	 * OpenSSH'in sftp_init'i yalnızca VERSION kabul edip fatal ile
	 * çıkıyor. Gerçek bir oturum da tam olarak böyle başlıyor.
	 */
	if _, err := fd.Write(sftpPkt(1, uint32(3))); err != nil {
		t.Fatalf("INIT gönderilemedi: %v", err)
	}
	if _, err := fu.Write(sftpPkt(2, uint32(3))); err != nil {
		t.Fatalf("VERSION gönderilemedi: %v", err)
	}
	waitForContent(t, down.dataW, string(sftpPkt(2, uint32(3))))

	return up, &pipeFeeder{fd}, &pipeFeeder{fu}, files, func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("Run dönmedi")
		}
	}
}

type pipeFeeder struct {
	w interface{ Write([]byte) (int, error) }
}

func (p *pipeFeeder) send(t *testing.T, b []byte) {
	t.Helper()
	if _, err := p.w.Write(b); err != nil {
		t.Fatalf("besleme başarısız: %v", err)
	}
}

/*
 * Uçtan uca: reddedilen istek HEDEFE ULAŞMIYOR ve İSTEMCİ CEVABINI ALIYOR.
 *
 * ⚠️ İKİNCİSİ BİRİNCİSİ KADAR ÖNEMLİ. Reddedilen istek hedefe gitmediği için
 * hedef onu hiçbir zaman cevaplamayacak; SFTP cevapları istek kimliğiyle
 * eşliyor, dolayısıyla cevapsız kalan bir kimlik istemcinin SONSUZA KADAR
 * beklemesi demek. Reddi uygulamak yetmiyor, söylemek de gerekiyor.
 */
func TestRefusedRequestIsBlockedAndAnswered(t *testing.T) {
	deny := func(r sftpaudit.Request) (bool, string) {
		return r.Path != "/etc/shadow", "path is not permitted"
	}

	down, up, feedDown, _, files, stop := startPolicySession(t, deny)
	defer stop()

	pkt := sftpPkt(3, uint32(11), "/etc/shadow", uint32(1), uint32(0))
	feedDown.send(t, pkt)

	// İstemciye cevap ulaşmalı: STATUS, aynı istek kimliğiyle.
	waitForContent(t, down.dataW, "postern:")

	// Hedef bu isteği HİÇ görmemeli.
	if got := up.dataW.String(); strings.Contains(got, "/etc/shadow") {
		t.Fatalf("REDDEDİLEN YOL HEDEFE ULAŞTI: %q", got)
	}

	// Denetim defterinde ret satırı olmalı.
	var seen bool
	for _, e := range files.all() {
		if e.Op == "denied."+sftpaudit.OpOpen && !e.OK && e.Path == "/etc/shadow" {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("ret denetim defterine düşmedi: %+v", files.all())
	}
}

// İzin verilen istek olduğu gibi geçiyor: politika varsayılan yolu
// değiştirmemeli.
func TestAllowedRequestStillReachesTheTarget(t *testing.T) {
	allow := func(sftpaudit.Request) (bool, string) { return true, "" }

	_, up, feedDown, _, _, stop := startPolicySession(t, allow)
	defer stop()

	pkt := sftpPkt(3, uint32(1), "/home/u/veri.txt", uint32(1), uint32(0))
	feedDown.send(t, pkt)

	waitForContent(t, up.dataW, string(pkt))
}

/*
 * ⚠️ CEVAP, HEDEFİN PAKETİNİN ORTASINA DÜŞEMEZ.
 *
 * ÖLÇÜLEN TEHLİKE: istemci hedeften bir paket okurken postern kendi
 * cevabını araya sokarsa, o baytlar istemcinin gözünde paketin GÖVDESİ
 * olur. Paket yanlış yerden ayrışır ve o noktadan sonra akıştaki HER bayt
 * kayar — istemci ya protokol hatasıyla kopar ya da indirdiği dosyanın
 * içine STATUS paketini yazar.
 *
 * Kurgu: hedef bir paketin uzunluk önekini ve gövdesinin bir kısmını
 * gönderiyor, sonra duruyor. Tam o sırada istemcinin isteği reddediliyor.
 * Cevap BEKLEMELİ; ancak hedef paketini tamamladıktan SONRA yazılmalı.
 */
func TestRefusalWaitsForAPacketBoundary(t *testing.T) {
	deny := func(r sftpaudit.Request) (bool, string) {
		return r.Path != "/etc/shadow", "path is not permitted"
	}

	down, _, feedDown, feedUp, _, stop := startPolicySession(t, deny)
	defer stop()

	// Hedef bir DATA paketine başlıyor ama bitirmiyor.
	full := sftpPkt(103, uint32(1), "GOVDE-BASLANGICI")
	head, tail := full[:len(full)-6], full[len(full)-6:]
	feedUp.send(t, head)
	waitForContent(t, down.dataW, "GOVDE-BAS")

	// Tam bu sırada ret geliyor.
	feedDown.send(t, sftpPkt(3, uint32(11), "/etc/shadow", uint32(1), uint32(0)))

	// Cevap HENÜZ yazılmamalı: hedef akışı paketin ortasında.
	time.Sleep(150 * time.Millisecond)
	if got := down.dataW.String(); strings.Contains(got, "postern:") {
		t.Fatalf("CEVAP PAKETİN ORTASINA YAZILDI; istemcinin akışı bu noktadan "+
			"sonra kayar. Tampon: %q", got)
	}

	// Hedef paketini tamamlıyor: sınıra varıldı, cevap şimdi gitmeli.
	feedUp.send(t, tail)
	waitForContent(t, down.dataW, "postern:")

	// Ve cevap, hedefin paketinin TAMAMINDAN sonra gelmeli.
	got := down.dataW.String()
	if i, j := strings.Index(got, "postern:"), strings.Index(got, string(tail)); i < j {
		t.Fatalf("cevap, hedefin paketi bitmeden yazılmış (cevap=%d, paket sonu=%d)", i, j)
	}
}

/*
 * ⚠️ SINIR SORUSU, YAZILMIŞ AMA HENÜZ ÇÖZÜMLENMEMİŞ BİR PARÇAYA SORULAMAZ.
 *
 * Hedef yönündeki tap önce istemciye YAZIYOR, sonra çözümleyiciye
 * BESLİYOR. Bu iki adım aynı kilit altında olmazsa aradaki anda
 * "sınırda mıyım" sorusu BAYAT bir cevap veriyor: baytlar istemciye
 * ulaşmış, çözümleyici hâlâ bir önceki paketin sonunda görünüyor. O anda
 * yazılan bir ret cevabı, istemcinin okumakta olduğu paketin tam ortasına
 * düşüyor ve akış o noktadan sonra kayıyor.
 *
 * Bu test o aralığı DETERMİNİSTİK hâle getiriyor: onWrite kancası tam
 * orada duruyor ve ret o sırada tetikleniyor. Kilit varsa enjektör
 * beklemek zorunda; yoksa yazıyor ve test görüyor.
 */
func TestRefusalCannotSlipBetweenTheWriteAndTheParse(t *testing.T) {
	down, fd, _ := newFakeChannel()
	up, fu, _ := newFakeChannel()
	downR := make(chan *ssh.Request)
	upR := make(chan *ssh.Request)

	inWindow := make(chan struct{})
	release := make(chan struct{})

	// İstemciye "GOVDE" yazıldığı an: baytlar orada, çözümleyici görmedi.
	down.respondWith(func(b []byte) {
		if !strings.Contains(string(b), "GOVDE") {
			return
		}
		select {
		case <-inWindow:
		default:
			close(inWindow)
		}
		<-release
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b := New(down, downR, up, upR, nil, false, RequestPolicy{AllowSFTP: true}, testLogger()).
		WithSFTP(&memSink{}).
		WithSFTPPolicy(func(r sftpaudit.Request) (bool, string) {
			return r.Path != "/etc/shadow", "path is not permitted"
		})

	done := make(chan error, 1)
	go func() { done <- b.Run(ctx) }()

	downR <- &ssh.Request{Type: "subsystem", Payload: sshString("sftp")}
	waitForSFTP(t, b)

	// Sürüm anlaşması: hedef konuşmuş olmalı (bkz. TargetAtBoundary).
	go func() { _, _ = fd.Write(sftpPkt(1, uint32(3))) }()
	go func() { _, _ = fu.Write(sftpPkt(2, uint32(3))) }()
	waitForContent(t, down.dataW, string(sftpPkt(2, uint32(3))))

	// Hedef yarım bir paket gönderiyor; kanca pencerede duruyor.
	full := sftpPkt(103, uint32(1), "GOVDE-BASLANGICI")
	go func() { _, _ = fu.Write(full[:len(full)-6]) }()

	select {
	case <-inWindow:
	case <-time.After(2 * time.Second):
		t.Fatal("yazma penceresine hiç girilmedi")
	}

	// Pencere AÇIKKEN ret tetikleniyor.
	go func() {
		_, _ = fd.Write(sftpPkt(3, uint32(11), "/etc/shadow", uint32(1), uint32(0)))
	}()

	time.Sleep(200 * time.Millisecond)

	got := down.dataW.String()
	close(release)

	if strings.Contains(got, "postern:") {
		t.Fatalf("CEVAP, YAZMA İLE ÇÖZÜMLEME ARASINDA YAZILDI — istemcinin "+
			"okuduğu paketin ortasına düştü. Tampon: %q", got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("Run dönmedi")
	}
}

/*
 * ⚠️ HEDEF KONUŞMADAN İSTEMCİYE YAZMIYORUZ.
 *
 * ÖLÇÜLEN TEHLİKE: istemci INIT'i ve reddedilecek bir isteği boru hattıyla
 * birlikte gönderebiliyor. Cevabı hemen yazsaydık, istemcinin gördüğü İLK
 * paket SSH_FXP_STATUS olurdu — oysa SFTP'de ilk paket SSH_FXP_VERSION
 * olmak zorunda. OpenSSH'in sftp_init'i başka bir şey görünce fatal ile
 * çıkıyor, paramiko SFTPError fırlatıyor: yani ret, oturumu düzgün
 * reddetmek yerine istemciyi çökertirdi.
 */
func TestRefusalWaitsForTheTargetToSpeakFirst(t *testing.T) {
	down, fd, _ := newFakeChannel()
	up, fu, _ := newFakeChannel()
	downR := make(chan *ssh.Request)
	upR := make(chan *ssh.Request)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b := New(down, downR, up, upR, nil, false, RequestPolicy{AllowSFTP: true}, testLogger()).
		WithSFTP(&memSink{}).
		WithSFTPPolicy(func(r sftpaudit.Request) (bool, string) {
			return r.Path != "/etc/shadow", "path is not permitted"
		})

	done := make(chan error, 1)
	go func() { done <- b.Run(ctx) }()

	downR <- &ssh.Request{Type: "subsystem", Payload: sshString("sftp")}
	waitForSFTP(t, b)

	// İstemci INIT ile reddedilecek isteği boru hattıyla gönderiyor.
	// Hedef henüz hiçbir şey söylemedi.
	go func() {
		_, _ = fd.Write(sftpPkt(1, uint32(3)))
		_, _ = fd.Write(sftpPkt(3, uint32(11), "/etc/shadow", uint32(1), uint32(0)))
	}()

	time.Sleep(200 * time.Millisecond)
	if got := down.dataW.String(); strings.Contains(got, "postern:") {
		t.Fatalf("HEDEF KONUŞMADAN CEVAP YAZILDI; istemcinin gördüğü ilk "+
			"paket VERSION olmalıydı. Tampon: %q", got)
	}

	// Hedef VERSION'ı yolluyor: artık cevap yazılabilir.
	if _, err := fu.Write(sftpPkt(2, uint32(3))); err != nil {
		t.Fatal(err)
	}
	waitForContent(t, down.dataW, "postern:")

	got := down.dataW.String()
	if i, j := strings.Index(got, "postern:"), strings.Index(got, string(sftpPkt(2, uint32(3)))); i < j {
		t.Fatalf("cevap VERSION'dan ÖNCE yazılmış (cevap=%d, version=%d)", i, j)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("Run dönmedi")
	}
}

/*
 * ⚠️ REDDİN GEREKÇESİ KULLANICIYA ULAŞIYOR — stderr'den.
 *
 * ÖLÇÜLEN ARIZA: reddi uyguluyor ve deftere yazıyorduk, ama OpenSSH'in
 * sftp istemcisi STATUS'un mesaj alanını hiç okumuyor ve başarısız bir
 * stat'ı durum kodundan bağımsız olarak "not found" diye yazıyor. Yani
 * engellenen kişi "engellendim" ile "dosya yok"u ayırt edemiyordu ve
 * yazım hatası sanıp varyasyonlarla denemeye devam ederdi.
 *
 * stderr ayrı bir SSH mesaj türü: SFTP çerçevelemesini bozamaz, paket
 * sınırı beklemek gerekmez.
 */
func TestRefusalReasonReachesTheUserOnStderr(t *testing.T) {
	deny := func(r sftpaudit.Request) (bool, string) {
		return r.Path != "/etc/shadow", "path is not permitted"
	}

	down, _, feedDown, _, _, stop := startPolicySession(t, deny)
	defer stop()

	feedDown.send(t, sftpPkt(3, uint32(11), "/etc/shadow", uint32(1), uint32(0)))

	waitForContent(t, down.errW, "/etc/shadow")

	got := down.errW.String()
	if !strings.Contains(got, "postern:") {
		t.Errorf("satır postern'den geldiğini söylemiyor: %q", got)
	}
	if !strings.Contains(got, "not permitted") {
		t.Errorf("gerekçe yok: %q", got)
	}
}

/*
 * Aynı gerekçe iki kez yazılmıyor.
 *
 * ⚠️ NEDEN: tek bir `get` stat ve open olmak üzere iki ret üretebiliyor,
 * `mget *` yüzlerce. Aynı satırı tekrar yazmak kullanıcının terminalini
 * bizim doldurmamız olurdu.
 */
func TestRepeatedRefusalsAreNotRepeatedToTheUser(t *testing.T) {
	deny := func(r sftpaudit.Request) (bool, string) {
		return r.Path != "/etc/shadow", "path is not permitted"
	}

	down, _, feedDown, _, _, stop := startPolicySession(t, deny)
	defer stop()

	for i := 2; i < 6; i++ {
		feedDown.send(t, sftpPkt(3, uint32(i), "/etc/shadow", uint32(1), uint32(0)))
	}
	waitForContent(t, down.errW, "/etc/shadow")
	time.Sleep(100 * time.Millisecond)

	if n := strings.Count(down.errW.String(), "/etc/shadow"); n != 1 {
		t.Fatalf("aynı gerekçe %d kez yazıldı: %q", n, down.errW.String())
	}
}
