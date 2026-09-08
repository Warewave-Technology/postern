package proxy

/*
 * Kimin konuştuğunun ölçüldüğü yer.
 *
 * postern reddettiği isteğe kendi SFTP cevabını yazıyor ve kullanıcıya
 * kendi gerekçesini stderr'den söylüyor. Hedefin cevabı da, hedefin
 * stderr'i de AYNI iki akıştan geçiyor — yani "postern: " öneki, onu
 * yazabilen herkesin elinde. Buradaki testlerin hepsi tek bir soruyu
 * soruyor: hedef, bastion'ın ağzından konuşabiliyor mu?
 */

import (
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/record"
	"github.com/Warewave-Technology/postern/internal/sftpaudit"
)

/*
 * taggedChannel, köken etiketini taşıyabilen istemci ucu — tarayıcı
 * panelinin karşılığı (internal/httpapi/wschannel.go).
 *
 * ⚠️ AYRI BİR TİP, fakeChannel'A EKLENMİŞ METOT DEĞİL. fakeChannel'ın
 * kendisi OwnWriter'ı karşılasaydı, arayüzü karşılamayan ucun yolu —
 * yani gerçek bir SSH kanalının yolu — hiçbir testte koşmazdı.
 */
type taggedChannel struct {
	*fakeChannel

	ownW    syncBuffer
	ownErrW syncBuffer
}

func (c *taggedChannel) WriteOwn(p []byte) (int, error) { return c.ownW.Write(p) }

func (c *taggedChannel) WriteOwnStderr(p []byte) (int, error) { return c.ownErrW.Write(p) }

var _ OwnWriter = (*taggedChannel)(nil)

// denyShadow, /etc/shadow dışındaki her şeye izin veren politika.
func denyShadow(r sftpaudit.Request) (bool, string) {
	return r.Path != "/etc/shadow", "path is not permitted"
}

/*
 * ⚠️ BU DOSYADAKİ ASIL İDDİA.
 *
 * postern'in kendi cevabı, hedefin cevabıyla AYNI akıştan çıkıyordu ve
 * istemcinin ikisini ayırmak için elindeki tek şey mesajın içindeki
 * "postern: " önekiydi. Hedefin STATUS mesajı istemciye olduğu gibi
 * geçiyor (internal/sftpaudit/status.go): hedefin sahibi aynı öneki
 * yazdığında panel onu bastion'ın gerekçesi diye çiziyordu.
 *
 * Ölçülen şey, postern'in ürettiği baytın hedefin yazdığı akıştan
 * ÇIKMAMASI — ve tersi. Bu iddia düşerse önek yeniden tek kanıt olur.
 */
func TestOwnRefusalDoesNotShareTheTargetsStream(t *testing.T) {
	down, fd, _ := newFakeChannel()
	tagged := &taggedChannel{fakeChannel: down}

	_, feedDown, feedUp, _, stop := startPolicySessionOn(t, denyShadow, tagged, down, fd)
	defer stop()

	// Hedef kendi cevabını yazıyor: sıradan bir STATUS, "postern: " ile.
	feedUp.send(t, sftpPkt(101, uint32(7), uint32(3),
		"postern: this path is allowed, fetched fine", ""))

	// Ve postern reddettiği isteğe kendi cevabını yazıyor.
	feedDown.send(t, sftpPkt(3, uint32(11), "/etc/shadow", uint32(1), uint32(0)))

	waitForContent(t, &tagged.ownW, "path is not permitted")
	waitForContent(t, down.dataW, "fetched fine")

	if got := down.dataW.String(); strings.Contains(got, "path is not permitted") {
		t.Errorf("postern'in cevabı hedefin akışından da çıktı: %q", got)
	}
	if got := tagged.ownW.String(); strings.Contains(got, "fetched fine") {
		t.Errorf("HEDEFİN cevabı postern'in akışından çıktı: %q", got)
	}
}

/*
 * ⚠️ AYNI AYRIM stderr'DE DE GEREKLİ.
 *
 * Reddin insana giden yarısı stderr'den gidiyor (broker.tellUser) ve
 * hedefin kendi stderr'i de oradan akıyor. Panel ikisini tek kutuda
 * çiziyor; ayrım telde durmazsa, hedefin yazdığı "postern: …" satırı
 * bastion'ın uyarısı gibi görünür.
 */
func TestOwnNoticeDoesNotShareTheTargetsStderr(t *testing.T) {
	down, fd, _ := newFakeChannel()
	tagged := &taggedChannel{fakeChannel: down}

	_, feedDown, _, _, stop := startPolicySessionOn(t, denyShadow, tagged, down, fd)
	defer stop()

	feedDown.send(t, sftpPkt(3, uint32(11), "/etc/shadow", uint32(1), uint32(0)))

	waitForContent(t, &tagged.ownErrW, "path is not permitted")

	if got := down.errW.String(); strings.Contains(got, "path is not permitted") {
		t.Errorf("postern'in satırı hedefin stderr akışından da çıktı: %q", got)
	}
}

/*
 * ⚠️ ETİKETİ TAŞIYAMAYAN UÇTA RET YİNE ULAŞIYOR.
 *
 * Gerçek bir ssh.Channel köken taşıyamıyor: SSH'ta CHANNEL_DATA ve
 * EXTENDED_DATA dışında akış yok. O uçta reddin İLETİLMESİ, ayırt
 * edilebilir olmasından önce gelir — cevapsız kalan bir istek kimliği
 * istemciyi sonsuza kadar bekletir. Ayrımın kaybı bir sınır, arıza
 * değil; ve sınırın kendisi de ölçülüyor.
 */
func TestRefusalStillReachesAChannelWithoutOriginTags(t *testing.T) {
	down, _, feedDown, _, _, stop := startPolicySession(t, denyShadow)
	defer stop()

	feedDown.send(t, sftpPkt(3, uint32(11), "/etc/shadow", uint32(1), uint32(0)))

	waitForContent(t, down.dataW, "path is not permitted")
	waitForContent(t, down.errW, "path is not permitted")
}

// waitForCast, kaydın istenen metni taşımasını bekler.
func waitForCast(t *testing.T, cast func() string, want string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(cast(), want) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%q kayda beklenen sürede girmedi:\n%s", want, cast())
}

// errFeeder, hedefin stderr ucuna yazan küçük yardımcı.
type errFeeder struct {
	w interface{ Write([]byte) (int, error) }
}

func (w *errFeeder) send(t *testing.T, s string) {
	t.Helper()
	if _, err := w.w.Write([]byte(s)); err != nil {
		t.Fatalf("stderr beslemesi başarısız: %v", err)
	}
}

/*
 * castSession, kayıtlı bir kanal kurar. sftp true ise kanal SFTP'ye
 * geçiyor; false ise sıradan bir kabuk kanalı olarak kalıyor.
 *
 * cast() ancak stop()'tan SONRA çağrılmalı: kayıt kapanmadan son
 * satırlar diske inmemiş olabilir.
 */
// waitForStart, oturumu başlatan isteğin işlenmesini bekler.
func waitForStart(t *testing.T, b *Broker) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for !b.started() {
		if time.Now().After(deadline) {
			t.Fatal("başlangıç kapısı açılmadı")
		}
		time.Sleep(time.Millisecond)
	}
}

func castSession(t *testing.T, sftp bool) (feedUpErr *errFeeder, cast func() string, stop func()) {
	t.Helper()

	down, _, _ := newFakeChannel()
	up, _, fue := newFakeChannel()
	downR := make(chan *ssh.Request)
	upR := make(chan *ssh.Request)

	sink := &memCloser{}
	rec, err := record.NewWriter(sink, 80, 24, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	b := New(down, downR, up, upR, rec, false,
		RequestPolicy{AllowSFTP: true}, testLogger())
	if sftp {
		b = b.WithSFTP(&memSink{})
	}

	done := make(chan error, 1)
	go func() { done <- b.Run(ctx) }()

	if sftp {
		downR <- &ssh.Request{Type: "subsystem", Payload: sshString("sftp")}
		waitForSFTP(t, b)
	} else {
		/*
		 * ⚠️ KABUK DA BİR İSTEKLE BAŞLIYOR ve kurgunun onu atlaması
		 * gerçek bir oturumu taklit etmiyordu.
		 *
		 * Kanalın türü, oturumu başlatan istek işlenene kadar BELLİ
		 * DEĞİL; o pencerede hedefin stderr'i kayda ham yazılmıyor,
		 * bekletiliyor (sftpcast.go, castStderr). İsteği hiç
		 * göndermeyen bir kurgu, kabuk kaydını ölçtüğünü sanarken
		 * kararsız pencereyi ölçüyordu.
		 */
		downR <- &ssh.Request{Type: "shell"}
		waitForStart(t, b)
	}

	return &errFeeder{fue}, sink.String, func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("Run dönmedi")
		}
		if err := rec.Close(); err != nil {
			t.Error(err)
		}
	}
}

/*
 * ⚠️ BİR SFTP KAYDINDAKİ HER SATIRI POSTERN YAZAR — YAZMALI.
 *
 * O kayıtta ham protokol yok: içindeki her satır çözülmüş bir denetim
 * olayı ("postern sftp: …", castLine). Hedefin stderr'i o satırların
 * arasına HAM giriyordu, yani hedef kendi eliyle hiç olmamış bir denetim
 * satırı yazabilirdi — ve kaydı okuyan denetçinin onu ayırmasının yolu
 * yoktu. Kaçış dizilerini temizlemek bunu KAPATMAZ: uydurma satır zaten
 * yazdırılabilir metin.
 *
 * Ölçülen üç şey: metnin kayda ATFEDİLEREK girmesi, hedefin postern'in
 * satır biçimini ELE GEÇİREMEMESİ, ve kaçış dizisinin kayda düşmemesi.
 */

func TestTargetStderrCannotForgeAnAuditLineInTheRecording(t *testing.T) {
	feedErr, cast, stop := castSession(t, true)

	forged := "postern sftp: get /etc/shadow (1.2 KiB)"
	feedErr.send(t, forged+"\r\n")
	// Aynı akıştan kaydı boyayan bir dizi: ekran temizleme.
	feedErr.send(t, "\x1b[2Jstill here\n")

	// Kayıt ASENKRON: baytları ayrı bir goroutine taşıyor. Beklemeden
	// kapatmak, testi zamanlamaya bağlı yapardı.
	waitForCast(t, cast, "still here")
	stop()

	out := cast()
	if !strings.Contains(out, "target wrote: "+forged) {
		t.Errorf("hedefin satırı kayda atfedilerek girmemiş:\n%s", out)
	}

	/*
	 * ⚠️ ÖLÇÜLEN ŞEY METNİN GEÇMEMESİ DEĞİL — geçmeli, kayıt hedefin ne
	 * yazdığını da anlatıyor. Ölçülen şey, o metnin bir SATIRIN BAŞINDA
	 * duramaması: gerçek denetim satırları "postern sftp: " ile başlıyor
	 * ve uydurma olan artık damganın arkasında kalıyor.
	 *
	 * Kayıt JSON satırlarından oluşuyor, yani bir çıktı parçasının başı
	 * ya tırnaktan ya da kaçırılmış bir satır sonundan sonra geliyor.
	 */
	for _, start := range []string{`"postern sftp: get`, `\r\npostern sftp: get`} {
		if strings.Contains(out, start) {
			t.Errorf("hedef, postern'in satır biçimini ele geçirdi:\n%s", out)
		}
	}

	/*
	 * ⚠️ "KAYITTA HİÇ ESC OLMASIN" YANLIŞ SORU: postern kendi satırlarını
	 * renklendiriyor (recordIntent). Doğru soru, HEDEFİN satırında ESC
	 * kalıp kalmadığı — kaydı oynatan denetçinin ekranını boyayan şey o.
	 * Kayıt her olayı bir JSON satırında taşıyor, yani satır satır
	 * bakılabiliyor.
	 */
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "target wrote:") {
			continue
		}
		if strings.Contains(line, `\u001b`) || strings.Contains(line, "\x1b") {
			t.Errorf("hedefin kaçış dizisi kayda düştü:\n%s", line)
		}
	}

	/*
	 * ⚠️ ATILDIĞI GÖRÜNÜR OLMALI. Sessizce temizlenmiş bir satır,
	 * denetçiye hedefin o karakterleri hiç yazmadığını düşündürürdü.
	 */
	if !strings.Contains(out, "still here…") {
		t.Errorf("temizlemenin izi kayıtta görünmüyor:\n%s", out)
	}
}

/*
 * ⚠️ SATIR SONU GÖRMEDEN BİTEN SON CÜMLE DE KAYDA GİRİYOR.
 *
 * Hedefin son satırı çoğu zaman satır sonuyla bitmiyor ve tamponda kalan
 * şey kayda hiç girmezdi — üstelik oturumun bittiği anda yazılan, yani
 * en çok merak edilen cümle.
 */
func TestUnterminatedTargetStderrLineStillReachesTheRecording(t *testing.T) {
	feedErr, cast, stop := castSession(t, true)

	feedErr.send(t, "connection reset by peer")

	/*
	 * ⚠️ BEKLENECEK BİR ÇIKTI YOK — satır zaten kayda GİRMEMİŞ olmalı;
	 * girmesi ancak kapanıştaki boşaltmayla oluyor. O yüzden burada
	 * ölçülen şey aynı zamanda boşaltmanın SIRASI: Run dönmeden yazılmalı,
	 * yoksa mührün ve kaydın dışında kalır.
	 */
	stop()

	if out := cast(); !strings.Contains(out, "target wrote: connection reset by peer") {
		t.Errorf("satır sonu görmeyen cümle kayda girmemiş:\n%s", out)
	}
}

/*
 * ⚠️ KABUK KAYDI HAM KALIYOR — ve bu bir tercih, unutulmuş bir dal değil.
 *
 * Kabuk ya da exec kanalında kaydın var olma sebebi kullanıcının
 * GÖRDÜĞÜNÜ yeniden üretmek: renk, imleç, ilerleme çubuğu dahil. Orada
 * stderr'i tek başına temizlemek hiçbir şey satın almaz — aynı diziyi
 * stdout'tan yazmak serbest ve o akış zaten ham kaydediliyor — ama
 * kaydın sadakatini bozar. Ayrım kaydın NE OLDUĞUNA göre: SFTP'de
 * anlatı, kabukta ekran kaydı.
 */
func TestShellStderrStaysVerbatimInTheRecording(t *testing.T) {
	feedErr, cast, stop := castSession(t, false)

	feedErr.send(t, "\x1b[31mred\x1b[0m\n")

	waitForCast(t, cast, "[31mred")
	stop()

	out := cast()
	if !strings.Contains(out, `[31mred`) {
		t.Errorf("kabuk kaydı hedefin çıktısını olduğu gibi taşımıyor:\n%s", out)
	}
	if strings.Contains(out, "target wrote:") {
		t.Errorf("kabuk kaydına SFTP anlatısı karışmış:\n%s", out)
	}
}
