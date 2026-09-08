package proxy

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/record"
	"github.com/Warewave-Technology/postern/internal/sftpaudit"
)

// requestSender, üzerine request gönderilebilen uç (ssh.Channel bunu sağlar).
// Ayrı arayüz olması test içindir: forwardRequest'i gerçek bağlantı kurmadan
// sınayabiliyoruz.
type requestSender interface {
	SendRequest(name string, wantReply bool, payload []byte) (bool, error)
}

/*
 * OwnWriter, postern'in KENDİ ürettiği baytları hedefinkilerden ayırt
 * edilebilir biçimde taşıyabilen istemci ucu.
 *
 * ⚠️ NEDEN VAR: postern reddettiği isteğe kendi SFTP cevabını yazıyor ve
 * kullanıcıya kendi gerekçesini stderr'den söylüyor — ama hedefin cevabı
 * da, stderr'i de AYNI iki akıştan geçiyor. İstemci ikisini yalnızca
 * metne bakarak ayırmaya çalışırsa, ayrımı hedef yazıyor demektir:
 * "postern: " diye başlayan bir hedef mesajı, bastion'ın cümlesi diye
 * okunur. Köken, yazan yerin SEÇTİĞİ bir şey olmalı.
 *
 * ⚠️ İSTEĞE BAĞLI, ZORUNLU DEĞİL. Gerçek bir ssh.Channel bunu
 * karşılayamaz: SSH'ta CHANNEL_DATA ve EXTENDED_DATA dışında akış yok ve
 * uydurmak protokolü bozardı. O uçta düz Write'a düşüyoruz — yani bir
 * `sftp` istemcisi ayrımı GÖREMİYOR ve bu sınır burada yazılı. Panelin
 * kendi taşıması var (httpapi/wschannel.go, akış etiketi).
 */
type OwnWriter interface {
	WriteOwn(p []byte) (int, error)
	WriteOwnStderr(p []byte) (int, error)
}

// Broker, bir kullanıcı kanalı (down) ile bir hedef kanalı (up) arasında
// veriyi ve request'leri iki yönde taşır.
type Broker struct {
	down  ssh.Channel
	downR <-chan *ssh.Request
	up    ssh.Channel
	upR   <-chan *ssh.Request

	// rec nil olabilir: kayıt kapalıysa broker aynen çalışmaya devam eder.
	// Sahipliği çağırana aittir — Close'u handleChannel çağırır, broker değil
	// (kayıt oturumdan uzun yaşayabilir: başlık zaten yazıldı, kapanışta
	// kuyruklar boşaltılacak).
	rec *record.Writer

	// recordInput, girdi akışının da kayda tee'lenip tee'lenmeyeceğini söyler.
	// ⚠️ VARSAYILAN KAPALI (config record_input: false): kullanıcının yazdığı
	// her şey girdidir — sudo parolası dahil.
	recordInput bool

	// policy, hangi request'lerin köprüden geçeceğini söyler (requests.go).
	policy RequestPolicy

	// idle nil olabilir: boşta kalma sınırı kapalıysa sarmalayıcı yok.
	idle *idleGuard

	/*
	 * castMu/castEvents/castDigest, SFTP olaylarının oturum KAYDINA
	 * yazılmasının durumu.
	 *
	 * ⚠️ SİNK'İN İÇİNDE DEĞİL, BROKER'DA — ve bu bir düzeltme. İlk hâli
	 * kayıt satırını sftpJournal.Emit'e koyuyordu; o katman depoyla
	 * ilgili, kayıtla değil. Sonuç: başka bir sink takılan her yerde
	 * (testler dahil) oturum sessizce mühürsüz kalıyordu. `b.rec`'in
	 * sahibi broker, dolayısıyla sarmalanacak yer de burası —
	 * chainWriter'ın "kanca koymak yerine sarmala" gerekçesinin aynısı.
	 */
	castMu     sync.Mutex
	castEvents int64
	castDigest [sha256.Size]byte

	// sftpSink nil olabilir: SFTP kapalıysa denetim de kurulmuyor ve
	// süzgeç subsystem'i zaten reddediyor.
	sftpSink SFTPSink

	// castErr, hedefin stderr'inin KAYDA giden kopyası; kayıt kapalıysa
	// nil (bkz. sftpcast.go, castStderr).
	castErr *castStderr

	/*
	 * onDeny, postern'in KENDİ reddettiği bir istek için çağrılıyor.
	 *
	 * ⚠️ NEDEN AYRI BİR KANCA, sftpSink DEĞİL. Günlükçü yalnızca
	 * AllowSFTP açıkken kuruluyor (lifecycle.go) — ve kaydetmek
	 * istediğimiz ret tam olarak KAPALIYKEN oluyor. Sink üzerinden
	 * yazmak, kaydedilecek tek durumda sink'in var olmaması demekti.
	 */
	onDeny func(reqType, reason string)

	/*
	 * sftpPolicy, SFTP isteklerine karar veren politika. nil ise hiçbir
	 * istek reddedilmiyor ve veri yolu bu özellik eklenmeden önceki gibi
	 * çalışıyor.
	 */
	sftpPolicy sftpaudit.Decider

	/*
	 * sftpReadOnly, bu kanalın hedefte hiçbir şeyi değiştiremeyeceği.
	 *
	 * ⚠️ KANALA AİT, KULLANICIYA DEĞİL. Rolün yazma hakkı olabilir;
	 * kısıt kanalın ne için açıldığından geliyor — panelin dosya
	 * tarayıcısı gibi.
	 */
	sftpReadOnly bool
	// sftp, kanal SFTP'ye geçtiğinde dolan çözümleyici (sftp.go).
	sftp sftpState
	// abortOnce, denetim çökünce kanalı bir kez kapatmak için.
	abortOnce sync.Once
	/*
	 * aborted, Run'a "hemen dön" diyen sinyal.
	 *
	 * ⚠️ KANALLARI KAPATMAK YETMİYOR — ölçüldü. Run, ctx ile üç
	 * goroutine'in bitişi arasında seçim yapıyor; o üçlünün içinde
	 * hedeften gelen request'leri dinleyen döngü de var ve o döngü
	 * ancak karşı taraf kanalı kapatınca bitiyor. Yalnızca Close
	 * çağıran bir sonlandırma, denetim çökmüşken oturumu akmaya devam
	 * ettiriyordu.
	 */
	aborted chan struct{}

	/*
	 * startGate, istemciden gelen VERİNİN, oturumu başlatan isteğin
	 * işlenmesini beklediği kapı.
	 *
	 * ⚠️ NEDEN VAR — ÖLÇÜLEN AÇIK. SFTP çözümleyicisi `subsystem sftp`
	 * İŞLENDİĞİNDE kuruluyor, kanal AÇILDIĞINDA değil. İstek goroutine'i
	 * tek ve sıralı; istemci önüne geçerli başka bir istek koyarsa
	 * (`pty-req` yetiyor) kurulum o isteğin hedef gidiş-dönüşü kadar
	 * gecikiyor. O aralıkta gelen baytlar hedefte çalışıp denetime HİÇ
	 * girmiyordu — TestPacketsBehindAnEarlierRequestAreAudited bunu
	 * kapı yokken sıfır olayla gösteriyor.
	 *
	 * ⚠️ TAMPON DEĞİL, BLOKLAMA. Baytları biriktirmek sınırsız bellek
	 * demekti; yazmayı bekletmek SSH penceresini doldurup istemciyi
	 * kendiliğinden durduruyor. Bellek maliyeti sıfır, sıra korunuyor:
	 * baytlar isteğin ARDINDAN, aynı sırayla gidiyor.
	 *
	 * ⚠️ KANAL TEMBEL KURULUYOR, KURUCUDA DEĞİL. Broker'ı elle kuran
	 * testler var (requests_test.go); New'e bağlasaydık onlarda kanal nil
	 * kalır ve close(nil) panik ederdi. Daha kötüsü: nil kanaldan okuma
	 * sonsuza kadar bloke eder, yani sessiz bir kilitlenme. gate() her
	 * çağırana aynı kanalı veriyor, nasıl kurulmuş olursa olsun.
	 */
	/*
	 * downMu, İSTEMCİYE giden veri akışını seri hâle getiriyor.
	 *
	 * ⚠️ NEDEN GEREKLİ: postern bazen istemciye kendi cevabını yazıyor
	 * (reddedilen SFTP istekleri). O yazma, hedeften gelen baytları
	 * aktaran goroutine ile çakışamaz — ve daha önemlisi, gerçek bir
	 * paketin ORTASINA düşemez. Kilit, yazma ile çözümlemeyi TEK PARÇA
	 * hâline getiriyor: kilidi alan biri, "son parça hem yazıldı hem
	 * çözümlendi" durumunu görüyor, arada kalmış bir anı değil.
	 */
	downMu sync.Mutex
	/*
	 * injectQ, istemciye gönderilmeyi bekleyen kendi cevaplarımız.
	 *
	 * ⚠️ KUYRUK VAR ÇÜNKÜ BEKLEMEK İSTEMİYORUZ. Ret anında hedef akışı
	 * paketin ortasındaysa cevabı yazamıyoruz; bir goroutine'i orada
	 * bekletmek, hedef susarsa sonsuza kadar asılı kalan bir goroutine
	 * demekti. Bunun yerine sıraya koyuluyor ve hedef yönü bir sonraki
	 * paket sınırına vardığında boşaltılıyor.
	 */
	injectQ []sftpaudit.Denial
	// injectMu, YALNIZCA kuyruğu koruyor.
	//
	// ⚠️ downMu'DAN AYRI OLMAK ZORUNDA. Retleri sıraya koyan goroutine,
	// istemciye yazan goroutine'in kilidini beklememeli: o yazma ağ
	// üzerinde bloke olabiliyor ve bekleyen goroutine istemciden OKUYAN
	// goroutine'in ta kendisi. Okumayı durdurmak, istemcinin yazmalarını
	// da durdurup ikisini birbirine kilitlerdi.
	/*
	 * noticeMu, kullanıcıya yazılan ret satırlarını koruyor.
	 *
	 * ⚠️ downMu'DAN AYRI: stderr farklı bir SSH mesaj türü ve veri
	 * akışının paket sınırlarıyla ilgisi yok. Aynı kilide bağlamak,
	 * insana bir cümle yazmayı veri akışının sırasına bağlamak olurdu.
	 */
	noticeMu      sync.Mutex
	notices       map[string]bool
	noticesCapped bool

	injectMu  sync.Mutex
	injectSig chan struct{}

	injectInit sync.Once
	gateInit   sync.Once
	gateOnce   sync.Once
	startGate  chan struct{}

	// abortErr, denetimi çökerten sebep. Run bunu döndürüyor.
	abortErr error

	/*
	 * answering, İSTEMCİDEN gelen bir isteğin cevaplanmasıyla kapanışın
	 * çakışmasını engelliyor.
	 *
	 * ⚠️ ÖLÇÜLDÜ, tahmin değil: `echo hello` gibi anında biten bir
	 * komutta hedef, biz istemciye "exec kabul edildi" cevabını
	 * geçirmeye fırsat bulmadan çıktısını yazıyor, exit-status'ü
	 * gönderiyor ve kanalı kapatıyor. Beklenen üç akış da bittiği için
	 * Run kapanışa geçiyor ve b.down.Close(), istemcinin kanalını exec
	 * cevabı yoldayken kesiyordu.
	 *
	 * İstemci tarafındaki görüntüsü: KOMUT ÇALIŞMIŞ ve çıktısı kanala
	 * YAZILMIŞ olmasına rağmen `sess.Output` → EOF. Yani aslında
	 * başarılı olan bir komut, ağ arızasından ayırt edilemeyen bir
	 * kopuşa dönüşüyor.
	 *
	 * Yarış, cevabı gönderen goroutine'in Run'ın beklediği üçlünün
	 * DIŞINDA olmasından geliyor ve o bilinçli (bkz. Run: sessiz bir
	 * istemci oturumu sonsuza kadar açık tutmasın). Kilit o goroutine'in
	 * bitmesini beklemiyor, yalnızca ELİNDEKİ isteği bitirmesini.
	 */
	answering sync.Mutex

	logger *slog.Logger
}

// New wires an inbound channel to an outbound one.
//
// rec nil geçilebilir (kayıt kapalı). recordInput yalnızca config açıkça
// istediğinde true olmalı.
func New(down ssh.Channel, downR <-chan *ssh.Request, up ssh.Channel, upR <-chan *ssh.Request, rec *record.Writer, recordInput bool, policy RequestPolicy, logger *slog.Logger) *Broker {
	b := &Broker{down: down, downR: downR, up: up, upR: upR, rec: rec,
		recordInput: recordInput, policy: policy, logger: logger,
		aborted: make(chan struct{})}
	/*
	 * ⚠️ KAYIT KOPYASI BURADA KURULUYOR, boru hattında değil. Run onu
	 * kapanışta boşaltıyor; goroutine içinde kurulsaydı Run'ın okuduğu
	 * alan bir veri yarışı olurdu.
	 */
	if rec != nil {
		b.castErr = newCastStderr(b)
	}

	return b
}

// injectSignal, enjektörü uyandıran kanal; ilk çağıran kuruyor.
func (b *Broker) injectSignal() chan struct{} {
	b.injectInit.Do(func() { b.injectSig = make(chan struct{}, 1) })
	return b.injectSig
}

// pokeInjector, enjektöre "bir şey değişti, dene" der. Bloke etmiyor.
func (b *Broker) pokeInjector() {
	select {
	case b.injectSignal() <- struct{}{}:
	default:
	}
}

/*
 * queueRefusals, postern'in kendi cevaplarını sıraya koyar.
 *
 * ⚠️ BURADA İSTEMCİYE YAZILMIYOR. Yazmak, istemciden okuyan goroutine'i
 * bir ağ yazmasının arkasında bekletirdi; okumayı durdurmak istemcinin
 * yazmalarını da durdurur ve iki yön birbirini kilitlerdi. Yazma işi
 * kendi goroutine'inde.
 */
func (b *Broker) queueRefusals(pkts []sftpaudit.Denial) {
	b.injectMu.Lock()
	b.injectQ = append(b.injectQ, pkts...)
	b.injectMu.Unlock()

	b.pokeInjector()
}

/*
 * tryInject, hedef akışı paket SINIRINDAYSA bekleyen cevapları yazar.
 *
 * ⚠️ SINIR ŞART. Gerçek bir paketin ortasına yazmak, istemcinin
 * çözümleyicisinde o paketi ikiye böler ve sonraki her bayt kayar.
 * Sınırda değilsek kuyruk duruyor; hedef bir sonraki paketi bitirince
 * yeniden çağrılıyoruz.
 */
func (b *Broker) tryInject() {
	s := b.sftp.Load()
	if s == nil {
		return
	}

	b.injectMu.Lock()
	empty := len(b.injectQ) == 0
	b.injectMu.Unlock()
	if empty {
		return
	}

	b.downMu.Lock()
	defer b.downMu.Unlock()

	if !s.TargetAtBoundary() {
		return
	}

	b.injectMu.Lock()
	q := b.injectQ
	b.injectQ = nil
	b.injectMu.Unlock()

	for _, d := range q {
		/*
		 * ⚠️ KENDİ CEVABIMIZ KENDİ ETİKETİYLE ÇIKIYOR. Bu paketi hedef
		 * DEĞİL postern üretti; istemcinin bunu paketin İÇİNDEKİ metne
		 * bakarak anlaması gerekseydi, ayrımı hedef yazabilirdi.
		 */
		if _, err := b.writeOwn(d.Status); err != nil {
			/*
			 * Yazılamadıysa kanal zaten kopuyor. Oturumu burada
			 * bitirmiyoruz: ret UYGULANDI, iletilemeyen şey yalnızca
			 * gerekçesi. Denetim satırı zaten yazılı.
			 */
			b.logger.Error("refusal reply not delivered to the client", "error", err)
			return
		}
		b.tellUser(d.Notice)
	}
}

/*
 * tellUser, reddin gerekçesini KULLANICIYA yazar — stderr'den.
 *
 * ⚠️ NEDEN VERİ AKIŞINDAN DEĞİL: stderr ayrı bir SSH mesaj türü
 * (EXTENDED_DATA), dolayısıyla SFTP çerçevelemesini bozamıyor ve paket
 * sınırı beklemek gerekmiyor. sayGoodbye'ın "SFTP açıkken insan cümlesi
 * yazma" kuralı VERİ akışı için doğru; burası o akış değil.
 *
 * ⚠️ NEDEN GEREKLİ: OpenSSH'in sftp istemcisi STATUS'un mesaj alanını hiç
 * okumuyor ve başarısız bir stat'ı "not found" diye yazıyor. Reddi
 * uygulamak ve deftere yazmak yetmiyor; engellenen kişi engellendiğini
 * BİLMELİ, yoksa yazım hatası sanıp varyasyonlarla denemeye devam eder.
 *
 * ⚠️ TEKRARLAR BASTIRILIYOR VE TOPLAM SINIRLI. Tek bir `get`, stat ve
 * open olmak üzere iki ret üretebiliyor; `mget *` yüzlerce. Aynı satırı
 * iki kez yazmak gürültü, sınırsız yazmak ise kullanıcının terminalini
 * bizim doldurmamız olurdu.
 */
func (b *Broker) tellUser(line string) {
	if line == "" {
		return
	}

	b.noticeMu.Lock()
	defer b.noticeMu.Unlock()

	if b.notices == nil {
		b.notices = map[string]bool{}
	}
	if b.notices[line] {
		return
	}
	if len(b.notices) >= maxRefusalNotices {
		if !b.noticesCapped {
			b.noticesCapped = true
			_, _ = b.writeOwnStderr([]byte("postern: further refusals are not shown\r\n"))
		}
		return
	}
	b.notices[line] = true

	// Yazma hatası yutuluyor: kanal kopuyorsa söylenecek bir şey kalmadı
	// ve ret zaten uygulandı.
	_, _ = b.writeOwnStderr([]byte(line + "\r\n"))
}

/*
 * writeOwn ve writeOwnStderr, postern'in KENDİ cümlesini yazar.
 *
 * ⚠️ ARAYÜZÜ KARŞILAMAYAN UÇTA DÜZ YAZMAYA DÜŞÜYOR — sessizce ve
 * bilerek. Gerçek bir SSH kanalında taşınacak bir köken alanı yok;
 * orada reddin İLETİLMESİ, ayırt edilebilir olmasından önce gelir.
 * Kaybolan tek şey ayrım ve o sınır OwnWriter'ın başında yazılı.
 */
func (b *Broker) writeOwn(p []byte) (int, error) {
	if w, ok := b.down.(OwnWriter); ok {
		return w.WriteOwn(p)
	}

	return b.down.Write(p)
}

func (b *Broker) writeOwnStderr(p []byte) (int, error) {
	if w, ok := b.down.(OwnWriter); ok {
		return w.WriteOwnStderr(p)
	}

	return b.down.Stderr().Write(p)
}

/*
 * injector, bekleyen retleri istemciye ulaştıran goroutine.
 *
 * ⚠️ AYRI BİR GOROUTINE OLMAK ZORUNDA. Reddi veren goroutine istemciden
 * OKUYAN goroutine; ona yazdırmak, okumayı bir ağ yazmasının arkasında
 * durdurup iki yönü birbirine kilitlerdi.
 *
 * ⚠️ WaitGroup İÇİNDE. İstemciye yazan herkes, kanal kapanmadan önce
 * bitmiş olmalı (bkz. TestUnansweredCloseHoldsTwoGoroutines çevresi).
 */
func (b *Broker) injector(ctx context.Context, stop <-chan struct{}) {
	sig := b.injectSignal()

	for {
		select {
		case <-sig:
			b.tryInject()
		case <-stop:
			return
		case <-b.aborted:
			return
		case <-ctx.Done():
			return
		}
	}
}

/*
 * maxRefusalNotices, bir oturumda kullanıcıya yazılacak en fazla FARKLI
 * ret satırı.
 *
 * Politikayla çakışan bir istemci (`mget *`) yüzlerce ret üretebiliyor;
 * hepsini yazmak kullanıcının terminalini bizim doldurmamız olurdu.
 * Yirmi farklı yol, neyin engellendiğini anlamaya fazlasıyla yetiyor ve
 * defterin tamamı zaten yerinde duruyor.
 */
const maxRefusalNotices = 20

// gate, başlangıç kapısını verir; ilk çağıran kuruyor.
func (b *Broker) gate() chan struct{} {
	b.gateInit.Do(func() { b.startGate = make(chan struct{}) })
	return b.startGate
}

// openStartGate, park etmiş istemci yazıcılarını serbest bırakır. Bir kez.
func (b *Broker) openStartGate() { b.gateOnce.Do(func() { close(b.gate()) }) }

// WithSFTP, SFTP denetim hedefini bağlar.
//
// Ayrı bir kurucu yerine ayarlayıcı olması bilinçli: SFTP kapalıyken
// (varsayılan) çağıranların hiçbiri değişmiyor.
func (b *Broker) WithSFTP(sink SFTPSink) *Broker {
	b.sftpSink = sink
	return b
}

// WithSFTPReadOnly, kanalı salt-okunur yapar.
//
// ⚠️ SUNUCU TARAFINDA, İSTEMCİDE DEĞİL. "Salt-okunur" panelin
// JavaScript'inde yaşasaydı, çalınmış bir oturum FXP_WRITE'ı elle yazar
// ve kısıt hiç var olmamış olurdu.
func (b *Broker) WithSFTPReadOnly(on bool) *Broker {
	b.sftpReadOnly = on
	return b
}

// WithSFTPPolicy, SFTP isteklerine karar verecek politikayı kurar.
//
// ⚠️ WithSFTP'DEN ÖNCE YA DA SONRA ÇAĞRILABİLİR; politika oturum
// KURULURKEN okunuyor (beginSFTP), kanal açılırken değil.
func (b *Broker) WithSFTPPolicy(d sftpaudit.Decider) *Broker {
	b.sftpPolicy = d
	return b
}

// WithDenyLog, reddedilen istekleri deftere yazacak geri çağrıyı kurar.
func (b *Broker) WithDenyLog(fn func(reqType, reason string)) *Broker {
	b.onDeny = fn
	return b
}

// outputSink returns where target→user bytes should be written: the user's
// channel alone, or that channel tee'd into the recording.
func (b *Broker) outputSink() io.Writer {
	return b.idle.wrap(b.tap(b.down, b.recStream(true), fromTarget))
}

// inputSink is the same for user→target bytes, gated by recordInput.
func (b *Broker) inputSink() io.Writer {
	var rec io.Writer
	if b.rec != nil && b.recordInput {
		rec = b.rec.InputStream()
	}
	return b.idle.wrap(b.tap(b.up, rec, fromClient))
}

/*
 * stderrSink returns where target→user stderr should be written: the
 * user's channel alone, or that channel tee'd into the recording.
 *
 * ⚠️ stderr ÇÖZÜMLENMİYOR: SFTP protokolü stderr üzerinde akmaz. Buraya
 * hedefin uyarı metinleri düşer ve onlar kayda ait.
 *
 * ⚠️ KULLANICIYA GİDEN KOPYA HAM, KAYDA GİRENİ DEĞİL — ve ikisi ayrı
 * sorunun cevabı. Kullanıcının ucundaki şey hedefin kendi akışı; onu
 * kırpmak, `sftp`nin gösterdiği hata metnini bozmak olurdu. Kayda giren
 * kopya ise ileride BAŞKA BİRİNİN, başka bir terminalde oynatacağı şey
 * (bkz. sftpcast.go, castStderr).
 */
func (b *Broker) stderrSink() io.Writer {
	if b.rec == nil {
		return b.idle.wrap(b.down.Stderr())
	}

	return b.idle.wrap(io.MultiWriter(b.down.Stderr(), b.castErr))
}

// recStream, kayıt akışını döner (kapalıysa nil).
func (b *Broker) recStream(output bool) io.Writer {
	if b.rec == nil {
		return nil
	}
	if output {
		return b.rec.OutputStream()
	}
	return b.rec.InputStream()
}

// tap, veri yoluna kopya alıcıyı takar.
//
// SFTP hiç kurulmamışsa (sftpSink nil) fazladan katman koymuyoruz:
// varsayılan yol, bu özellik eklenmeden önceki yolla aynı kalıyor.
func (b *Broker) tap(dst io.Writer, rec io.Writer, dir direction) io.Writer {
	if b.sftpSink == nil {
		if rec != nil {
			return io.MultiWriter(dst, rec)
		}
		return dst
	}
	return &sftpTap{dst: dst, rec: rec, dir: dir, b: b}
}

/*
 * sayGoodbye, oturumu BİZİM kapattığımız durumlarda kullanıcıya tek
 * satırlık sebebi yazar.
 *
 * ⚠️ AYNI CÜMLE KAYDA DA GİRİYOR. Yalnızca kanala yazsaydık, oynatılan
 * .cast'te oturum ortasından kesilmiş görünürdü ve olayı sonradan
 * inceleyen kişi "burada ne oldu" sorusunu kayıttan cevaplayamazdı.
 * outputSink zaten hedeften gelen baytları kayda tee'liyor; bu satır da
 * oradan geçiyor ki sıra bozulmasın.
 *
 * ⚠️ SEBEP YOKSA SESSİZ. Kullanıcı `exit` yazdığında veda etmek gürültü
 * olurdu; yazdığımız yalnızca BİZİM aldığımız kararlar.
 *
 * ⚠️ BU SATIR KÖKEN ETİKETİ TAŞIMIYOR (writeOwn kullanmıyor) ve bu bir
 * eksik değil. İki sebebi var: satır outputSink'ten geçiyor ki AYNI SIRAYLA
 * kayda da girsin, ve buraya yalnızca SFTP OLMAYAN bir kanalda geliniyor
 * (aşağıdaki kapı). Kabuk kanalında ayrımın alıcısı yok — terminal baytları
 * çiziyor ve hedefin stdout'u da aynı cümleyi zaten yazabilir; etiket orada
 * hiçbir şey satın almaz.
 */
func (b *Broker) sayGoodbye(ctx context.Context) {
	var line string
	switch cause := context.Cause(ctx); {
	case cause == nil:
		return
	case errors.Is(cause, ErrTerminated):
		line = "session closed by an administrator"
		if who, ok := TerminatedBy(cause); ok && who != "" {
			line += " (" + who + ")"
		}
	case errors.Is(cause, ErrShuttingDown):
		// ⚠️ "Bir yönetici kesti" DEMİYOR. Bir dağıtım gecesi herkese
		// yapılmamış bir kesme bildirmek, hem kullanıcıyı yanlış yere
		// baktırır hem denetim defterini kirletir.
		line = "session closed: this bastion is shutting down"
	case errors.Is(cause, ErrIdleTimeout):
		line = "session closed: idle too long"
	case errors.Is(cause, ErrMaxLifetime):
		line = "session closed: maximum session lifetime reached"
	case errors.Is(cause, ErrRecordingFailed):
		// ⚠️ ARIZANIN AYRINTISI KULLANICIYA GİTMİYOR: disk yolu ve
		// hata metni bastion'ın içine dair. Kullanıcının bilmesi
		// gereken, kendi hatası olmadığı.
		line = "session closed: this bastion could not keep recording it"
	default:
		return
	}

	/*
	 * ⚠️ SFTP OTURUMUNA VEDA YAZILMIYOR — VE BU BİR DÜZELTME.
	 *
	 * Mesaj outputSink() üzerinden gidiyor; o sink hedef yönündeki
	 * sftpTap'i sarıyor ve tap, SFTP oturumu açıkken yazılan HER baytı
	 * `sftpaudit.Session.FromTarget`e besliyor. finishSFTP() oturumu
	 * bitiriyor ama `b.sftp`yi TEMİZLEMİYOR, dolayısıyla bu satır
	 * çözümleyiciye hedeften gelmiş bir paketmiş gibi giriyordu:
	 * bozuk bir uzunluk başlığı → abortAudit → "sftp audit failed;
	 * ending session".
	 *
	 * İki yanlış birden üretiyordu. Denetim defterinde ve log'da,
	 * denetim ÇALIŞMIŞKEN "denetim çöktü" yazıyordu; ve oturumun
	 * bitiş sebebi "yönetici kapattı" yerine "denetim arızası"na
	 * dönüşüyordu (Run, abortErr'i döndürüyor). Yani yöneticinin kendi
	 * bastığı düğme, kayda bir arıza olarak geçiyordu.
	 *
	 * Yazmamak zaten doğrusu: karşı taraf bir `sftp` istemcisi, ikili
	 * protokol okuyor. Ona insan cümlesi göndermek okunabilir bir
	 * uyarı değil, protokol akışına çöp enjekte etmek olurdu. Sebep
	 * kaybolmuyor — Run onu çağırana döndürüyor ve oturum kaydına
	 * lifecycle yazıyor.
	 */
	if b.sftp.Load() != nil {
		return
	}

	// \r\n: ham kipteki bir terminalde tek \n satırı kaydırmaz.
	msg := []byte("\r\npostern: " + line + "\r\n")

	// Yazma hatası yutuluyor: karşı taraf çoktan gitmiş olabilir ve
	// bu, kapanışı geciktirecek bir sebep değil.
	_, _ = b.outputSink().Write(msg)
}

// Run shuttles data and requests until the session ends, then returns.
func (b *Broker) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	wgCloseSignal := make(chan struct{})
	wg.Add(3)

	/*
	 * ⚠️ BU İKİSİ WaitGroup DIŞINDA ve bu bilinçli — aşağıdaki
	 * relayRequests(b.up, b.downR, ...) da öyle.
	 *
	 * İkisi de İSTEMCİDEN okuyor. Beklemeye alsaydık, hiçbir şey
	 * yazmayan bir istemci oturumun hiç bitmemesi demek olurdu:
	 * kullanıcı çıksa, hedef kapatsa, yönetici kessin — Run yine de
	 * istemcinin bir tuşa basmasını beklerdi.
	 *
	 * ⚠️ BEDELİ ÖLÇÜLDÜ: kendi Close()'umuz kendi Read'imizi
	 * uyandırmıyor (x/crypto channel.go — close mesajı gönderiliyor,
	 * okuyucuyu serbest bırakan ch.close() ise karşı taraftan close
	 * ALINDIĞINDA çalışıyor). Yani bu ikisi, istemci close'a cevap
	 * verene ya da TCP ölene kadar yaşıyor.
	 *
	 * ⚠️ SINIR max_channels_per_conn DEĞİL — ve burada öyle yazıyordu.
	 * O ayar EŞZAMANLI kanalı sayıyor ve sayaç kanal kapanınca azalıyor
	 * (sshd/server.go), yani aynı bağlantı üzerinde SIRAYLA açılıp
	 * kapanan kanalların sayısına bir sınır yok. Biten her kanal, cevap
	 * vermeyen bir istemcide bu iki goroutine'i bırakıyor ve
	 * birikiyorlar — ölçüldü: TestSequentialChannelsAccumulateHeldGoroutines.
	 *
	 * Gerçek sınır: max_conns × (bağlantı ömrü boyunca açılan kanal
	 * sayısı), ve ikinci çarpan istemcinin elinde. Bağlantı ölünce
	 * hepsi serbest kalıyor, yani kalıcı bir sızıntı değil; ama
	 * "sınırsız değil" demek için fazla iyimser.
	 *
	 * Düzeltmek ürünün en kritik veri yolunu yeniden kurmayı
	 * gerektirirdi (cevapsız close'da okuyucuyu uyandırmak); sınırı
	 * DOĞRU bilmek ve yazmak şimdilik doğru karşılık. İkinci ölçüm:
	 * TestUnansweredCloseHoldsTwoGoroutines.
	 */
	go func() {
		n, err := pipe(b.inputSink(), b.down, b.up)
		if err != nil {
			b.logger.Error("down->up pipe failed",
				"error", err,
				"count", n,
			)
		}
	}()

	go func() {
		defer wg.Done()

		n, err := pipe(b.outputSink(), b.up, nil)
		if err != nil {
			b.logger.Error("up->down pipe failed",
				"error", err,
				"count", n,
			)
		}
	}()

	go func() {
		defer wg.Done()

		n, err := pipe(b.stderrSink(), b.up.Stderr(), nil)
		if err != nil {
			b.logger.Error("up.stderr->down.stderr pipe failed",
				"error", err,
				"count", n,
			)
		}
	}()

	go func() {
		defer wg.Done()

		b.relayRequests(b.down, b.upR, fromTarget, false)
	}()
	/*
	 * ⚠️ ENJEKTÖR wg'NİN DIŞINDA, ve bu bir zorunluluk. wgCloseSignal
	 * "veri goroutine'leri bitti" demek; enjektör de onu beklediği için
	 * içine koymak dairesel bir bekleme yaratıyordu — wgCloseSignal
	 * enjektörü, enjektör kapanış sinyalini bekliyordu ve Run hiç
	 * dönmüyordu. (Ölçüldü: üç test aynı anda "Run dönmedi" dedi.)
	 *
	 * Yine de istemci kanalı kapanmadan ÖNCE bitmiş olmak zorunda; o
	 * yüzden kendi durdurma kanalı ve kendi beklemesi var.
	 */
	injStop := make(chan struct{})
	injDone := make(chan struct{})
	go func() {
		defer close(injDone)

		b.injector(ctx, injStop)
	}()

	go b.relayRequests(b.up, b.downR, fromClient, true)

	go func() {
		wg.Wait()
		close(wgCloseSignal)
	}()

	// graceful, oturumun kendi kendine bittiğini söylüyor (hedef kapattı
	// ya da kullanıcı çıktı) — zorla kesilmedi. Aşağıdaki bekleme
	// yalnızca bu dalda güvenli.
	var graceful bool
	select {
	case <-ctx.Done():
	case <-wgCloseSignal:
		graceful = true
	case <-b.aborted:
	}

	// ⚠️ Kapanış SIRASI: önce yarım kalan transferler yazılıyor. Kanal
	// kapandıktan sonra yazmaya kalksaydık, koparılmış bir transferin
	// izi kaybolurdu — yani veriyi çekip bağlantıyı koparmak, denetimden
	// kaçmanın yolu olurdu.
	/*
	 * ⚠️ KAPI KAPANIŞTA DA AÇILIYOR. Oturumu başlatan istek hiç gelmediyse
	 * (yalnızca veri yazan bir istemci) park etmiş yazıcı orada kalırdı.
	 * finishSFTP'den ÖNCE açılıyor ki uyanan baytlar çözümleyiciye girsin
	 * ve yarım transferin izi onları da kapsasın.
	 */
	b.openStartGate()
	b.finishSFTP()

	/*
	 * ⚠️ ENJEKTÖR BURADA DURUYOR — istemci kanalına yazan herkes, kanal
	 * kapanmadan önce bitmiş olmalı.
	 */
	close(injStop)
	<-injDone

	/*
	 * ⚠️ SON BİR DENEME. Enjektör ctx ile birlikte durdu; sıraya girmiş
	 * ama iletilememiş bir ret varsa istemci onu hiç görmeyecek. Denemek
	 * bedava, denememek istemciyi cevapsız bırakmak.
	 */
	b.tryInject()
	b.injectMu.Lock()
	if n := len(b.injectQ); n > 0 {
		b.logger.Error("refusals never reached the client", "count", n)
	}
	b.injectMu.Unlock()

	// ⚠️ KULLANICI NEDEN KESİLDİĞİNİ ÖĞRENMELİ. Sessizce kopan bir
	// oturum, ağ arızasından ayırt edilemez: kullanıcı yeniden bağlanıp
	// aynı işi tekrar dener, yönetici ise "haber verdim" sanır.
	b.sayGoodbye(ctx)

	/*
	 * ⚠️ ÖNCE HEDEF, SONRA İSTEMCİ.
	 *
	 * Sıra tersineydi ve iki sebeple yanlıştı:
	 *
	 *  1. down.Close(), KOVULAN tarafa yazıyor. Ölü ya da tıkalı bir
	 *     istemci bu çağrıyı geciktirdiğinde, hedefteki kabuk o süre
	 *     boyunca yaşamaya devam ediyordu. Yöneticinin kesme düğmesinden
	 *     beklediği tek garanti tam olarak buydu ve sıranın sonundaydı.
	 *
	 *  2. up.Close() hedefteki oturumu bitiren şey (sshd kanal
	 *     kapanınca süreç grubuna HUP gönderiyor). Serbest bırakılması
	 *     asıl önemli olan kaynak UZAKTAKİ; yerel soket ikinci sırada
	 *     beklemeye tahammül edebilir.
	 *
	 * Normal çıkışta da doğru: kullanıcı `exit` yazdığında hedef kanalı
	 * bir an önce kapatmanın zararı yok.
	 */
	b.up.Close()

	/*
	 * ⚠️ İSTEMCİNİN KANALI, CEVABI YOLDAYKEN KAPANMASIN (bkz. answering).
	 *
	 * Boş kritik bölge KASITLI: burada korunacak bir veri yok, beklenecek
	 * bir iş var — kilidi tutan relayRequests'in elindeki isteği
	 * bitirmesi.
	 *
	 * ⚠️ YALNIZCA graceful'DA ve up.Close()'DAN SONRA. İkisi de
	 * beklemenin sonlu olmasının şartı:
	 *
	 *  - graceful, hedefin request akışının kapandığı anlamına geliyor;
	 *    yani karşı taraftan close ALINMIŞ ve bekleyen bir SendRequest
	 *    çoktan serbest kalmış. Kendi Close()'umuzun kendi okumamızı
	 *    uyandırmadığı ölçüldü (yukarıdaki nota bakın) — zorla kesmede
	 *    hedef hâlâ canlı ve sessiz olabilir, orada beklemek yöneticinin
	 *    kesme düğmesini hedefin insafına bırakırdı.
	 *
	 *  - up kapalıyken devam eden forwardRequest hedefi beklemiyor;
	 *    cevap ise istemcinin hâlâ açık olan kanalına yazılıyor.
	 */
	if graceful {
		b.answering.Lock()
		b.answering.Unlock()
	}

	b.down.Close()

	/*
	 * ⚠️ DENETİM ÇÖKTÜĞÜ İÇİN KAPATTIYSAK BUNU SÖYLÜYORUZ.
	 *
	 * ÖLÇÜLEN ARIZA: Run koşulsuz nil dönüyordu, yani iki çağrı
	 * yerindeki `if err := sess.Run(...); err != nil` dalları ÖLÜ
	 * KODDU — hiçbir koşulda çalışmıyorlardı. Bu depodaki tekrar eden
	 * sınıfın tersi: yazılmış ve hiç tetiklenemeyen bir hata yolu.
	 *
	 * Gerçek bir sinyal var ve kayboluyordu: SFTP çözücüsü akışı
	 * anlayamadığında oturumu KASTEN kapatıyoruz (abortAudit) ve bu,
	 * "kullanıcı çıktı" ile karıştırılmaması gereken bir bitiş.
	 *
	 * Kapatma hataları döndürülmüyor: karşı taraf çoktan gitmiş
	 * olabilir ve o gürültü, asıl sinyali gömerdi.
	 *
	 * ⚠️ abortErr YALNIZCA KANALIN KAPANDIĞINI GÖRDÜKTEN SONRA
	 * OKUNUYOR. Alan başka bir goroutine'den yazılıyor (abortAudit) ve
	 * doğrudan okumak veri yarışı olurdu: Run, wgCloseSignal ya da
	 * ctx.Done yoluyla da çıkabiliyor, o yollarda yazma ile okuma
	 * arasında hiçbir sıralama garantisi yok.
	 *
	 * Kapalı bir kanaldan alma, close'dan ÖNCEKİ her yazmayı
	 * görünür kılıyor — abortAudit de abortErr'i close'dan önce
	 * yazıyor. Kapanmamışsa alana hiç dokunmuyoruz.
	 */
	/*
	 * ⚠️ HEDEFİN SON CÜMLESİ, MÜHÜRDEN ÖNCE. Satır sonu görmeden biten
	 * bir stderr satırı tamponda bekliyor olabilir.
	 *
	 * Boşaltma BURADA, stderr goroutine'inde DEĞİL — o goroutine ctx
	 * iptaliyle bitmiyor (hedefin akışını okurken bekliyor) ve Run onu
	 * beklemeden dönüyor. Orada boşaltmak, en çok merak edilen cümleyi —
	 * oturum koparken yazılanı — kaydın dışında bırakırdı.
	 */
	b.flushStderrCast()

	/*
	 * ⚠️ MÜHÜR SATIRI BURADA, Run DÖNMEDEN ÖNCE. Kaydı lifecycle
	 * kapatıyor ve bunu Run döndükten SONRA yapıyor; sıra tersine
	 * dönerse mühür kaydın DIŞINDA kalır ve hiçbir şeyi mühürlemez.
	 *
	 * Oturum bir arızayla bittiyse de yazılıyor: yarım kalmış bir
	 * oturumun kaç olay taşıdığı, tam bitmiş olanınki kadar bir bulgu.
	 */
	b.sealSFTPCast()

	select {
	case <-b.aborted:
		return b.abortErr
	default:
		return nil
	}
}

// relayRequests forwards allowed requests from src to dst, answering the
// sender when it asked for a reply.
//
// Reddedilen request HEDEFE HİÇ GİTMEZ ve gönderene başarısız cevap
// döner — SSH'ta "hayır" demenin yolu bu. WantReply yoksa sessizce
// düşer; gönderen zaten cevap beklemiyor.
func (b *Broker) relayRequests(dst ssh.Channel, src <-chan *ssh.Request, dir direction, observe bool) {
	for req := range src {
		/*
		 * ⚠️ İSTEMCİ YÖNÜ KİLİTLİ İŞLENİYOR: bir isteğin cevabı
		 * gönderilmeden kapanış başlayamasın (bkz. answering).
		 * Reddedilen istekler de dahil — "hayır" da bir cevaptır ve
		 * kaybolursa istemci reddi değil kopuk bir bağlantı görür.
		 *
		 * Hedef yönü kilitlenmiyor: o akış Run'ın beklediği üç
		 * goroutine'den biri, yani kapanıştan zaten önce bitiyor.
		 */
		if dir == fromClient {
			b.answering.Lock()
		}
		b.relayOne(dst, req, dir, observe)
		if dir == fromClient {
			b.answering.Unlock()

			/*
			 * ⚠️ KAPI YALNIZCA HEDEFTE PROGRAM BAŞLATAN İSTEKLERLE
			 * AÇILIYOR — ve bu liste EKSİK OLAMAZ. clientRequests kapalı
			 * bir izin listesi (requests.go); dışındaki her tür zaten
			 * reddedilip hedefe hiç gitmiyor. İzinlilerden
			 * pty-req/window-change/signal/env ve iki OpenSSH uzantısı
			 * program başlatmıyor, dolayısıyla geriye bu üçü kalıyor.
			 *
			 * ⚠️ O LİSTEYE PROGRAM BAŞLATAN YENİ BİR TÜR EKLENİRSE BURASI
			 * DA GÜNCELLENMELİ; yoksa pencere sessizce geri gelir.
			 *
			 * Reddedilen istek de kapıyı açıyor: ret sonrası hedefte
			 * program yok, ama istemci veri göndermeye devam edebilir ve
			 * onu sonsuza kadar park etmenin bir faydası olmazdı.
			 */
			switch req.Type {
			case "shell", "exec", "subsystem":
				b.openStartGate()
			}
		}
	}
}

// relayOne filters one request, forwards it to the far end and sends back
// whatever answer its sender is waiting for.
func (b *Broker) relayOne(dst ssh.Channel, req *ssh.Request, dir direction, observe bool) {
	if ok, reason := b.policy.allow(dir, req); !ok {
		// Warn seviyesi: bu bir teşhis satırı değil, denetim olayı.
		// Operatör "kim sftp denedi" sorusunu buradan cevaplayacak.
		b.logger.Warn("session request denied",
			"direction", dir.String(),
			"req.type", req.Type,
			"reason", reason,
		)

		/*
		 * ⚠️ DEFTERE ÖNCE, CEVAPTAN ÖNCE. İstemciye "hayır" demeden
		 * yazıyoruz ki, ret ile onun izi arasında bir pencere kalmasın.
		 *
		 * ⚠️ YAZILAMAZSA YİNE REDDEDİYORUZ. Kayıt açılamadığında oturumu
		 * reddeden kuralın (proxy.Open) tersi gibi görünüyor ama değil:
		 * orada yazılamayan şey oturumun KENDİSİNİN kanıtı ve devam etmek
		 * kayıtsız erişim demek. Burada eylem zaten REDDETMEK; yazamamak
		 * yüzünden reddetmekten vazgeçmek, denetimi bozan birine kapıyı
		 * açardı. Kayıp "denediğini bilmiyoruz", "girdi" değil — ve o
		 * kayıp log'a Error olarak düşüyor.
		 */
		if b.onDeny != nil {
			b.onDeny(req.Type, reason)
		}

		if req.WantReply {
			if err := req.Reply(false, nil); err != nil {
				b.logger.Debug("request denial reply failed",
					"error", err,
					"req.type", req.Type,
				)
			}
		}
		return
	}

	/*
	 * ⚠️ DENETİM İLETİMDEN ÖNCE KURULUYOR (bkz. beginSFTP).
	 *
	 * Aşağıdaki forwardRequest hedefin cevabını bekliyor ve o sürede
	 * istemcinin baytları çoktan akıyor. Kurulum cevaptan sonra
	 * yapıldığında, boru hattı yapan bir istemcinin ilk SFTP paketleri
	 * denetimsiz geçiyordu.
	 */
	armed := false
	if observe {
		armed = b.beginSFTP(req)
	}

	res, err := forwardRequest(dst, req)
	if err != nil {
		b.logger.Debug("request forward failed",
			"error", err,
			"direction", dir.String(),
			"req.type", req.Type,
		)
	}

	// Hedef subsystem'i kabul etmediyse kurduğumuzu geri alıyoruz.
	if armed && undoArm(req.WantReply, res, err) {
		b.cancelSFTP()
	}

	if observe {
		b.recordResize(req)
		b.recordIntent(req)
	}

	if req.WantReply {
		err = req.Reply(res, nil)
		if err != nil {
			b.logger.Debug("request reply failed",
				"error", err,
				"direction", dir.String(),
				"req.type", req.Type,
			)
		}
	}
}

/*
 * undoArm, kurulan SFTP denetiminin geri alınıp alınmayacağını söyler.
 *
 * ⚠️ AYRI BİR FONKSİYON, ÇÜNKÜ BURADAKİ BİR HATA DENETİMİ KAPATIYOR —
 * ve kapattı. Koşul relayOne'ın içinde yalnızca `!res` diye yazılmıştı;
 * o hâliyle `subsystem sftp` isteğini want_reply=0 ile gönderen bir
 * istemcide denetim kuruluyor ve HEMEN geri alınıyor, istek ise hedefe
 * gidiyordu. Yani denetlenen taraf, tek bir tel bitini düşürerek
 * denetlenmemeyi seçebiliyordu — SFTP denetiminin var olma sebebinin
 * tam tersi. Ölçüldü: gerçek OpenSSH want_reply=0'ı onurlandırıp
 * sftp-server'ı başlatıyor.
 *
 * ⚠️ res, CEVAP İSTEMEDİĞİMİZDE BİLGİ TAŞIMIYOR. x/crypto'da
 * SendRequest, wantReply=false iken hedefte ne olursa olsun
 * `false, nil` ile bitiyor (ssh/channel.go). Sormadığımız sorunun
 * cevabını "hayır" saymak, tam olarak yukarıdaki arızayı üretiyor.
 *
 * Saf ve dışa kapalı olması bilinçli: dört kombinasyonun dördü de
 * doğrudan sınanabiliyor. Köprünün sahte kanalıyla `req.Reply`
 * çağrılamadığı için (gerçek bir bağlantı istiyor) "hedef hayır dedi"
 * hâli uçtan uca kurulamıyor; karar burada olunca ölçülebiliyor.
 */
func undoArm(wantReply, res bool, err error) bool {
	if err != nil {
		return true
	}
	return wantReply && !res
}

// forwardRequest sends req to dst verbatim and reports dst's answer.
func forwardRequest(dst requestSender, req *ssh.Request) (bool, error) {
	return dst.SendRequest(req.Type, req.WantReply, req.Payload)
}

// recordResize mirrors terminal size changes into the recording.
func (b *Broker) recordResize(req *ssh.Request) {
	if b.rec == nil {
		return
	}

	switch req.Type {
	case "pty-req":
		p, err := ParsePty(req.Payload)
		if err != nil {
			b.logger.Error("pty-req parse error",
				"error", err,
				"req.type", req.Type,
			)
			return
		}

		err = b.rec.Resize(b.clampDim(p.Columns, defaultCols), b.clampDim(p.Rows, defaultRows))
		if err != nil {
			b.logger.Error("pty-req resize error",
				"error", err,
				"req.type", req.Type,
			)
		}

		return

	case "window-change":
		p, err := ParseWindowChange(req.Payload)
		if err != nil {
			b.logger.Error("window-change parse error",
				"error", err,
				"req.type", req.Type,
			)
			return
		}

		err = b.rec.Resize(b.clampDim(p.Columns, defaultCols), b.clampDim(p.Rows, defaultRows))
		if err != nil {
			b.logger.Error("window-change resize error",
				"error", err,
				"req.type", req.Type,
			)
		}

		return

	default:
		return
	}
}

// maxTerminalDim, kayda yazılabilecek en büyük terminal boyutu.
//
// 65535, pty'nin kendi sınırı: TIOCSWINSZ'in struct winsize alanları
// 16 bit. Bundan büyük bir değer hedefte zaten temsil edilemez.
const maxTerminalDim = 65535

// Sıfır boyut yerine yazılan asciicast varsayılanları. record.NewWriter
// başlığı da aynı değerlerle kuruyor; ikisi ayrışırsa kayıt kendi
// içinde tutarsız olur.
const (
	defaultCols = 80
	defaultRows = 24
)

// clampDim, istemciden gelen terminal boyutunu kayda yazmadan önce
// sınırlar.
//
// NEDEN: bu sınır yazılana kadar burada düz bir int(p.Columns) vardı ve
// p.Columns istemciden gelen bir uint32'ydi. Kimliği doğrulanmış
// herhangi bir kullanıcı cols=4294967295 gönderip KENDİ denetim
// kaydına "4294967295x4294967295" yazdırabiliyordu — hiçbir terminalin
// olamayacağı bir geometri. Oynatıcılar replay ızgarasını "r"
// olaylarından boyutlandırdığı için, olayı inceleyen bir operatör
// saldırganın zehirlediği oturumu oynatamıyordu. Ürünü kayıt olan bir
// sistemde, denetlenen tarafın denetim dosyasına ne yazılacağını
// seçebilmesi asıl kusurdur.
//
// ⚠️ İŞARET KONTROLÜ DEĞİL, MUTLAK SINIR: int(uint32(0xFFFFFFFF))
// amd64'te 4294967295, 32 bitte -1'dir. "Negatif değilse tamam" diyen
// bir kontrol CI'da (amd64) yeşil kalıp 32 bitte "-1x-1" üretirdi.
//
// Reddetmek yerine SINIRLAMAK: yeniden boyutlandırmanın OLDUĞU bilgisi
// kaydın bir parçası ve onu düşürmek de bir kayıp. Sınıra takılan
// değer ayrıca loglanıyor.
func (b *Broker) clampDim(v uint32, fallback int) int {
	if v > maxTerminalDim {
		b.logger.Warn("terminal dimension clamped for recording",
			"value", v, "limit", maxTerminalDim)
		return maxTerminalDim
	}

	// SIFIR DA AYNI KUSUR, DİĞER UÇTAN. RFC 4254 pty-req'te boyutun
	// piksel alanlarıyla verilmesine izin verdiği için karakter alanı
	// meşru olarak 0 gelebilir; ama "0x0" bir ızgara değil. Oynatıcı
	// replay yüzeyini "r" olaylarından kurduğundan, 0 yazılan bir kayıt
	// tıpkı 4294967295 yazılan kayıt gibi AÇILMIYOR. Üst sınırı koyan
	// gerekçe buraya da aynen uyuyor: denetlenen taraf, kendi kaydının
	// oynatılabilirliğini seçememeli.
	//
	// Düşürmek yerine asciicast varsayılanını yazıyoruz — başlık zaten
	// aynı ikameyi yapıyor (record.NewWriter) — ve ikameyi logluyoruz.
	if v == 0 {
		b.logger.Warn("zero terminal dimension replaced for recording",
			"substituted", fallback)
		return fallback
	}

	return int(v)
}

// recordIntent, oturumun NE YAPMAK İSTEDİĞİNİ kayda ve loga yazar.
//
// ⚠️ NEDEN VAR: `exec` istekleri hedefe geçiyor ama komut satırı
// HİÇBİR YERE yazılmıyordu. `ssh user:target@bastion 'komut'` çalışıyor,
// çıktısı kayda düşüyor ama KOMUTUN KENDİSİ ne kayıtta ne sessions
// tablosunda ne logda görünüyordu — kısa çıktılı bir komut (dosya
// silme, kullanıcı ekleme) fiilen boş bir transkript bırakıyordu.
//
// Bu, `subsystem`in engellenme gerekçesiyle AYNI boşluk: "denetlenemeyen
// kanal". Orada kapatıp burada açık bırakmak tutarsızdı.
//
// Komut kayda "o" olayı olarak DEĞİL, ayrı bir satır olarak yazılamıyor
// (asciicast v2'de üç olay tipi var), o yüzden oynatıcının göstereceği
// akışa bir başlık satırı olarak giriyor ve ayrıca Warn ile loglanıyor.
func (b *Broker) recordIntent(req *ssh.Request) {
	var line string

	switch req.Type {
	case "exec":
		p, err := ParseExec(req.Payload)
		if err != nil {
			b.logger.Error("exec parse error", "error", err)
			// Ayrıştıramadığımız bir komutu SESSİZ geçmiyoruz: denetim
			// kaydı "burada bir exec vardı" demeli.
			line = "postern: exec (unparsable command)"
			b.logger.Warn("session exec", "command", "<unparsable>")
		} else {
			line = "postern: exec " + p.Command
			b.logger.Warn("session exec", "command", p.Command)
		}

	case "shell":
		line = "postern: shell"

	case "signal":
		line = "postern: signal"

	/*
	 * ⚠️ ALT SİSTEM DE YAZILIYOR ve eksikliği ölçülmüş bir yanlış
	 * izlenimdi: bir SFTP oturumunun kaydı, oturumun SFTP olduğunu
	 * bile söylemiyordu. Kaydı açan denetçi boş bir dosya görüyor ve
	 * "kimse bir şey yapmamış" diye okuyordu.
	 *
	 * Ad KARŞI TARAFTAN geliyor: istemci ne yazarsa o. Bu yüzden
	 * temizlenerek yazılıyor — kayda giren metin oynatıldığında
	 * terminalde çalışır (sftpcast.go'daki gerekçe).
	 */
	case "subsystem":
		var sub SubsystemRequest
		if err := ssh.Unmarshal(req.Payload, &sub); err != nil {
			line = "postern: subsystem (unparsable)"
		} else {
			line = "postern: subsystem " + castSafe(sub.Name)
		}

	default:
		return
	}

	if b.rec == nil {
		return
	}
	// Kayda çıktı akışının başına düşüyor: oynatan kişi oturumun ne
	// için açıldığını ilk satırda görüyor.
	if _, err := b.rec.OutputStream().Write([]byte("\r\n\x1b[2m" + line + "\x1b[0m\r\n")); err != nil {
		b.logger.Error("intent record failed", "error", err)
	}
}
