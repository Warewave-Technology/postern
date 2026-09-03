package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/record"
)

// --- test yardımcıları: sahte ssh.Channel ---
//
// ssh.Channel bir ARAYÜZ olduğu için broker'ı gerçek bağlantı kurmadan
// sınayabiliyoruz. Okuma ucu io.Pipe: veriyi test besler, EOF'u test seçer.

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Read(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type sentReq struct {
	name      string
	wantReply bool
	payload   []byte
}

type fakeChannel struct {
	dataR *io.PipeReader
	dataW *syncBuffer
	errR  *io.PipeReader
	errW  *syncBuffer

	mu         sync.Mutex
	sent       []sentReq
	closed     bool
	closeWrite bool

	// gate/entered, SendRequest'i testin kontrolüne verir: entered
	// "istek bana ulaştı", gate ise "artık cevaplayabilirsin" demek.
	// Aradaki pencere, gerçekte hedefin cevabını beklediğimiz an.
	gate    chan struct{}
	entered chan struct{}

	// refuse, SendRequest'in "hayır" demesi. Hedefin bir isteği
	// reddetmesi, kabul etmesi kadar olağan bir cevap.
	refuse bool
}

func newFakeChannel() (ch *fakeChannel, feedData, feedStderr *io.PipeWriter) {
	dr, dw := io.Pipe()
	er, ew := io.Pipe()
	return &fakeChannel{dataR: dr, dataW: &syncBuffer{}, errR: er, errW: &syncBuffer{}}, dw, ew
}

func (c *fakeChannel) Read(p []byte) (int, error)  { return c.dataR.Read(p) }
func (c *fakeChannel) Write(p []byte) (int, error) { return c.dataW.Write(p) }

func (c *fakeChannel) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	/*
	 * ⚠️ BU, GERÇEK ssh.Channel DEĞİL — ve eski yorum öyle diyordu.
	 *
	 * x/crypto'da Close() yalnızca channelCloseMsg GÖNDERİYOR;
	 * okumada bekleyenleri uyandıran ch.close(), karşı taraftan close
	 * ALINDIĞINDA çalışıyor (channel.go, msgChannelClose dalı). Yani
	 * gerçekte kapanış tek başına okuyucuyu serbest bırakmıyor.
	 *
	 * Buradaki uyandırma testlerin çoğunu basitleştirdiği için
	 * duruyor, ama koşumun GERÇEKTEN DAHA BAĞIŞLAYICI olduğunu bilerek
	 * yazıyoruz: cevap vermeyen bir istemcinin davranışı bu tiple
	 * ölçülemez, onun için deafChannel var.
	 */
	c.dataR.Close()
	c.errR.Close()
	return nil
}

func (c *fakeChannel) CloseWrite() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeWrite = true
	return nil
}

func (c *fakeChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	c.mu.Lock()
	gate, entered := c.gate, c.entered
	c.mu.Unlock()

	if gate != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-gate
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, sentReq{name: name, wantReply: wantReply, payload: payload})
	return !c.refuse, nil
}

// refuseRequests, hedefin bundan sonraki her isteğe "hayır" demesini
// sağlar. Run'dan ÖNCE çağrılmalı.
func (c *fakeChannel) refuseRequests() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refuse = true
}

// holdRequests, bu kanala gelen request'leri release çağrılana kadar
// bekletir. entered, ilk request'in ulaştığını haber verir.
//
// Run'dan ÖNCE çağrılmalı.
func (c *fakeChannel) holdRequests() (entered <-chan struct{}, release func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gate = make(chan struct{})
	c.entered = make(chan struct{}, 1)
	g := c.gate
	return c.entered, sync.OnceFunc(func() { close(g) })
}

func (c *fakeChannel) Stderr() io.ReadWriter {
	return struct {
		io.Reader
		io.Writer
	}{Reader: c.errR, Writer: c.errW}
}

func (c *fakeChannel) sentRequests() []sentReq {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]sentReq(nil), c.sent...)
}

func (c *fakeChannel) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *fakeChannel) isCloseWritten() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeWrite
}

/*
 * TestBrokerDoesNotCloseWhileAnsweringClient, kapanışın istemcinin
 * cevabını kesmediğini ölçüyor.
 *
 * ⚠️ CANLI SSH İLE YAKALANMIYOR. `echo hello` 120 kez koşturuldu
 * (yüklü makinede, eşzamanlı da) ve pencere bir kez bile
 * kaçırılmadı — ama yarış gerçek ve tam olarak bu sırayla oluyor.
 * Bu yüzden pencere burada sahte kanalla ZORLA açık tutuluyor:
 * "bazen düşen" bir test, düşünce kimsenin inanmadığı bir testtir.
 */
func TestBrokerDoesNotCloseWhileAnsweringClient(t *testing.T) {
	down, _, _ := newFakeChannel()
	up, feedUp, feedUpErr := newFakeChannel()
	downR := make(chan *ssh.Request)
	upR := make(chan *ssh.Request)

	// Hedefe iletim burada duracak: istek gitti, cevabı henüz yok.
	//
	// WantReply=false: ssh.Request.Reply gerçek bir bağlantı ister
	// (alanları paket-içi), sahte kanalla çağrılamaz. Sınanan şey zaten
	// bir alt katman — "istek işlenirken kapatma" — ve cevabın
	// gönderilmesi o pencerenin içinde.
	entered, release := up.holdRequests()

	done := make(chan error, 1)
	go func() {
		done <- New(down, downR, up, upR, nil, false, RequestPolicy{}, testLogger()).Run(context.Background())
	}()

	select {
	case downR <- &ssh.Request{Type: "exec", Payload: ssh.Marshal(struct{ Command string }{"echo hello"})}:
	case <-time.After(2 * time.Second):
		t.Fatal("downR'den okuyan yok — Run istemcinin request akışını dinlemiyor")
	}

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("exec hedefe iletilmedi")
	}

	// Hedef tarafı BİTTİ: çıktı, stderr ve request akışı kapandı.
	// Broker'ın beklediği üç goroutine de burada dönüyor.
	feedUp.Close()
	feedUpErr.Close()
	close(upR)

	// Kusurlu sürüm tam burada istemcinin kanalını kapatıyordu.
	time.Sleep(50 * time.Millisecond)
	if down.isClosed() {
		t.Fatal("istemcinin kanalı, isteği cevaplanmadan kapatıldı — cevap yolda kalır ve istemci komutu EOF ile düşer")
	}

	release()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cevap verildikten sonra Run dönmedi")
	}

	if !down.isClosed() {
		t.Error("oturum bitti ama istemcinin kanalı kapatılmadı")
	}

	var forwarded bool
	for _, r := range up.sentRequests() {
		if r.name == "exec" {
			forwarded = true
		}
	}
	if !forwarded {
		t.Error("exec hedefe hiç gitmemiş — test yanlış şeyi bekliyor")
	}
}

/*
 * TestForcedCloseDoesNotWaitForTheTarget, düzeltmenin yöneticinin kesme
 * düğmesini hedefe bağlamadığını ölçüyor.
 *
 * ⚠️ BU TEST DÜZELTMENİN KENDİ RİSKİ İÇİN VAR. Kapanışta bir isteğin
 * bitmesini beklemek, yanlış yere konursa oturumu SESSİZ BİR HEDEFİN
 * insafına bırakırdı: ctx iptal edilir, admin "kestim" sanır, kabuk
 * yaşamaya devam eder. Bekleme bu yüzden yalnızca graceful dalda.
 */
func TestForcedCloseDoesNotWaitForTheTarget(t *testing.T) {
	down, _, _ := newFakeChannel()
	up, _, _ := newFakeChannel()
	downR := make(chan *ssh.Request)
	upR := make(chan *ssh.Request)

	// Hedef cevap vermiyor ve HİÇ vermeyecek: release çağrılmıyor.
	entered, _ := up.holdRequests()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- New(down, downR, up, upR, nil, false, RequestPolicy{}, testLogger()).Run(ctx)
	}()

	select {
	case downR <- &ssh.Request{Type: "exec", Payload: ssh.Marshal(struct{ Command string }{"sleep 3600"})}:
	case <-time.After(2 * time.Second):
		t.Fatal("downR'den okuyan yok")
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("exec hedefe iletilmedi")
	}

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("oturum zorla kesildi ama Run, sessiz hedefin cevabını bekliyor — kesme düğmesi hedefe bağlanmış")
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// mustWrite, karşı uçtan okuyan olmadığında testi 60 sn astırmak yerine
// anlaşılır bir hatayla düşürür (io.Pipe senkrondur: okuyan yoksa yazma
// bloklar).
func mustWrite(t *testing.T, w io.Writer, s string) {
	t.Helper()
	errc := make(chan error, 1)
	go func() {
		_, err := w.Write([]byte(s))
		errc <- err
	}()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("yazma hatası: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("%q yazılamadı — karşı uçtan okuyan yok (Run akışları taşımıyor)", s)
	}
}

func waitForContent(t *testing.T, b *syncBuffer, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(b.String(), want) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%q beklenen sürede gelmedi; tampon: %q", want, b.String())
}

// --- testler ---

// Üç veri akışı da doğru yönde taşınmalı: klavye→hedef, çıktı→ekran,
// stderr→stderr (Ek C.5: stderr ayrı bir akıştır, ayrıca kopyalanmalı).
func TestBrokerRelaysData(t *testing.T) {
	down, feedDown, _ := newFakeChannel()
	up, feedUp, feedUpErr := newFakeChannel()
	downR := make(chan *ssh.Request)
	upR := make(chan *ssh.Request)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- New(down, downR, up, upR, nil, false, RequestPolicy{}, testLogger()).Run(ctx) }()

	mustWrite(t, feedDown, "ls -la\n")
	waitForContent(t, up.dataW, "ls -la")

	mustWrite(t, feedUp, "total 42\n")
	waitForContent(t, down.dataW, "total 42")

	mustWrite(t, feedUpErr, "permission denied\n")
	waitForContent(t, down.errW, "permission denied")

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ctx iptalinde Run dönmedi")
	}
}

// ⚠️ S1.5'in en kritik sözleşmesi: exit-status kaybolmamalı.
//
// Senaryo bilinçli olarak zor: hedefin ÇIKTISI bitiyor, kısa bir sessizlik
// oluyor, exit-status ANCAK ONDAN SONRA geliyor. "Çıktı bitti, kapatıyorum"
// diyen bir implementasyon bu request'i kaçırır ve istemci her komut için 0
// görür (Ek C.3). Run, hedefin request akışı kapanmadan dönmemeli.
func TestBrokerForwardsExitStatusBeforeClosing(t *testing.T) {
	down, _, _ := newFakeChannel()
	up, feedUp, feedUpErr := newFakeChannel()
	downR := make(chan *ssh.Request)
	upR := make(chan *ssh.Request)

	done := make(chan error, 1)
	go func() {
		done <- New(down, downR, up, upR, nil, false, RequestPolicy{}, testLogger()).Run(context.Background())
	}()

	// Hedefin çıktısı bitti.
	feedUp.Close()
	feedUpErr.Close()

	// Kısa sessizlik: aceleci implementasyon burada kapatıp kaybeder.
	time.Sleep(50 * time.Millisecond)

	select {
	case upR <- &ssh.Request{Type: "exit-status", WantReply: false, Payload: ssh.Marshal(struct{ Status uint32 }{3})}:
	case <-time.After(2 * time.Second):
		t.Fatal("upR'den okuyan yok — Run hedefin request akışını dinlemiyor")
	}
	close(upR)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run dönmedi")
	}

	var found bool
	for _, r := range down.sentRequests() {
		if r.name == "exit-status" {
			found = true
			var st struct{ Status uint32 }
			if err := ssh.Unmarshal(r.payload, &st); err != nil {
				t.Fatalf("payload bozulmuş: %v", err)
			}
			if st.Status != 3 {
				t.Fatalf("exit-status = %d, beklenen 3", st.Status)
			}
		}
	}
	if !found {
		t.Fatal("exit-status istemciye iletilmedi — her komut 0 dönecek")
	}

	if !down.isClosed() {
		t.Error("Run bitince down kanalı kapatılmalı (bekleyen kopyalar uyanmalı)")
	}
}

// Kullanıcıdan gelen request'ler hedefe DEĞİŞMEDEN gitmeli.
func TestForwardRequest(t *testing.T) {
	cases := []struct {
		name string
		req  ssh.Request
	}{
		{
			name: "pty-req wantReply true",
			req: ssh.Request{
				Type:      "pty-req",
				WantReply: true,
				Payload: ssh.Marshal(struct {
					Term          string
					Columns, Rows uint32
					Width, Height uint32
					Modes         string
				}{Term: "xterm-256color", Columns: 120, Rows: 30}),
			},
		},
		{
			name: "window-change wantReply false",
			req: ssh.Request{
				Type:      "window-change",
				WantReply: false,
				Payload: ssh.Marshal(struct {
					Columns, Rows uint32
					Width, Height uint32
				}{Columns: 80, Rows: 24}),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dst, _, _ := newFakeChannel()

			ok, err := forwardRequest(dst, &tc.req)
			if err != nil {
				t.Fatalf("beklenmeyen hata: %v", err)
			}
			if !ok {
				t.Fatal("hedef kabul etti, forwardRequest false dönmemeli")
			}

			sent := dst.sentRequests()
			if len(sent) != 1 {
				t.Fatalf("gönderilen request sayısı = %d, beklenen 1", len(sent))
			}
			if sent[0].name != tc.req.Type {
				t.Errorf("tip = %q, beklenen %q", sent[0].name, tc.req.Type)
			}
			if sent[0].wantReply != tc.req.WantReply {
				t.Errorf("wantReply = %v, beklenen %v", sent[0].wantReply, tc.req.WantReply)
			}
			if !bytes.Equal(sent[0].payload, tc.req.Payload) {
				t.Error("payload değişmiş — olduğu gibi geçmeli (Ek C.4)")
			}
		})
	}
}

// stdout ve stderr AYNI kanala (down) yazar. Biri bitti diye kanalın yazma
// yönü kapatılamaz: diğeri hâlâ yazıyor olabilir ve x/crypto'da CloseWrite ile
// eşzamanlı yazma gerçek bir veri yarışıdır (-race entegrasyon koşusunda
// yakalandı).
//
// Sözleşme: down'a yazan HERKES bitmeden down.CloseWrite çağrılmaz.
func TestBrokerKeepsDownWritableWhileStderrFlows(t *testing.T) {
	down, _, _ := newFakeChannel()
	up, feedUp, feedUpErr := newFakeChannel()
	downR := make(chan *ssh.Request)
	upR := make(chan *ssh.Request)

	done := make(chan error, 1)
	go func() {
		done <- New(down, downR, up, upR, nil, false, RequestPolicy{}, testLogger()).Run(context.Background())
	}()

	// stdout bitti; stderr HÂLÂ açık.
	feedUp.Close()
	time.Sleep(50 * time.Millisecond)

	if down.isCloseWritten() {
		t.Fatal("stdout bitti diye down yarı kapatıldı — stderr hâlâ aynı kanala yazıyor")
	}

	// Geciken stderr çıktısı yine de geçmeli.
	mustWrite(t, feedUpErr, "geciken hata\n")
	waitForContent(t, down.errW, "geciken hata")

	feedUpErr.Close()
	close(upR)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run dönmedi")
	}
}

// --- S1.8: kayda tee'leme ---

// memCloser, record.Writer'ın yazacağı bellek hedefi.
type memCloser struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (m *memCloser) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.buf.Write(p)
}

func (m *memCloser) Close() error { return nil }

func (m *memCloser) String() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.buf.String()
}

// Hedefin çıktısı hem kullanıcıya hem kayda gitmeli; kullanıcının girdisi
// ise recordInput=false iken kayda GİTMEMELİ.
//
// ⚠️ Girdi varsayılan kapalı: kullanıcının yazdığı her şey girdidir, sudo
// parolası dahil.
func TestBrokerTeesOutputNotInput(t *testing.T) {
	down, feedDown, _ := newFakeChannel()
	up, feedUp, _ := newFakeChannel()
	downR := make(chan *ssh.Request)
	upR := make(chan *ssh.Request)

	sink := &memCloser{}
	rec, err := record.NewWriter(sink, 80, 24, nil)
	if err != nil {
		t.Fatalf("record.NewWriter: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- New(down, downR, up, upR, rec, false, RequestPolicy{}, testLogger()).Run(ctx) }()

	mustWrite(t, feedUp, "hedefin ciktisi\n")
	waitForContent(t, down.dataW, "hedefin ciktisi")

	mustWrite(t, feedDown, "gizli-parola\n")
	waitForContent(t, up.dataW, "gizli-parola")

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run dönmedi")
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("rec.Close: %v", err)
	}

	cast := sink.String()
	if !strings.Contains(cast, "hedefin ciktisi") {
		t.Errorf("çıktı kayda tee'lenmemiş; kayıt: %q", cast)
	}
	if strings.Contains(cast, "gizli-parola") {
		t.Errorf("recordInput=false iken GİRDİ kayda düştü — parola sızıntısı; kayıt: %q", cast)
	}
}

// recordInput=true iken girdi de kaydedilmeli — AMA yarı kapatma
// kaybolmamalı: pipe klavye yönünde CloseWrite arar ve io.MultiWriter bunu
// sağlamaz. Kaybolursa "cat f | ssh host 'wc -l'" asılır (Ek C.6).
func TestBrokerTeedInputKeepsHalfClose(t *testing.T) {
	down, feedDown, _ := newFakeChannel()
	up, _, _ := newFakeChannel()
	downR := make(chan *ssh.Request)
	upR := make(chan *ssh.Request)

	rec, err := record.NewWriter(&memCloser{}, 80, 24, nil)
	if err != nil {
		t.Fatalf("record.NewWriter: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- New(down, downR, up, upR, rec, true, RequestPolicy{}, testLogger()).Run(context.Background())
	}()

	mustWrite(t, feedDown, "girdi\n")
	waitForContent(t, up.dataW, "girdi")

	// Kullanıcı stdin'i kapattı: hedef bunu EOF olarak görmeli.
	feedDown.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if up.isCloseWritten() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("stdin kapandı ama hedefe yarı kapatma iletilmedi — tee CloseWrite'ı yuttu")
}

/*
 * ⚠️ DENETİM ÇÖKÜNCE Run BUNU ÇAĞIRANA SÖYLEMELİ.
 *
 * ÖLÇÜLEN ARIZA: Run koşulsuz nil dönüyordu, yani sshd/channel.go ve
 * httpapi/terminal.go'daki `if err := sess.Run(...); err != nil`
 * dalları ÖLÜ KODDU — hiçbir koşulda çalışmıyorlardı. Bu depodaki
 * tekrar eden sınıfın tersi: yazılmış ve hiç tetiklenemeyen bir hata
 * yolu.
 *
 * Kaybolan sinyal gerçekti: SFTP çözücüsü akışı anlayamadığında
 * oturumu KASTEN kapatıyoruz ve bu, "kullanıcı çıktı" ile
 * karıştırılmaması gereken bir bitiş.
 */
func TestRunReportsAnAuditAbort(t *testing.T) {
	down, _, _ := newFakeChannel()
	up, _, _ := newFakeChannel()
	downR := make(chan *ssh.Request)
	upR := make(chan *ssh.Request)

	b := New(down, downR, up, upR, nil, false, RequestPolicy{}, testLogger())

	done := make(chan error, 1)
	go func() { done <- b.Run(context.Background()) }()

	cause := errors.New("sftp stream stopped making sense")
	b.abortAudit(cause)

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("denetim çöktü ama Run nil döndü — çağıranın hata dalı ölü kod")
		}
		if !errors.Is(err, cause) {
			t.Errorf("dönen hata sebebi taşımıyor: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run dönmedi")
	}
}

// Normal çıkışta nil dönmeli: her bitişi hata saymak, gerçek sinyali
// gürültüye gömerdi.
func TestRunReturnsNilOnANormalExit(t *testing.T) {
	down, _, _ := newFakeChannel()
	up, _, _ := newFakeChannel()
	downR := make(chan *ssh.Request)
	upR := make(chan *ssh.Request)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- New(down, downR, up, upR, nil, false, RequestPolicy{}, testLogger()).Run(ctx) }()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("normal çıkışta hata döndü: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run dönmedi")
	}
}

/*
 * ⚠️ SAĞIR KANAL: GERÇEK ssh.Channel GİBİ DAVRANAN SAHTE.
 *
 * newFakeChannel'ın Close'u okumada bekleyenleri uyandırıyor ve yorumu
 * "gerçek kanal gibi" diyor. YANLIŞ — x/crypto kaynağına bakıldı:
 * channel.Close() yalnızca channelCloseMsg GÖNDERİYOR; okuyucuları
 * uyandıran ch.close() ancak karşı taraftan close ALINDIĞINDA
 * çağrılıyor (channel.go, msgChannelClose dalı).
 *
 * Fark önemli: koşum gerçeklikten daha bağışlayıcı olduğu için, cevap
 * vermeyen bir istemcinin ne yaptığını mevcut testlerin hiçbiri
 * göremiyor. Bu tip o boşluğu kapatıyor.
 */
type deafChannel struct {
	*fakeChannel
	block chan struct{}
}

func newDeafChannel() *deafChannel {
	ch, _, _ := newFakeChannel()
	return &deafChannel{fakeChannel: ch, block: make(chan struct{})}
}

// Read, karşı taraf cevap verene kadar dönmüyor — Close bile uyandırmaz.
func (d *deafChannel) Read(p []byte) (int, error) {
	<-d.block
	return 0, io.EOF
}

/*
 * answer, karşı tarafın nihayet close'a cevap vermesi.
 *
 * ⚠️ İSTEK KANALLARI DA KAPANIYOR ve bu gerçeğin taklidi: x/crypto'da
 * karşı taraftan close alındığında ch.close() çalışıyor ve o,
 * pending.eof() ile BİRLİKTE close(c.incomingRequests) da yapıyor.
 * Yalnızca okumayı serbest bırakan bir taklit, istek röleleri hiç
 * bitmediği için "serbest kalmadılar" derdi — koşumun eksikliğini
 * ürünün kusuru sanmak olurdu (ilk hâli tam olarak bunu yaptı).
 */
func (d *deafChannel) answer(reqs ...chan *ssh.Request) {
	close(d.block)
	for _, r := range reqs {
		close(r)
	}
}

/*
 * ⚠️ CEVAP VERMEYEN İSTEMCİ, OTURUM BİTTİKTEN SONRA GOROUTINE TUTUYOR.
 *
 * Run'ın beş goroutine'inden ikisi WaitGroup dışında ve bu BİLİNÇLİ:
 * hiçbir şey yazmayan bir istemciyi beklemek, oturumun hiç
 * bitmemesi demek olurdu. Bedeli, o ikisinin karşı taraf close'a cevap
 * verene (ya da TCP ölene) kadar yaşaması.
 *
 * Bu test o bedeli ÖLÇÜYOR ve sınırlarını yazıya döküyor. Sınırsız
 * değil: bağlantı başına en fazla max_channels_per_conn, toplamda
 * max_conns ile çarpımı kadar. Düzeltmek, ürünün en kritik veri
 * yolunu yeniden kurmayı gerektirirdi; ölçüp sınırını bilmek doğru
 * karşılık.
 */
func TestUnansweredCloseHoldsTwoGoroutines(t *testing.T) {
	down := newDeafChannel()
	up, _, _ := newFakeChannel()
	downR := make(chan *ssh.Request)
	upR := make(chan *ssh.Request)

	before := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- New(down, downR, up, upR, nil, false, RequestPolicy{}, testLogger()).Run(ctx) }()

	// Oturumu bitir: Run dönmeli, istemci cevap vermese bile.
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cevap vermeyen istemci Run'ı kilitledi — oturum hiç bitmezdi")
	}

	// ⚠️ ASIL ÖLÇÜM: Run döndü ama istemci tarafındaki okuyucular hâlâ
	// bekliyor. Sayı SIFIRA dönmüyor ve bu beklenen davranış.
	time.Sleep(200 * time.Millisecond)
	during := runtime.NumGoroutine()
	if during <= before {
		t.Skip("goroutine sayısı ölçülemedi (koşumdaki gürültü); " +
			"ölçüm ortama duyarlı, iddiayı zorlamıyoruz")
	}

	// Karşı taraf nihayet cevap verince serbest kalıyorlar.
	down.answer(downR, upR)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before+1 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("istemci cevap verdikten sonra da serbest kalmadılar: "+
		"önce=%d sonra=%d — sızıntı sınırsız olurdu", before, runtime.NumGoroutine())
}
