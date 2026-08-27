package proxy

import (
	"bytes"
	"context"
	"io"
	"log/slog"
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
	// Gerçek kanal gibi: kapanış, okumada bekleyenleri uyandırır.
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
	defer c.mu.Unlock()
	c.sent = append(c.sent, sentReq{name: name, wantReply: wantReply, payload: payload})
	return true, nil
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
