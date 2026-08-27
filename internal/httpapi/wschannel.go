package httpapi

// WebSocket'i ssh.Channel gibi giydiren adaptör.
//
// NEDEN BÖYLE: broker (proxy.Broker) istemci tarafından bir ssh.Channel
// bekliyor. WebSocket'i o arayüze uydurunca broker, kayıt, denetim ve
// yeniden boyutlandırma mantığının TAMAMI olduğu gibi çalışıyor — web
// terminali için ikinci bir kopya yazmıyoruz. S1.7'de record.Writer'ı
// io.Writer arkasına koyduğumuzda öğrendiğimiz şeyin büyük ölçekli hâli:
// dar bir arayüz, iki dünyayı birbirine tanıtmadan bağlar.
//
// PROTOKOL (plan S4 sözleşmesi):
//
//	binary frame  (her iki yön)   : terminal verisi
//	text/JSON     (istemci→sunucu): {"type":"resize","cols":120,"rows":30}
//	text/JSON     (sunucu→istemci): {"type":"exit","status":0}
//
// Neden ikisi ayrı: terminal verisi ham bayttır ve içinde her şey olabilir
// (kaçış dizileri, UTF-8 parçaları). Kontrol mesajlarını aynı akışa
// gömseydik, çıktının içinde geçen bir metni komut sanma riski doğardı —
// SSH'ın veri ve request'i ayrı taşımasının sebebi de bu.

import (
	"context"
	"encoding/json"
	"io"
	"sync"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/proxy"
)

// wsChannel, ssh.Channel arayüzünü WebSocket üzerinde karşılar.
type wsChannel struct {
	conn *websocket.Conn

	// ctx bağlantının ömrüne bağlıdır, isteğinkine DEĞİL: WebSocket
	// yükseltmesinden sonra "istek" biter ama bağlantı yaşar.
	ctx context.Context

	// pending, okunmuş ama tüketilmemiş mesaj artığı.
	//
	// WebSocket MESAJ tabanlı, io.Reader ise AKIŞ tabanlı: çağıran 32
	// baytlık tampon verip 4 KB'lık bir mesajın ortasında kalabilir.
	// Artığı saklamazsak o baytlar kaybolur — record.Writer'daki eksik
	// UTF-8 dizisini bekletme fikrinin aynısı, başka bir sınırda.
	pending []byte

	// writeMu, eşzamanlı yazmaları serileştirir. Broker çıktıyı bir
	// goroutine'den yazarken SendRequest başka birinden gelebilir;
	// websocket.Conn tek yazıcı bekler.
	writeMu sync.Mutex

	// reqs, broker'ın downR'ı. Read metin mesajı gördüğünde buraya
	// yazar; bağlantı bitince KAPANIR.
	//
	// ⚠️ Okuma tek yerden yürür: websocket.Conn eşzamanlı Read'e izin
	// vermez, o yüzden "kontrol mesajlarını dinleyen ayrı goroutine"
	// diye bir şey YOK — kontrol ve veri aynı döngüden ayrışır.
	reqs chan *ssh.Request

	// closeReqs, kanalı yalnızca bir kez kapatır: Read bağlantı
	// kapandıktan sonra tekrar çağrılabilir ve ikinci close panik olurdu.
	closeReqs sync.Once

	// onEOF, bağlantı kapandığında BİR KEZ çağrılır.
	//
	// Neden gerekli: broker'ın beklediği akışlar hedef tarafındakiler
	// (up→down, stderr, upR). İstemci kopyası bilerek sayılmaz — normal
	// SSH'ta klavye akışı oturum boyunca bitmez. Ama pty'li bir kabukta
	// hedef, stdin'in kapanmasını görmez (pty EOF'u geçirmez), yani WS
	// kapandığında hedefe "bitti" diyen kimse olmaz ve broker sonsuza
	// dek bekler. Bu geri çağrı o boşluğu dolduruyor: çağıran ctx'i
	// iptal eder, broker ctx.Done() dalından çıkar.
	onEOF   func()
	eofOnce sync.Once
}

// resizeMessage, istemciden gelen tek kontrol mesajı tipi.
type resizeMessage struct {
	Type string `json:"type"`
	Cols uint32 `json:"cols"`
	Rows uint32 `json:"rows"`
}

// newWSChannel, bağlantıyı sarar ve gelen kontrol mesajlarını request
// kanalına çeviren goroutine'i başlatır.
//
// Dönen kanal broker'ın downR'ıdır: pty-req, shell ve window-change
// buradan akar.
func newWSChannel(ctx context.Context, conn *websocket.Conn, onEOF func()) (*wsChannel, <-chan *ssh.Request) {
	// Tampon: ilk iki request (pty-req + shell) kimse okumadan önce
	// yazılabilsin. Tamponsuz kanal burada kilitlenirdi — broker henüz
	// başlamamış oluyor.
	c := &wsChannel{conn: conn, ctx: ctx, reqs: make(chan *ssh.Request, 8), onEOF: onEOF}

	// Terminal, kabuk açılmadan boş kalır: SSH istemcisinin yaptığı iki
	// şeyi biz sentetik olarak üretiyoruz. Boyut şimdilik varsayılan;
	// istemcinin ilk resize mesajı gerçek boyutu getirecek.
	c.reqs <- &ssh.Request{
		Type:      "pty-req",
		WantReply: false,
		Payload: ssh.Marshal(proxy.PtyRequest{
			Term: "xterm-256color", Columns: 80, Rows: 24,
		}),
	}
	c.reqs <- &ssh.Request{Type: "shell", WantReply: false}

	return c, c.reqs
}

// maxTerminalDim, tarayıcıdan kabul edilen en büyük terminal boyutu.
// internal/proxy'deki sınırla AYNI olmalı: iki kapı, tek kural.
const maxTerminalDim = 65535

// handleControl, bir metin mesajını request'e çevirip kanala bırakır.
// Tanınmayan mesajlar sessizce yok sayılır: istemci sürümü sunucudan
// yeni olabilir ve bilinmeyen bir kontrol mesajı oturumu düşürmemeli.
func (c *wsChannel) handleControl(data []byte) {
	var msg resizeMessage
	if err := json.Unmarshal(data, &msg); err != nil || msg.Type != "resize" {
		return
	}
	// Üst sınır alt sınır kadar gerekli: msg.Cols uint32 ve JSON
	// negatifi reddeder ama 4294967295'i geçirir. O değer hem hedefte
	// (TIOCSWINSZ 16 bitlik alanlar kullanır) hem kayıtta anlamsız.
	// SSH kapısındaki karşılığı internal/proxy'deki maxTerminalDim —
	// iki kapı aynı sınırı uygulamalı, yoksa ayrışırlar.
	if msg.Cols == 0 || msg.Rows == 0 ||
		msg.Cols > maxTerminalDim || msg.Rows > maxTerminalDim {
		return
	}

	req := &ssh.Request{
		Type:      "window-change",
		WantReply: false,
		Payload: ssh.Marshal(proxy.WindowChangeRequest{
			Columns: msg.Cols, Rows: msg.Rows,
		}),
	}
	// Kanal doluysa BLOKLAMA: resize kaybolabilir, ama okuma döngüsünün
	// durması terminali tamamen dondururdu. Boyut zaten bir sonraki
	// pencere değişikliğinde düzelir.
	select {
	case c.reqs <- req:
	default:
	}
}

// Read, istemciden gelen klavye girdisini döner.
//
// Kontrol mesajları BURADA akmaz: metin mesajı görünce request kanalına
// yönlendirilir ve okumaya devam edilir. Böylece broker'ın gördüğü akış
// yalnızca terminal verisidir.
func (c *wsChannel) Read(p []byte) (int, error) {
	for {
		if len(c.pending) > 0 {
			n := copy(p, c.pending)
			c.pending = c.pending[n:]
			return n, nil
		}

		typ, data, err := c.conn.Read(c.ctx)
		if err != nil {
			// Bağlantı kapandı: broker için bu normal bir sonlanma.
			// io.EOF, "kullanıcı çıktı" demenin akış dilindeki karşılığı.
			//
			// Request kanalını da burada kapatıyoruz: broker downR'ı
			// range ile dinliyor, kapanmayan kanal o goroutine'i sonsuza
			// dek yaşatırdı.
			c.closeReqs.Do(func() { close(c.reqs) })
			if c.onEOF != nil {
				c.eofOnce.Do(c.onEOF)
			}
			return 0, io.EOF
		}

		if typ == websocket.MessageText {
			c.handleControl(data)
			continue
		}
		c.pending = data
	}
}

// Write, terminal çıktısını istemciye binary frame olarak gönderir.
func (c *wsChannel) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if err := c.conn.Write(c.ctx, websocket.MessageBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close, WebSocket'i kapatır.
func (c *wsChannel) Close() error {
	return c.conn.Close(websocket.StatusNormalClosure, "session ended")
}

// CloseWrite, SSH'ta "yazacağım bir şey kalmadı ama okumaya devam" demek.
//
// WebSocket'te yarı kapama YOK. En dürüst karşılık hiçbir şey yapmamak:
// bağlantıyı burada kapatmak, hedeften hâlâ gelebilecek çıktıyı (çıkış
// mesajı gibi) keserdi.
func (c *wsChannel) CloseWrite() error { return nil }

// SendRequest, hedeften gelen bildirimleri istemciye iletir.
//
// Yalnızca exit-status'ü iletiyoruz: terminalin "oturum şu kodla bitti"
// diyebilmesi için. Diğer request'ler (keepalive vb.) tarayıcıda karşılığı
// olmadığı için sessizce yutulur.
//
// wantReply her durumda false döner: WS'te cevap kanalı yok.
func (c *wsChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	if name != "exit-status" {
		return false, nil
	}

	var st struct{ Status uint32 }
	if err := ssh.Unmarshal(payload, &st); err != nil {
		return false, nil
	}

	msg, err := json.Marshal(map[string]any{"type": "exit", "status": st.Status})
	if err != nil {
		return false, nil
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	// Hata yutuluyor: bağlantı zaten kapanıyor olabilir ve exit bildirimi
	// gönderilememesi oturumu etkilemez.
	_ = c.conn.Write(c.ctx, websocket.MessageText, msg)
	return false, nil
}

// Stderr, SSH'ta ayrı bir akıştır (extended data). Terminalde karşılığı
// yok: xterm.js tek akış gösterir ve pty modunda hedef stderr'i zaten
// aynı akışa yazar. Yazılanı stdout'a yönlendiriyoruz, okuma tarafı boş.
func (c *wsChannel) Stderr() io.ReadWriter { return stderrAdapter{c} }

type stderrAdapter struct{ c *wsChannel }

func (s stderrAdapter) Write(p []byte) (int, error) { return s.c.Write(p) }
func (s stderrAdapter) Read([]byte) (int, error)    { return 0, io.EOF }

// wsChannel'ın ssh.Channel'ı gerçekten karşıladığını DERLEME ZAMANINDA
// doğrula: imza değişirse hata testte değil derlemede çıksın.
var _ ssh.Channel = (*wsChannel)(nil)
