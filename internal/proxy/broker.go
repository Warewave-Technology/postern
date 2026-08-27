package proxy

import (
	"context"
	"io"
	"log/slog"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/record"
)

// requestSender, üzerine request gönderilebilen uç (ssh.Channel bunu sağlar).
// Ayrı arayüz olması test içindir: forwardRequest'i gerçek bağlantı kurmadan
// sınayabiliyoruz.
type requestSender interface {
	SendRequest(name string, wantReply bool, payload []byte) (bool, error)
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

	logger *slog.Logger
}

// New wires an inbound channel to an outbound one.
//
// rec nil geçilebilir (kayıt kapalı). recordInput yalnızca config açıkça
// istediğinde true olmalı.
func New(down ssh.Channel, downR <-chan *ssh.Request, up ssh.Channel, upR <-chan *ssh.Request, rec *record.Writer, recordInput bool, policy RequestPolicy, logger *slog.Logger) *Broker {
	return &Broker{down: down, downR: downR, up: up, upR: upR, rec: rec, recordInput: recordInput, policy: policy, logger: logger}
}

// outputSink returns where target→user bytes should be written: the user's
// channel alone, or that channel tee'd into the recording.
func (b *Broker) outputSink() io.Writer {
	if b.rec != nil {
		return b.idle.wrap(io.MultiWriter(b.down, b.rec.OutputStream()))
	}
	return b.idle.wrap(b.down)
}

// inputSink is the same for user→target bytes, gated by recordInput.
func (b *Broker) inputSink() io.Writer {
	if b.rec != nil && b.recordInput {
		return b.idle.wrap(io.MultiWriter(b.up, b.rec.InputStream()))
	}
	return b.idle.wrap(b.up)
}

// errorSink returns where target→user bytes should be written: the user's
// channel alone, or that channel tee'd into the recording.
func (b *Broker) stderrSink() io.Writer {
	if b.rec != nil {
		return b.idle.wrap(io.MultiWriter(b.down.Stderr(), b.rec.OutputStream()))
	}
	return b.idle.wrap(b.down.Stderr())
}

// Run shuttles data and requests until the session ends, then returns.
func (b *Broker) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	wgCloseSignal := make(chan struct{})
	wg.Add(3)

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
	go b.relayRequests(b.up, b.downR, fromClient, true)

	go func() {
		wg.Wait()
		close(wgCloseSignal)
	}()

	select {
	case <-ctx.Done():
	case <-wgCloseSignal:
	}

	b.down.Close()
	b.up.Close()

	return nil
}

// relayRequests forwards allowed requests from src to dst, answering the
// sender when it asked for a reply.
//
// Reddedilen request HEDEFE HİÇ GİTMEZ ve gönderene başarısız cevap
// döner — SSH'ta "hayır" demenin yolu bu. WantReply yoksa sessizce
// düşer; gönderen zaten cevap beklemiyor.
func (b *Broker) relayRequests(dst ssh.Channel, src <-chan *ssh.Request, dir direction, observe bool) {
	for req := range src {
		if ok, reason := b.policy.allow(dir, req); !ok {
			// Warn seviyesi: bu bir teşhis satırı değil, denetim
			// olayı. Operatör "kim sftp denedi" sorusunu buradan
			// cevaplayacak.
			b.logger.Warn("session request denied",
				"direction", dir.String(),
				"req.type", req.Type,
				"reason", reason,
			)

			if req.WantReply {
				if err := req.Reply(false, nil); err != nil {
					b.logger.Debug("request denial reply failed",
						"error", err,
						"req.type", req.Type,
					)
				}
			}
			continue
		}

		res, err := forwardRequest(dst, req)
		if err != nil {
			b.logger.Debug("request forward failed",
				"error", err,
				"direction", dir.String(),
				"req.type", req.Type,
			)
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

		err = b.rec.Resize(b.clampDim(p.Columns), b.clampDim(p.Rows))
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

		err = b.rec.Resize(b.clampDim(p.Columns), b.clampDim(p.Rows))
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
func (b *Broker) clampDim(v uint32) int {
	if v > maxTerminalDim {
		b.logger.Warn("terminal dimension clamped for recording",
			"value", v, "limit", maxTerminalDim)
		return maxTerminalDim
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
