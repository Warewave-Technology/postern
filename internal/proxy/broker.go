package proxy

import (
	"context"
	"log/slog"
	"sync"

	"golang.org/x/crypto/ssh"
)

// requestSender, üzerine request gönderilebilen uç (ssh.Channel bunu sağlar).
// Ayrı arayüz olması test içindir: forwardRequest'i gerçek bağlantı kurmadan
// sınayabiliyoruz.
type requestSender interface {
	SendRequest(name string, wantReply bool, payload []byte) (bool, error)
}

// Broker, bir kullanıcı kanalı (down) ile bir hedef kanalı (up) arasında
// veriyi ve request'leri iki yönde taşır.
//
// S1.7'de buraya bir *record.Writer eklenecek ve çıktı akışı tee'lenecek.
type Broker struct {
	down  ssh.Channel
	downR <-chan *ssh.Request
	up    ssh.Channel
	upR   <-chan *ssh.Request

	logger *slog.Logger
}

// New wires an inbound channel to an outbound one.
func New(down ssh.Channel, downR <-chan *ssh.Request, up ssh.Channel, upR <-chan *ssh.Request, logger *slog.Logger) *Broker {
	return &Broker{down: down, downR: downR, up: up, upR: upR, logger: logger}
}

// Run shuttles data and requests until the session ends, then returns.
func (b *Broker) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	wgCloseSignal := make(chan struct{})
	wg.Add(3)

	go func() {
		n, err := pipe(b.up, b.down, true)
		if err != nil {
			b.logger.Error("down->up pipe failed",
				"error", err,
				"count", n,
			)
		}
	}()

	go func() {
		defer wg.Done()

		n, err := pipe(b.down, b.up, false)
		if err != nil {
			b.logger.Error("up->down pipe failed",
				"error", err,
				"count", n,
			)
		}
	}()

	go func() {
		defer wg.Done()

		n, err := pipe(b.down.Stderr(), b.up.Stderr(), false)
		if err != nil {
			b.logger.Error("up.stderr->down.stderr pipe failed",
				"error", err,
				"count", n,
			)
		}
	}()

	go func() {
		defer wg.Done()

		b.relayRequests(b.down, b.upR, "upR->down")
	}()
	go b.relayRequests(b.up, b.downR, "downR->up")

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

// relayRequests forwards every request from src to dst, answering the sender
// when it asked for a reply.
func (b *Broker) relayRequests(dst ssh.Channel, src <-chan *ssh.Request, direction string) {
	for req := range src {
		res, err := forwardRequest(dst, req)
		if err != nil {
			b.logger.Debug("request forward failed",
				"error", err,
				"direction", direction,
				"req.type", req.Type,
			)
		}

		if req.WantReply {
			err = req.Reply(res, nil)
			if err != nil {
				b.logger.Debug("request reply failed",
					"error", err,
					"direction", direction,
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
