package sshd

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

/*
 * ⚠️ KAPANIŞ AÇIK BAĞLANTIYI BEKLEMELİ.
 *
 * Serve, ctx iptal edilince dinleyiciyi kapatıp HEMEN dönüyordu:
 * bağlantıları taşıyan goroutine'leri bekleyen hiçbir şey yoktu.
 * Bedeli kullanıcının rahatsızlığından ibaret değildi — Session.Close
 * hiç çalışmadığı için kayıt yarım kapanıyor ve arşiv kuyruğuna hiç
 * girmiyordu, yani bir yeniden başlatma o oturumların kaydını hem
 * eksik hem yüklenemez bırakıyordu.
 */
func TestServeWaitsForOpenConnections(t *testing.T) {
	cfg := testConfigNoDB(t)
	cfg.Shutdown.DrainTimeout = 3 * time.Second

	srv, err := New(cfg, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx, l) }()

	// Bir bağlantı aç ve el sıkışmasını YARIM bırak: handleConn
	// goroutine'i çalışıyor olacak.
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Serve'in bağlantıyı kabul etmesine izin ver.
	time.Sleep(200 * time.Millisecond)

	start := time.Now()
	cancel()

	select {
	case <-served:
		/*
		 * ⚠️ SÜRE DE ÖLÇÜLÜYOR. Yalnızca "döndü mü" diye baksaydık,
		 * beklemeyi tamamen kaldıran bir değişiklik de geçerdi —
		 * düzeltmeden önceki hâl tam olarak buydu ve o da dönüyordu.
		 * Handshake zaman aşımı bağlantıyı bitirene kadar beklemek
		 * ZORUNDA; anında dönmek beklememek demek.
		 */
		if elapsed := time.Since(start); elapsed < 50*time.Millisecond {
			t.Fatalf("Serve %s içinde döndü: açık bağlantı beklenmedi", elapsed)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Serve hiç dönmedi")
	}
}

// brokenListener, ilk Accept'te gerçek bağlantıyı verir, sonrakilerde
// KALICI bir hata döner (isTemporaryAcceptErr'in eşlemediği bir hata).
type brokenListener struct {
	net.Listener
	served bool
}

func (b *brokenListener) Accept() (net.Conn, error) {
	if !b.served {
		b.served = true
		return b.Listener.Accept()
	}
	return nil, errors.New("accept: listener is permanently broken")
}

// syncBuffer, log'u testin okuyabileceği ve -race'in şikâyet
// etmeyeceği şekilde tutar: bağlantı goroutine'i iddialar koşarken
// yazmaya devam ediyor.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

/*
 * ⚠️ KALICI BİR ACCEPT HATASINDA DA DRAIN KOŞMALI.
 *
 * drain'in başında `if ctx.Err() == nil { return }` vardı ve gerekçesi
 * "kalıcı bir Accept hatasında süreç ölmüyor" diyordu. Ölçüldü: ölüyor.
 * Hata ListenAndServe → RunE → Execute zincirinden geçip os.Exit(1)'e
 * gidiyor. O yolda drain hiç çalışmadığı için açık oturumların denetim
 * satırı açık, kaydı yarım kalıyordu.
 *
 * ctx BURADA HİÇ İPTAL EDİLMİYOR — testin bütün mesele bu: kapanış
 * sinyali yok, yalnızca dinleyici bozuldu.
 */
func TestDrainRunsAfterAPermanentAcceptError(t *testing.T) {
	cfg := testConfigNoDB(t)
	cfg.Shutdown.DrainTimeout = 500 * time.Millisecond
	// El sıkışma süresi uzun: bağlantı goroutine'i beklenirken hâlâ
	// yaşıyor olmalı, yoksa beklemenin ölçüsü kalmaz.
	cfg.Listen.HandshakeTimeout = 20 * time.Second

	logs := &syncBuffer{}
	srv, err := New(cfg, nil, slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	l := &brokenListener{Listener: raw}

	served := make(chan error, 1)
	go func() { served <- srv.Serve(context.Background(), l) }()

	conn, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	start := time.Now()
	select {
	case err := <-served:
		if err == nil {
			t.Fatal("kalıcı Accept hatası nil ile döndü")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Serve dönmedi")
	}
	elapsed := time.Since(start)

	if elapsed < cfg.Shutdown.DrainTimeout/2 {
		t.Errorf("Serve %v'de döndü; drain_timeout %v ve açık bir bağlantı "+
			"vardı — drain atlanıyor ve süreç ölürken oturumların kaydı "+
			"yarım kalıyor", elapsed, cfg.Shutdown.DrainTimeout)
	}

	// ⚠️ SÜRE TEK BAŞINA YETMEZ: başka bir yerde uyuyup drain'i yine
	// atlayan bir değişiklik zamanı geçirirdi. Drain'in KOŞTUĞUNU
	// kendi satırından okuyoruz.
	if got := logs.String(); !strings.Contains(got, "shutdown grace expired") {
		t.Errorf("drain hiç koşmamış; log: %q", got)
	}
}
