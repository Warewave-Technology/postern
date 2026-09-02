package sshd

import (
	"context"
	"net"
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
