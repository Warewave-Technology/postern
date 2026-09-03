//go:build integration

package integration

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/upstream"
)

// tarpit, TCP bağlantısını kabul eden ama SSH banner'ı hiç göndermeyen bir
// dinleyici döner. Ölü bir sunucu, kasıtlı bir tarpit ya da tüm TCP'yi kabul
// eden bir ara katman gerçek hayatta tam böyle davranır.
func tarpit(t *testing.T) (host string, port int) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var conns []net.Conn

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c) // hiçbir şey yazma: karşı taraf beklesin
			mu.Unlock()
		}
	}()

	t.Cleanup(func() {
		l.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})

	addr := l.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port
}

// Dial'ın TAMAMI ctx'e uymalı — yalnızca TCP fazı değil, SSH el sıkışması da.
//
// ⚠️ ssh.NewClientConn'un kendi zaman aşımı YOKTUR; ClientConfig.Timeout
// sadece ssh.Dial'ın TCP bağlantısına uygulanır (x/crypto client.go:204).
// Yani TCP'yi kabul edip el sıkışmayan bir hedef, önlem alınmazsa Dial'ı
// sonsuza dek tutar — bastion için kaynak tüketimi açığı (plan Ek B:
// "Timeout'lar tanımlı: handshake, idle, toplam").
//
// Docker gerektirmez: hedefin el sıkışmaya hiç başlamaması yeterli.
// Host key pinleme ve sertifika kabulü cert_test.go'nun konusu.
func TestDialRespectsContext(t *testing.T) {
	host, port := tarpit(t)
	authority := testAuthority(t)

	cfg := model.Target{
		Name:    "tarpit",
		Host:    host,
		Port:    port,
		HostKey: authority.AuthorizedKey(), // el sıkışma hiç bitmeyecek; değer önemsiz
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	start := time.Now()
	_, err := upstream.DialWithCert(ctx, cfg, upstream.Identity{
		PosternUser: "yigit@warewave.io",
		OSUser:      "postern",
	}, authority)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("el sıkışmayan hedefe bağlanma başarılı olamaz")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("ctx'e saygı gösterilmedi: %v sürdü (beklenen ~1s) — SSH el sıkışması sınırsız", elapsed)
	}
}
