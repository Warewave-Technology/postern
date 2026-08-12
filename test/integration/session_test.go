//go:build integration

package integration

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/upstream"
)

// S1.5 istasyon 2: hedefte ham session kanalı açılıyor ve o kanal üzerinden
// request göndermek gerçekten çalışıyor mu?
//
// Bu test aynı zamanda broker'ın S1.5'te yapacağı işin küçük bir provası:
// kanalı aç → "exec" request'i gönder (WantReply=true, cevabı bekle) →
// çıktıyı oku → hedeften gelen request akışında exit-status'ü yakala.
func TestOpenSession(t *testing.T) {
	tgt := startSSHTarget(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := upstream.Dial(ctx, tgt.targetConfig())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	ch, reqs, err := conn.OpenSession()
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer ch.Close()

	// Hedeften gelen request'leri topla; exit-status buradan çıkacak.
	type exitStatus struct{ Status uint32 }
	exitCh := make(chan uint32, 1)
	go func() {
		for req := range reqs {
			if req.Type == "exit-status" {
				var st exitStatus
				if err := ssh.Unmarshal(req.Payload, &st); err == nil {
					select {
					case exitCh <- st.Status:
					default:
					}
				}
			}
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}()

	// exec: WantReply=true → hedef kabul/red cevabı vermeli.
	ok, err := ch.SendRequest("exec", true, ssh.Marshal(struct{ Command string }{
		Command: "echo hello-from-target; exit 7",
	}))
	if err != nil {
		t.Fatalf("SendRequest(exec): %v", err)
	}
	if !ok {
		t.Fatal("hedef exec isteğini reddetti")
	}

	out, err := io.ReadAll(ch)
	if err != nil {
		t.Fatalf("çıktı okunamadı: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "hello-from-target" {
		t.Fatalf("çıktı = %q, beklenen %q", got, "hello-from-target")
	}

	select {
	case status := <-exitCh:
		if status != 7 {
			t.Fatalf("exit-status = %d, beklenen 7", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("exit-status gelmedi — kanal request akışı çalışmıyor")
	}
}
