//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/model"
)

// tgtStub, hiç bağlanılmayacak testler için geçerli görünümlü hedef tanımı.
func tgtStub() model.Target {
	return model.Target{
		Name: "web01", Host: "127.0.0.1", Port: 2299,
		HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIcLUQM0UcoZdJVh2EokribDvFZyyNyAVURM/LrCugFM",
	}
}

// S3 bağlantısının "Bitti" kanıtı: gerçek bir oturum, denetim kaydında
// başlangıcı ve bitişi olan TEK bir satır bırakıyor — doğru kullanıcı,
// doğru hedef ve policy'nin verdiği os_user ile.
func TestSessionAuditTrail(t *testing.T) {
	caKeyPath, caAuthorizedKey := newTestCA(t)

	tgt := startCertTarget(t, caAuthorizedKey)
	tc := tgt.target()
	tc.Name = "web01"

	addr, hostPub, signer, db := testServerWithDB(t, caKeyPath, tc)

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "yigit:web01",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         15 * time.Second,
	})
	if err != nil {
		t.Fatalf("proxy'ye bağlanılamadı: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	out, err := sess.Output("echo audit-kanit")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "audit-kanit" {
		t.Fatalf("çıktı = %q", got)
	}
	sess.Close()

	// EndSession, broker döndükten sonra ama istemcinin gördüğü kapanıştan
	// bağımsız bir anda yazılır; kısa bir bekleme payı bırak.
	var recorded []model.Session
	deadline := time.Now().Add(5 * time.Second)
	for {
		recorded, err = db.Sessions(context.Background(), "", 0)
		if err != nil {
			t.Fatalf("Sessions: %v", err)
		}
		if len(recorded) == 1 && !recorded[0].Open() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("denetim kaydı kapanmadı; durum: %+v", recorded)
		}
		time.Sleep(50 * time.Millisecond)
	}

	got := recorded[0]
	if got.User != "yigit" {
		t.Errorf("User = %q, beklenen %q", got.User, "yigit")
	}
	if got.Target != "web01" {
		t.Errorf("Target = %q, beklenen %q", got.Target, "web01")
	}
	// os_user, policy'nin verdiği karar (testServer config'inde "postern").
	if got.OSUser != "postern" {
		t.Errorf("OSUser = %q, beklenen %q — users.os_user yerine policy kararı yazılmalı", got.OSUser, "postern")
	}
	if got.SrcIP == "" || strings.Contains(got.SrcIP, ":") {
		t.Errorf("SrcIP = %q — port ayrılmamış ya da boş", got.SrcIP)
	}
	if got.RecordingPath == "" {
		t.Error("RecordingPath boş — .cast dosyasıyla bağ kopuk")
	}
	if got.StartedAt.IsZero() || got.EndedAt.Before(got.StartedAt) {
		t.Errorf("zamanlar tutarsız: started=%v ended=%v", got.StartedAt, got.EndedAt)
	}
}

// Veritabanı öldüğünde oturum REDDEDİLMELİ — sessizce, kayıtsız devam değil.
// S1.8'deki "kayıt açılamazsa oturum reddedilir" kararının S3 karşılığı:
// denetlenemeyen oturum, olmaması gereken oturumdur.
//
// Handshake'in ÇALIŞTIĞI ana kadar veritabanı sağlıklı (auth da ona
// bakıyor); kanal açılmadan hemen önce kapatıyoruz. Böylece tam olarak
// channel.go'daki "lookup failed → arıza" dallarını vuruyoruz.
func TestSessionRejectedWhenDatabaseDown(t *testing.T) {
	caKeyPath, _ := newTestCA(t)

	// Hedef konteynerine gerek yok: veritabanı kapalıyken hedef
	// çözümlemesine hiç ulaşılamayacak. Yine de config'e bir hedef koyuyoruz
	// ki ret sebebi "unknown target" olmasın.
	tc := tgtStub()

	addr, hostPub, signer, db := testServerWithDB(t, caKeyPath, tc)

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "yigit:web01",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         15 * time.Second,
	})
	if err != nil {
		t.Fatalf("handshake başarısız (veritabanı henüz açıktı): %v", err)
	}
	defer client.Close()

	// Handshake bitti, kimlik doğrulandı. Şimdi veritabanını devir.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := client.NewSession(); err == nil {
		t.Fatal("veritabanı kapalıyken oturum açıldı — denetlenemeyen oturum kabul edilmemeli")
	}
}
