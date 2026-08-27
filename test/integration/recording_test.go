//go:build integration

package integration

// Oturum kaydının panelden izlenmesi: kayıt S1.7'den beri yazılıyordu
// ama hiçbir yerden okunamıyordu — denetim dosyası vardı, denetim yoktu.
//
//	go test -tags integration -run TestRecording -v ./test/integration/

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Gerçek bir oturum aç, kaydı panelden indir, içeriğini doğrula.
func TestRecordingIsServedToAdmins(t *testing.T) {
	sshAddr, apiURL, hostPub, db := oobBastion(t, 0)

	if err := db.SetUserAdmin(context.Background(), "yigit", true); err != nil {
		t.Fatal(err)
	}

	// --- oturumu SSH üzerinden aç ve tanınabilir bir çıktı üret ---
	client, err := kiClient(sshAddr, hostPub, approveInBrowser)
	if err != nil {
		t.Fatalf("OOB girişi: %v", err)
	}
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	const marker = "POSTERN_KAYIT_ISARETI"
	if _, err := sess.Output("echo " + marker); err != nil {
		t.Fatalf("exec: %v", err)
	}
	sess.Close()
	client.Close()

	// Oturumun kapanması ve kaydın kapatılması için kısa bir pencere.
	var sessionID string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		recorded, err := db.Sessions(context.Background(), "", 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(recorded) == 1 && !recorded[0].Open() {
			sessionID = recorded[0].ID
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if sessionID == "" {
		t.Fatal("oturum kapanmadı")
	}

	jar, _ := cookiejar.New(nil)
	http1 := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, http1, apiURL)

	t.Run("oturum detayi kayit durumunu soyler", func(t *testing.T) {
		status, body := adminReq(t, http1, "GET", apiURL+"/api/admin/sessions/"+sessionID, "")
		if status != 200 {
			t.Fatalf("durum = %d; gövde: %s", status, body)
		}

		var detail struct {
			ID        string `json:"id"`
			Recording struct {
				State string `json:"state"`
				Size  int64  `json:"size"`
			} `json:"recording"`
		}
		if err := json.Unmarshal([]byte(body), &detail); err != nil {
			t.Fatalf("JSON: %v; gövde: %s", err, body)
		}
		if detail.Recording.State != "complete" {
			t.Errorf("durum = %q, \"complete\" bekleniyordu", detail.Recording.State)
		}
		if detail.Recording.Size == 0 {
			t.Error("kayıt boyutu 0")
		}
	})

	t.Run("kayit indirilebilir ve icerigi dogru", func(t *testing.T) {
		status, body := adminReq(t, http1, "GET", apiURL+"/api/admin/sessions/"+sessionID+"/recording", "")
		if status != 200 {
			t.Fatalf("durum = %d; gövde: %s", status, body)
		}

		lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
		if len(lines) < 2 {
			t.Fatalf("%d satır, başlık + en az bir olay bekleniyordu:\n%s", len(lines), body)
		}

		var header struct {
			Version int `json:"version"`
			Width   int `json:"width"`
			Height  int `json:"height"`
		}
		if err := json.Unmarshal([]byte(lines[0]), &header); err != nil {
			t.Fatalf("başlık ayrıştırılamadı: %v", err)
		}
		if header.Version != 2 {
			t.Errorf("asciicast sürümü = %d", header.Version)
		}

		// Her olay satırı geçerli bir üçlü dizi olmalı — oynatıcının
		// varsaydığı şey bu.
		for i, line := range lines[1:] {
			var ev []json.RawMessage
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				t.Fatalf("olay %d ayrıştırılamadı: %v (%q)", i, err, line)
			}
			if len(ev) != 3 {
				t.Errorf("olay %d %d elemanlı, 3 bekleniyordu", i, len(ev))
			}
		}

		if !strings.Contains(body, marker) {
			t.Errorf("kayıtta oturumun çıktısı yok (%q aranıyordu)", marker)
		}
	})

	// Kaydı KİMİN izlediği de denetlenmeli: kayıtlar başkalarının
	// yazdığı komutları ve çıktılarını içeriyor.
	t.Run("izleme denetim kaydina dusuyor", func(t *testing.T) {
		status, body := adminReq(t, http1, "GET", apiURL+"/api/admin/log", "")
		if status != 200 {
			t.Fatalf("durum = %d", status)
		}
		if !strings.Contains(body, "session.replay") {
			t.Errorf("admin_log'da session.replay yok:\n%s", body)
		}
		if !strings.Contains(body, sessionID) {
			t.Errorf("denetim satırı oturum id'sini taşımıyor")
		}
	})

	t.Run("admin olmayan kaydi alamaz", func(t *testing.T) {
		if err := db.SetUserAdmin(context.Background(), "yigit", false); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.SetUserAdmin(context.Background(), "yigit", true) })

		status, _ := adminReq(t, http1, "GET", apiURL+"/api/admin/sessions/"+sessionID+"/recording", "")
		if status != 403 {
			t.Errorf("durum = %d, 403 bekleniyordu", status)
		}
	})

	t.Run("olmayan oturum 404", func(t *testing.T) {
		status, _ := adminReq(t, http1, "GET",
			apiURL+"/api/admin/sessions/0123456789abcdef0123456789abcdef/recording", "")
		if status != 404 {
			t.Errorf("durum = %d, 404 bekleniyordu", status)
		}
	})
}

var _ = ssh.Dial
