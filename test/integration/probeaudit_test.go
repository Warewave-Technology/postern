//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/config"
	"github.com/warewave/postern/internal/store"
)

/*
 * ⚠️ YOKLAMA, ÇIKTI ÜRETMESE DE DEFTERE YAZILMALI.
 *
 * target_probe açıkken postern, kullanıcının AÇTIĞI bağlantı üzerinde
 * kullanıcının yazmadığı komutları çalıştırıyor ve o komutlar hedefin
 * kendi günlüklerinde O KULLANICININ hesabı altında görünüyor. Özelliğin
 * bu çizgiyi geçme gerekçesi, config.go'nun ve README'nin verdiği söz:
 * "her koşu admin_log'a yazılır".
 *
 * Söz tutulmuyordu. Satır, Probe ve RecordTargetProbe'un İKİSİ DE
 * başarılı olduktan sonra yazılıyordu; kullanılabilir çıktı üretmeyen
 * her koşuda denetim yüzeyi "hiçbir şey olmadı" diyordu. Operatöre
 * güvenmesi söylenen `via = probe` süzgeci, tam da ALIŞILMADIK davranan
 * makineleri eksik raporluyordu — yani bir araştırmacının arayacağı
 * makineleri.
 */
func TestProbeIsAuditedEvenWhenItAnswersNothing(t *testing.T) {
	caKeyPath, caAuthorizedKey := newTestCA(t)
	tgt := startCertTarget(t, caAuthorizedKey)
	tc := tgt.target()
	tc.Name = "web01"

	// ⚠️ 1ns: bağlam Probe koşmadan önce dolmuş oluyor, yani "hedef
	// hiçbir şey söylemedi" dalı DETERMİNİSTİK. Ölçmek istediğimiz şey
	// tam olarak o dal.
	tuneConfig = func(c *config.Config) {
		c.TargetProbe.Enabled = true
		c.TargetProbe.Timeout = 1
		c.TargetProbe.Refresh = time.Nanosecond
	}
	t.Cleanup(func() { tuneConfig = nil })

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
	if _, err := sess.Output("echo yoklama-kanit"); err != nil {
		t.Fatalf("exec: %v", err)
	}
	sess.Close()
	client.Close()

	// Yoklama ayrı goroutine'de ve oturum onu BEKLEMİYOR.
	var row store.AdminLogEntry
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		rows, lerr := db.AdminLog(context.Background(), 200)
		if lerr != nil {
			t.Fatalf("AdminLog: %v", lerr)
		}
		for _, e := range rows {
			if e.Action == "target.probe" {
				row = e
			}
		}
		if row.Action != "" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if row.Action == "" {
		t.Fatal("hedefte kullanıcının yazmadığı komutlar çalıştı ve denetim " +
			"defterinde tek satır yok — `via = probe` süzgeci, alışılmadık " +
			"davranan makineleri eksik raporluyor")
	}
	if row.Actor != "yigit" {
		t.Errorf("actor = %q; komutlar KİMİN bağlantısında koştu belli değil", row.Actor)
	}
	if row.Entity != "web01" {
		t.Errorf("entity = %q, hedef adı bekleniyordu", row.Entity)
	}
	// Hangi komutların koştuğu satırda yazılı: cevabı kaynağa bakmayı
	// gerektirmemeli.
	if !strings.Contains(row.Details, "uname") {
		t.Errorf("details = %q; hangi komutların koştuğunu söylemiyor", row.Details)
	}
	// ⚠️ Ve satır, koşunun cevapsız kaldığını SÖYLÜYOR — başarılı bir
	// yoklamadan ayırt edilemez olsaydı defter yanıltıcı olurdu.
	if !strings.Contains(row.Details, "answered nothing") {
		t.Errorf("details = %q; cevapsız koşu başarılıdan ayırt edilemiyor", row.Details)
	}
}
