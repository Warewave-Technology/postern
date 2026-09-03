//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/config"
	"github.com/Warewave-Technology/postern/internal/store"
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

/*
 * ⚠️ CEVAPSIZ YOKLAMA HER KANALDA TEKRARLANMAMALI.
 *
 * refresh kapısı probed_at'e bakıyor ve o yalnızca BAŞARILI yoklamada
 * yazılıyordu. Yani cevap üretmeyen bir yoklama kapıyı hiç kapatmıyor
 * ve aynı bağlantının her kanalında yeniden koşuyordu. Denetim satırı
 * denemeye taşındıktan sonra bu, her kanalda bir defter satırı demek
 * oldu — başarılı yoklamada beş kanal bir satır yazarken.
 *
 * Üç bedel: hedefin günlüğüne kullanıcının adına tekrar tekrar komut
 * düşüyor, defter aynı cümleyle şişiyor, ve refresh ayarı söylediği
 * şeyi yapmıyor.
 */
func TestFailingProbeIsNotRepeatedOnEveryChannel(t *testing.T) {
	caKeyPath, caAuthorizedKey := newTestCA(t)
	tgt := startCertTarget(t, caAuthorizedKey)
	tc := tgt.target()
	tc.Name = "web01"

	// 1ns: yoklama deterministik olarak cevapsız kalıyor.
	// refresh BELGELENEN varsayılan gibi uzun: kapı kapanmalı.
	tuneConfig = func(c *config.Config) {
		c.TargetProbe.Enabled = true
		c.TargetProbe.Timeout = 1
		c.TargetProbe.Refresh = 24 * time.Hour
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

	// ⚠️ TEK BAĞLANTI, BEŞ KANAL — ControlMaster'ın şekli.
	const channels = 5
	for i := 0; i < channels; i++ {
		sess, serr := client.NewSession()
		if serr != nil {
			t.Fatalf("%d. NewSession: %v", i, serr)
		}
		if _, oerr := sess.Output("echo kanal"); oerr != nil {
			t.Fatalf("%d. exec: %v", i, oerr)
		}
		sess.Close()
	}
	client.Close()

	// Yoklamalar ayrı goroutine'lerde; oturmalarını bekle.
	deadline := time.Now().Add(25 * time.Second)
	rows := 0
	for time.Now().Before(deadline) {
		all, lerr := db.AdminLog(context.Background(), 200)
		if lerr != nil {
			t.Fatal(lerr)
		}
		rows = 0
		for _, e := range all {
			if e.Action == "target.probe" {
				rows++
			}
		}
		if rows >= 1 {
			// Bir satır geldikten sonra kısa bir süre daha bekle:
			// tekrar varsa bu pencerede görünür.
			time.Sleep(3 * time.Second)
			all, _ = db.AdminLog(context.Background(), 200)
			rows = 0
			for _, e := range all {
				if e.Action == "target.probe" {
					rows++
				}
			}
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	t.Logf("kanal = %d, refresh = 24h, target.probe satırı = %d", channels, rows)
	if rows == 0 {
		t.Fatal("hiç yoklama satırı yok — kurgu tutmadı")
	}
	if rows > 1 {
		t.Errorf("%d kanalda %d defter satırı — cevapsız yoklama refresh "+
			"kapısını kapatmıyor, hedefte her kanalda yeniden komut "+
			"çalışıyor ve defter aynı cümleyle şişiyor", channels, rows)
	}
}
