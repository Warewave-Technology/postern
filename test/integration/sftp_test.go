//go:build integration

package integration

/*
 * SFTP'nin UÇTAN UCA denetlendiğinin kanıtı.
 *
 * ⚠️ NİYE GERÇEK BİR İSTEMCİ VE GERÇEK BİR sftp-server:
 * çözümleyicinin birim testleri paketleri kendisi kuruyor. O testler
 * çözümleyicinin kendi varsayımlarını doğruluyor — varsayımlar yanlışsa
 * ikisi birlikte yanlış olur ve test yeşil kalır. Burada paketleri
 * pkg/sftp üretiyor, cevapları OpenSSH'in sftp-server'ı veriyor;
 * ikisinin arasında duran postern'in ne gördüğü ölçülüyor.
 *
 * Hedefin sftp-server'a sahip olması testin ayırt ediciliğinin şartı
 * (aynı gerekçe request_filter_test.go'da yazılı).
 */

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/config"
	"github.com/warewave/postern/internal/store"
)

// sftpBastion, SFTP'si AÇIK bir bastion ve ona bağlı bir istemci kurar.
func sftpBastion(t *testing.T, on bool) (*ssh.Client, *store.Store) {
	t.Helper()

	caKeyPath, caAuthorizedKey := newTestCA(t)
	tgt := startCertTarget(t, caAuthorizedKey)
	tc := tgt.target()
	tc.Name = "web01"

	tuneConfig = func(c *config.Config) { c.Session.SFTP = on }
	t.Cleanup(func() { tuneConfig = nil })

	srv, hostPub, signer, db := newBastionOpts(t, caKeyPath, false, tc)
	addr := startBastion(t, srv)

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "yigit:web01",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         15 * time.Second,
	})
	if err != nil {
		t.Fatalf("proxy'ye bağlanılamadı: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client, db
}

// waitForFiles, denetim satırlarının yazılmasını bekler.
//
// Günlükçü olayları toplu yazıyor (veri yolunda veritabanı turu olmasın
// diye), o yüzden yazımın oturumdan biraz sonra bitmesi normal.
func waitForFiles(t *testing.T, db *store.Store, sessionID string, want int) []store.SessionFile {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var last []store.SessionFile
	for time.Now().Before(deadline) {
		f, err := db.SessionFiles(context.Background(), sessionID)
		if err != nil {
			t.Fatalf("SessionFiles: %v", err)
		}
		last = f
		if len(f) >= want {
			return f
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("dosya olayı yazılmadı: %d satır var, en az %d bekleniyordu: %+v",
		len(last), want, last)
	return nil
}

// onlySession, tek oturumun kimliğini döner.
func onlySession(t *testing.T, db *store.Store) string {
	t.Helper()
	ss, err := db.Sessions(context.Background(), "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(ss) != 1 {
		t.Fatalf("oturum sayısı = %d", len(ss))
	}
	return ss[0].ID
}

/*
 * ⚠️ BU TEST, KANALIN NİYE YILLARCA KAPALI KALDIĞINI ÖLÇÜYOR.
 *
 * Süzgeç yazılmadan önce `subsystem sftp` uçtan uca çalışıyordu ve
 * transfer .cast kaydına ham ikili olarak düşüyordu: oynatılamaz ve
 * "kim hangi dosyayı aldı" cevapsız. Kanal ancak o soru cevaplandığı
 * için geri açıldı; burada cevabın GERÇEK bir istemci-sunucu çifti
 * arasında da üretildiği doğrulanıyor.
 */
func TestSFTPDownloadIsAuditedPerFile(t *testing.T) {
	client, db := sftpBastion(t, true)

	sc, err := sftp.NewClient(client)
	if err != nil {
		t.Fatalf("sftp oturumu açılamadı (session.sftp açıkken açılmalıydı): %v", err)
	}
	defer sc.Close()

	// Hedefte bilinen içerikte bir dosya oluştur ve geri indir.
	const body = "postern-sftp-denetim-kanıtı\n"
	remote := "/tmp/postern-sftp-test.txt"

	w, err := sc.Create(remote)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r, err := sc.Open(remote)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	r.Close()

	// Baytlar BOZULMADAN geçmiş olmalı: postern araya bir SFTP sunucusu
	// koymuyor, yalnızca kopyayı çözümlüyor.
	if string(got) != body {
		t.Fatalf("içerik bozuldu: %q", string(got))
	}
	sc.Close()
	client.Close()

	files := waitForFiles(t, db, onlySession(t, db), 2)

	var wrote, read *store.SessionFile
	for i := range files {
		f := &files[i]
		if f.Op != "transfer" || f.Path != remote {
			continue
		}
		if f.Wrote > 0 {
			wrote = f
		}
		if f.Read > 0 {
			read = f
		}
	}
	if wrote == nil {
		t.Fatalf("yükleme denetim satırı yok: %+v", files)
	}
	if read == nil {
		t.Fatalf("indirme denetim satırı yok: %+v", files)
	}
	if wrote.Wrote != int64(len(body)) {
		t.Errorf("yazılan = %d, %d bekleniyordu", wrote.Wrote, len(body))
	}
	if read.Read != int64(len(body)) {
		t.Errorf("okunan = %d, %d bekleniyordu", read.Read, len(body))
	}
	if !strings.Contains(wrote.Flags, "write") {
		t.Errorf("yükleme bayrakları = %q", wrote.Flags)
	}
}

// Silme ve yeniden adlandırma da dosya seviyesinde görünmeli.
func TestSFTPRemoveAndRenameAreAudited(t *testing.T) {
	client, db := sftpBastion(t, true)

	sc, err := sftp.NewClient(client)
	if err != nil {
		t.Fatal(err)
	}

	src := "/tmp/postern-rename-src.txt"
	dst := "/tmp/postern-rename-dst.txt"
	f, err := sc.Create(src)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("x"))
	f.Close()

	if err := sc.Rename(src, dst); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if err := sc.Remove(dst); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	sc.Close()
	client.Close()

	files := waitForFiles(t, db, onlySession(t, db), 4)

	var sawRename, sawRemove bool
	for _, f := range files {
		if f.Op == "rename" && f.Path == src && f.NewPath == dst && f.OK {
			sawRename = true
		}
		if f.Op == "remove" && f.Path == dst && f.OK {
			sawRemove = true
		}
	}
	if !sawRename {
		t.Errorf("yeniden adlandırma denetime girmedi: %+v", files)
	}
	if !sawRemove {
		t.Errorf("silme denetime girmedi: %+v", files)
	}
}

/*
 * ⚠️ REDDEDİLEN İŞLEM "OLMUŞ" GİBİ YAZILMAMALI.
 *
 * Denetim isteği değil SONUCU kaydediyor. İzinsizlikten dönen bir silme
 * "silindi" diye görünseydi, soruşturma var olan bir dosyayı yok
 * sayardı.
 */
func TestSFTPDeniedOperationIsRecordedAsDenied(t *testing.T) {
	client, db := sftpBastion(t, true)

	sc, err := sftp.NewClient(client)
	if err != nil {
		t.Fatal(err)
	}

	// Var olmayan bir dizinde dosya açmayı dene: hedef reddedecek.
	missing := "/proc/postern-yok/dosya"
	if _, err := sc.Open(missing); err == nil {
		t.Fatal("olmayan dosya açıldı — test ayırt edici değil")
	}
	sc.Close()
	client.Close()

	files := waitForFiles(t, db, onlySession(t, db), 1)

	var found bool
	for _, f := range files {
		if f.Op == "open" && f.Path == missing {
			found = true
			if f.OK {
				t.Error("başarısız açma OK=true yazıldı")
			}
		}
	}
	if !found {
		t.Fatalf("reddedilen açma denetime girmedi: %+v", files)
	}
}

// Varsayılan yapılandırmada SFTP hâlâ KAPALI olmalı.
//
// ⚠️ Bu, request_filter_test.go'daki testin tamamlayıcısı: orada
// varsayılanın reddettiği, burada ayarın açtığı ölçülüyor. İkisi
// birlikte "yükseltme yapan operatör habersiz bir çıkış yolu kazanmaz"
// iddiasını sabitliyor.
func TestSFTPStaysClosedUnlessEnabled(t *testing.T) {
	client, _ := sftpBastion(t, false)

	if _, err := sftp.NewClient(client); err == nil {
		t.Fatal("session.sftp kapalıyken sftp oturumu açıldı")
	}
}
