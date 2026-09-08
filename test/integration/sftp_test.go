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
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/config"
	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/verify"
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

/*
 * sealOf, kaydın mühür satırındaki iki değeri okur: olay sayısı ve özet.
 *
 * ⚠️ DEĞERLERİ DOSYADAN OKUYORUZ, VERİTABANINDAN DEĞİL. Testin sorusu
 * tam olarak ikisinin aynı olup olmadığı: veritabanındaki değeri alıp
 * kendisiyle karşılaştıran bir test, hiçbir şey ölçmez.
 */
func sealOf(t *testing.T, castPath string) (int64, string) {
	t.Helper()

	body, err := os.ReadFile(castPath)
	if err != nil {
		t.Fatalf("kayıt okunamadı: %v", err)
	}
	m := regexp.MustCompile(`postern sftp: (\d+) events, digest sha256:([0-9a-f]{64})`).
		FindStringSubmatch(string(body))
	if m == nil {
		t.Fatalf("kayıtta mühür satırı yok:\n%s", string(body))
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		t.Fatalf("mühürdeki sayı okunamadı: %v", err)
	}

	return n, m[2]
}

// waitForMarkedSession, oturumun kapanmasını ve defter işaretinin
// yazılmasını bekler.
//
// ⚠️ terminate_test.go'daki waitForClosedSession'dan AYRI: o yalnızca
// ended_at'e bakıyor, defter işareti ise kapanışın SON adımı
// (proxy/lifecycle.go). ended_at'te durmak, işaret yazılmadan okuyup
// "ölçülmemiş" görmek demekti.
func waitForMarkedSession(t *testing.T, db *store.Store) model.Session {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		id := onlySession(t, db)
		s, err := db.Session(context.Background(), id)
		if err != nil {
			t.Fatalf("Session: %v", err)
		}
		// SFTPJournal işareti kapanışın SON adımı (proxy/lifecycle.go);
		// ended_at'i beklemek yetmiyor.
		if !s.Open() && s.SFTPJournal.Measured {
			return s
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("oturum kapanmadı ya da defter işareti yazılmadı")

	return model.Session{}
}

/*
 * ⚠️ KAYIT İLE DEFTER HİÇ KARŞILAŞTIRILMIYORDU.
 *
 * emitSFTP her olayı önce kayda, sonra deftere yazıyor (sftpcast.go) ve
 * kaydın sonuna "N events" mührü düşüyor. O sayının programatik bir
 * tüketicisi yoktu: defterden düşmüş ya da silinmiş bir satır hiçbir
 * yüzeyde görünmüyordu.
 *
 * Bu test kablonun tamamını ölçüyor — gerçek bir istemci, gerçek bir
 * sftp-server, gerçek bir veritabanı: mühürdeki sayı oturumun satırına
 * yazılıyor mu, satır damgaları o sayıyla tutuyor mu, ve karar
 * (verify.JournalOf) "eksiksiz" diyor mu. Birim testleri bu üçünün
 * hiçbirini birlikte göremiyor.
 */
func TestSFTPSessionSealMatchesTheJournal(t *testing.T) {
	client, db := sftpBastion(t, true)

	sc, err := sftp.NewClient(client)
	if err != nil {
		t.Fatalf("sftp oturumu açılamadı: %v", err)
	}

	/*
	 * ⚠️ OLAYLAR KASTEN ÇEŞİTLİ. Satırı iki taraf da üretiyor (kaydı
	 * yazan broker ve defterdeki satırlardan mührü yeniden hesaplayan
	 * kontrol) ve ayrışabilecekleri yerler tam olarak burada: HEDEFTEN
	 * gelen gerekçe metni, ASCII olmayan bir dosya adı, ve başarısız
	 * bir istek. Yalnızca düz bir indirmeyle ölçmek, biçimin kolay
	 * yarısını ölçmek olurdu.
	 */
	remote := "/tmp/postern-journal-seal-ğüşiöç.txt"
	w, err := sc.Create(remote)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := w.Write([]byte("mühür ile defter aynı şeyi söylemeli\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	w.Close()
	if _, err := sc.ReadDir("/tmp"); err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	// Hedefin REDDETTİĞİ bir istek: satırda "[failed]" ve hedefin kendi
	// gerekçe metni var.
	if _, err := sc.Open("/proc/postern-yok/dosya"); err == nil {
		t.Fatal("olmayan dosya açıldı — test ayırt edici değil")
	}
	if err := sc.Remove(remote); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	sc.Close()
	client.Close()

	waitForFiles(t, db, onlySession(t, db), 4)
	s := waitForMarkedSession(t, db)

	if s.RecordingPath == "" {
		t.Fatal("oturumun kaydı yok — test ayırt edici değil")
	}

	/*
	 * 1. Oturumun satırındaki mühür, kayda YAZILAN mühürle aynı olmalı —
	 *    hem sayı hem özet. Özet ayrışırsa kontrol her oturumu
	 *    "değiştirilmiş" diye raporlar; yani yanlış alarmın kaynağı
	 *    tam olarak burası olurdu.
	 */
	wantEvents, wantDigest := sealOf(t, s.RecordingPath)
	if s.SFTPJournal.Events != wantEvents {
		t.Errorf("MÜHÜR İLE OTURUM SATIRI AYRIŞTI: satır %d olay, kayıt %d olay",
			s.SFTPJournal.Events, wantEvents)
	}
	if s.SFTPJournal.Digest != wantDigest {
		t.Errorf("ÖZET AYRIŞTI:\n  satır %s\n  kayıt %s",
			s.SFTPJournal.Digest, wantDigest)
	}
	if s.SFTPJournal.Events == 0 {
		t.Fatal("mühür sıfır olay diyor — bu oturum dosyaya dokundu")
	}
	// 2. Sağlıklı bir oturumda hiçbir olay kaybolmamalı.
	if s.SFTPJournal.Lost != 0 {
		t.Errorf("sağlıklı oturumda %d olay kaybolmuş", s.SFTPJournal.Lost)
	}

	// 3. Ve karar: defter eksiksiz.
	rows, err := db.SessionFiles(context.Background(), s.ID)
	if err != nil {
		t.Fatalf("SessionFiles: %v", err)
	}
	got := verify.JournalOf(s, rows)
	if got.State != verify.JournalIntact {
		t.Errorf("DEFTER EKSİK GÖRÜNDÜ: %v — %s (%d olay, %d satır)",
			got.State, got.Detail, s.SFTPJournal.Events, got.Rows)
	}
	/*
	 * ⚠️ ÖZETİN GERÇEKTEN KARŞILAŞTIRILDIĞI DA ÖLÇÜLÜYOR. "intact"
	 * cevabı, özet hiç bakılmadan da verilebiliyor (mühürde özet
	 * yoksa); ikisini ayırmayan bir test, özet kontrolünü tümüyle
	 * söken bir değişiklikte yeşil kalırdı.
	 */
	if !got.DigestChecked {
		t.Error("satırların ÖZETİ karşılaştırılmadı: kontrol yalnızca sayıya bakmış")
	}
}

/*
 * ⚠️ "KONTROL EDİLMEDİ" CEVABI NADİR OLMAK ZORUNDA.
 *
 * Defter kontrolü mühürdeki sayıya bakıyor ve o sayı oturum
 * kapanırken yazılıyor. İşaret yalnızca SFTP açık oturumlarda
 * yazılsaydı, SFTP'si kapalı bir bastion'da HER oturum sonsuza dek
 * "kontrol edilmedi" görünürdü — ve her oturumda görülen bir
 * "bilmiyorum", okunmayan bir "bilmiyorum"dur. O gürültünün altında
 * gerçek bir eksiklik de fark edilmezdi.
 */
func TestShellSessionIsMarkedAsHavingNoFileEvents(t *testing.T) {
	client, db := sftpBastion(t, false)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if _, err := sess.Output("echo defter-kontrolu"); err != nil {
		t.Fatalf("exec: %v", err)
	}
	sess.Close()
	client.Close()

	s := waitForMarkedSession(t, db)

	if s.SFTPJournal.Events != 0 || s.SFTPJournal.Lost != 0 {
		t.Errorf("kabuk oturumunda dosya olayı sayıldı: %+v", s.SFTPJournal)
	}

	rows, err := db.SessionFiles(context.Background(), s.ID)
	if err != nil {
		t.Fatalf("SessionFiles: %v", err)
	}
	got := verify.JournalOf(s, rows)
	if got.State != verify.JournalIntact {
		t.Errorf("kabuk oturumu için durum = %v (%s)", got.State, got.Detail)
	}
}
