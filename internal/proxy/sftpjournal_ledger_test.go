package proxy

// Zincirin TAMAMI: SFTP paketi → sftpaudit → günlükçü → GERÇEK defter.
//
// ⚠️ NEDEN GERÇEK VERİTABANI. Bu arızanın hiçbir parçası taklitte
// görünmüyordu: sınırı PostgreSQL'in btree indeksi koyuyor, reddi
// PostgreSQL'in UTF-8 doğrulaması veriyor. Sahte bir fileWriter her iki
// satırı da seve seve kabul eder ve testler yeşil yanarken defter
// oturumun bütün dosya olaylarını kaybetmeye devam ederdi.

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/sftpaudit"
	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/testdb"
)

const ledgerHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIcLUQM0UcoZdJVh2EokribDvFZyyNyAVURM/LrCugFM"

// newLedger, göç edilmiş bir depo ve ona bağlı bir oturum satırı kurar.
func newLedger(t *testing.T, sessionID string) *store.Store {
	t.Helper()
	ctx := context.Background()

	st, err := store.Open(ctx, testdb.DSN(t))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if _, err := st.CreateUser(ctx, "yigit", "", "yigit"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := st.CreateTarget(ctx, model.Target{
		Name: "web01", Host: "127.0.0.1", Port: 22, HostKey: ledgerHostKey,
	}); err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	if err := st.StartSession(ctx, store.SessionStart{
		ID: sessionID, Username: "yigit", TargetName: "web01",
		OSUser: "yigit", SrcIP: "10.0.0.1", StartedAt: time.Now(),
	}); err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	return st
}

/*
 * deepPath, n bayt uzunluğunda ve SIKIŞMAYAN bir dizin yolu üretir.
 *
 * ⚠️ TEKRARLI BİR YOL BU TESTİ SESSİZCE ETKİSİZ KILIYOR. PostgreSQL btree
 * girdisini gerekirse sıkıştırıyor: strings.Repeat("derin/", 500) ile
 * kurulan 3 KiB'lık bir yol indekse SIĞIYOR ve satır yazılabiliyor —
 * yani düzeltme geri alındığında test yine yeşil yanardı. Gerçek dosya
 * adları sıkışmaz; sınırı test eden şey de sıkışmayan veri olmalı.
 */
func deepPath(parent string, n int) string {
	r := rand.New(rand.NewSource(42))
	raw := make([]byte, n)
	r.Read(raw)

	var b strings.Builder
	b.WriteString(parent)
	for i, c := range hex.EncodeToString(raw) {
		if i%24 == 0 {
			b.WriteByte('/')
		}
		b.WriteRune(c)
		if b.Len() >= n {
			break
		}
	}
	return b.String()
}

// sftpPacket, tek bir SFTP paketini uzunluk önekiyle kurar.
func sftpPacket(typ byte, fields ...any) []byte {
	body := []byte{typ}
	for _, f := range fields {
		switch v := f.(type) {
		case uint32:
			body = binary.BigEndian.AppendUint32(body, v)
		case string:
			body = binary.BigEndian.AppendUint32(body, uint32(len(v)))
			body = append(body, v...)
		}
	}
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(body))), body...)
}

/*
 * ⚠️ ZİNCİRİN KANITI.
 *
 * İki dosya adı, ikisi de sıradan bir SFTP istemcisinin üretebileceği:
 *
 *   1. 3000 baytlık iç içe dizin yolu — PATH_MAX'ın altında, yani hedefte
 *      GEÇERLİ; btree indeksinin 2704 baytlık sınırının üstünde.
 *   2. Latin-1 adlandırılmış bir dosya — gerçek sunucularda olağan.
 *
 * İkisi de INSERT'i düşürüyordu. Grup tek transaction olduğu için düşen
 * bir satır değil, oturumun BÜTÜN dosya olaylarıydı: aynı gruptaki
 * "/etc/shadow açıldı" satırı da onunla birlikte gidiyordu. Bu testin
 * ölçtüğü şey o satırın deftere ULAŞMASI.
 */
func TestSFTPEventsWithHostilePathsStillLandInTheLedger(t *testing.T) {
	const sessionID = "sess-hostile"
	ctx := context.Background()
	st := newLedger(t, sessionID)

	var failed []error
	/*
	 * recorded=true: bu oturumun bir kaydı var. Satırların InRecording
	 * damgası oradan geliyor ve defteri mühürle karşılaştıran kontrolün
	 * dayanağı o (bkz. sftpjournal.go, recorded).
	 */
	j := newSFTPJournal(st, sessionID, testLogger(), true,
		func(e error) { failed = append(failed, e) })

	// ⚠️ SORUŞTURMANIN SATIRI AYNI GRUPTA: kaybı görünür kılan şey bu.
	audit := sftpaudit.NewSession(j.Emit)
	feed := func(chunk []byte) {
		t.Helper()
		if err := audit.FromClient(chunk); err != nil {
			t.Fatalf("FromClient: %v", err)
		}
	}
	reply := func(chunk []byte) {
		t.Helper()
		if err := audit.FromTarget(chunk); err != nil {
			t.Fatalf("FromTarget: %v", err)
		}
	}

	deep := deepPath("/veri", 3000)
	latin1 := "/home/ali/rapor-\xe7\xf6\xfc.txt"

	const openRead = uint32(1)
	feed(sftpPacket(3 /*fxpOpen*/, uint32(1), "/etc/shadow", openRead, uint32(0)))
	reply(sftpPacket(102 /*fxpHandle*/, uint32(1), "h1"))
	feed(sftpPacket(3, uint32(2), deep, openRead, uint32(0)))
	reply(sftpPacket(102, uint32(2), "h2"))
	feed(sftpPacket(3, uint32(3), latin1, openRead, uint32(0)))
	// Hedef reddediyor: gerekçe metni de hedeften geliyor ve o da deftere
	// giriyor (STATUS mesajı → detail).
	reply(sftpPacket(101 /*fxpStatus*/, uint32(3), uint32(3), strings.Repeat("R", 20<<10), ""))

	written, lost := j.Close()

	if lost != 0 {
		t.Errorf("%d denetim satırı kaybedildi; hepsi yazılabilir olmalıydı", lost)
	}
	if len(failed) != 0 {
		t.Errorf("oturum denetim arızasıyla bitirildi: %v", failed)
	}

	rows, err := st.SessionFiles(ctx, sessionID)
	if err != nil {
		t.Fatalf("SessionFiles: %v", err)
	}
	if int64(len(rows)) != written || written != 3 {
		t.Fatalf("defterde %d satır var, günlükçü %d yazdım diyor, 3 bekleniyordu:\n%+v",
			len(rows), written, rows)
	}

	var sawShadow, sawDeep, sawLatin1 bool
	for _, r := range rows {
		switch {
		case r.Path == "/etc/shadow":
			sawShadow = true
		case strings.HasPrefix(r.Path, "/veri/"):
			sawDeep = true
			if !strings.HasSuffix(r.Path, "(truncated)") {
				t.Errorf("kesilmiş yol işaretlenmemiş: %q", r.Path[len(r.Path)-40:])
			}
		case strings.HasPrefix(r.Path, "/home/ali/rapor-"):
			sawLatin1 = true
			if len(r.Detail) > 1024 {
				t.Errorf("hedefin gerekçesi %d bayt olarak saklandı; "+
					"satırın boyunu karşı taraf belirliyor", len(r.Detail))
			}
		}
	}
	if !sawShadow {
		t.Error("SORUŞTURMANIN SATIRI KAYBOLDU: /etc/shadow açılışı deftere " +
			"girmedi — yazılamayan bir komşu satır grubun tamamını götürdü")
	}
	if !sawDeep {
		t.Error("derin yolun satırı deftere girmedi")
	}
	if !sawLatin1 {
		t.Error("latin-1 adlı dosyanın satırı deftere girmedi")
	}

	// Kesilmiş yol ARANABİLİR kalıyor: üst dizin üzerinden soruşturma
	// çalışmaya devam etmeli.
	found, err := st.FileHistory(ctx, store.FileQuery{Path: "/veri", Under: true})
	if err != nil {
		t.Fatalf("FileHistory: %v", err)
	}
	if len(found) != 1 {
		t.Errorf("kesilmiş yol üst dizininden bulunamadı: %d satır", len(found))
	}
}
