//go:build integration

package archive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/warewave/postern/internal/model"
	"github.com/warewave/postern/internal/objstore"
	"github.com/warewave/postern/internal/record"
	"github.com/warewave/postern/internal/store"
	"github.com/warewave/postern/internal/testdb"
)

// fixedArchiver, sabit bir istemciyle arşivleyici kurar (testler için).
func fixedArchiver(db *store.Store, client *objstore.Client, cfg Config, logger *slog.Logger) *Archiver {
	return New(db, cfg,
		func(context.Context) (objstore.Credentials, error) {
			return objstore.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
		},
		func(objstore.Credentials) (*objstore.Client, error) { return client, nil },
		logger)
}

// newDB, göçleri uygulanmış boş bir veritabanı.
func newDB(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(context.Background(), testdb.DSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return db
}

/*
 * MinIO koşumu.
 *
 * ⚠️ testcontainers/modules/minio KULLANILMIYOR: o modül go.mod'a on
 * kadar yeni bağımlılık getiriyor ve tek ihtiyacımız bir konteyner
 * başlatmak. GenericContainer, depoda zaten kullanılan yol.
 *
 * Konteyner SÜREÇ BOYUNCA PAYLAŞILIYOR (testdb ile aynı desen); testler
 * birbirinden KOVA adıyla ayrılıyor.
 */
const (
	minioImage = "minio/minio:RELEASE.2024-01-16T16-07-38Z"
	minioUser  = "posterntest"
	minioPass  = "posterntest123"
)

var (
	minioOnce     sync.Once
	minioEndpoint string
	minioErr      error
	bucketCounter int
	bucketMu      sync.Mutex
)

func minioURL(t *testing.T) string {
	t.Helper()
	minioOnce.Do(func() {
		ctx := context.Background()
		req := testcontainers.ContainerRequest{
			Image:        minioImage,
			ExposedPorts: []string{"9000/tcp"},
			Env: map[string]string{
				"MINIO_ROOT_USER":     minioUser,
				"MINIO_ROOT_PASSWORD": minioPass,
			},
			Cmd:        []string{"server", "/data"},
			WaitingFor: wait.ForHTTP("/minio/health/live").WithPort("9000/tcp"),
		}
		c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: req, Started: true,
		})
		if err != nil {
			minioErr = err
			return
		}
		host, herr := c.Host(ctx)
		if herr != nil {
			minioErr = herr
			return
		}
		port, perr := c.MappedPort(ctx, "9000/tcp")
		if perr != nil {
			minioErr = perr
			return
		}
		minioEndpoint = fmt.Sprintf("http://%s:%s", host, port.Port())
	})
	if minioErr != nil {
		t.Fatalf("minio: %v", minioErr)
	}
	return minioEndpoint
}

// newBucket, bu test için boş bir kova açar ve adını döner.
func newBucket(t *testing.T, endpoint string) string {
	t.Helper()
	bucketMu.Lock()
	bucketCounter++
	name := fmt.Sprintf("test-%03d", bucketCounter)
	bucketMu.Unlock()

	req, err := http.NewRequest(http.MethodPut, endpoint+"/"+name, nil)
	if err != nil {
		t.Fatal(err)
	}
	signForTest(t, req, sha256Empty())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		t.Fatalf("kova açılamadı: %d %s", resp.StatusCode, body)
	}
	return name
}

func sha256Empty() string {
	sum := sha256.Sum256(nil)
	return hex.EncodeToString(sum[:])
}

/*
 * signForTest, testin BAĞIMSIZ tanığı.
 *
 * ⚠️ Nesnenin varlığını doğrularken postern'in kendi istemcisini
 * kullanmak, "depoda duruyor" ile "istemcimiz duruyor sanıyor"u ayırt
 * edemezdi. Bu yüzden doğrulama düz http.DefaultClient + kendi
 * imzamızla yapılıyor.
 */
func signForTest(t *testing.T, req *http.Request, payloadHash string) {
	t.Helper()
	c, err := objstore.New(objstore.Config{
		Endpoint: "http://127.0.0.1:1",
		Bucket:   "x",
		Region:   "us-east-1",
		Credentials: objstore.Credentials{
			AccessKeyID: minioUser, SecretAccessKey: minioPass,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	c.SignForTest(req, payloadHash)
}

// getObject, nesneyi bağımsız olarak indirir.
func getObject(t *testing.T, endpoint, bucket, key string) ([]byte, int) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, endpoint+"/"+bucket+"/"+key, nil)
	if err != nil {
		t.Fatal(err)
	}
	signForTest(t, req, sha256Empty())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return body, resp.StatusCode
}

// seedFinishedSession, bitmiş bir oturum ve kayıt dosyası kurar.
func seedFinishedSession(t *testing.T, db *store.Store, dir, id, content string) string {
	t.Helper()
	ctx := context.Background()

	if _, err := db.CreateUser(ctx, "yigit", "", "yigit"); err != nil &&
		!isConflict(err) {
		t.Fatal(err)
	}
	if _, err := db.CreateTarget(ctx, model.Target{
		Name: "web01", Host: "10.0.0.1", Port: 22,
		HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIcLUQM0UcoZdJVh2EokribDvFZyyNyAVURM/LrCugFM",
	}); err != nil && !isConflict(err) {
		t.Fatal(err)
	}

	day := filepath.Join(dir, "2026-09-02")
	if err := os.MkdirAll(day, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(day, id+".cast")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := db.StartSession(ctx, store.SessionStart{
		ID: id, Username: "yigit", TargetName: "web01", OSUser: "yigit",
		SrcIP: "10.0.0.9", StartedAt: time.Now().Add(-time.Hour), RecordingPath: path,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.EndSession(ctx, id, time.Now().Add(-30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := db.QueueArchive(ctx, id); err != nil {
		t.Fatal(err)
	}
	return path
}

func isConflict(err error) bool {
	return err != nil && (contains(err.Error(), "already exists") || contains(err.Error(), "conflict"))
}

func contains(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}

func newArchiver(t *testing.T, db *store.Store, dir, endpoint, bucket string) *Archiver {
	t.Helper()
	client, err := objstore.New(objstore.Config{
		Endpoint: endpoint, Bucket: bucket, Region: "us-east-1",
		Credentials: objstore.Credentials{
			AccessKeyID: minioUser, SecretAccessKey: minioPass,
		},
		Timeout: 15 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixedArchiver(db, client, Config{RecordingsDir: dir, Prefix: "postern", Bucket: bucket},
		slog.New(slog.NewTextHandler(os.Stderr, nil)))
}

/*
 * ⚠️ BELİRLEYİCİ TEST: YEREL KAYIT TAMAMEN SİLİNDİKTEN SONRA BAYTLAR
 * HÂLÂ ALINABİLİYOR MU.
 *
 * Veritabanındaki bir bayrağı kontrol eden test, hiçbir şey
 * yüklemeyen bir uygulamayı da geçirirdi. Ölçtüğümüz şey: dosyayı
 * diskten sildikten sonra, AYNI baytlar depodan geri geliyor mu.
 */
func TestArchivedRecordingSurvivesLocalDeletion(t *testing.T) {
	endpoint := minioURL(t)
	bucket := newBucket(t, endpoint)
	db := newDB(t)
	dir := t.TempDir()

	const id = "aaaabbbbccccdddd1111222233334444"
	content := "{\"version\":2,\"width\":80,\"height\":24}\n[0.5,\"o\",\"gizli komut\"]\n"
	seedFinishedSession(t, db, dir, id, content)

	want := sha256.Sum256([]byte(content))

	a := newArchiver(t, db, dir, endpoint, bucket)
	a.RunOnce(context.Background())

	st, found, err := db.ArchiveStateOf(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if !found || !st.Archived {
		t.Fatalf("arşivlenmedi: %+v (son hata: %s)", st, st.LastError)
	}

	// ⚠️ YEREL KOPYAYI YOK ET. Bundan sonra gelen her bayt depodan.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}

	body, code := getObject(t, endpoint, bucket, st.ObjectKey)
	if code != http.StatusOK {
		t.Fatalf("nesne alınamadı: http %d", code)
	}
	got := sha256.Sum256(body)
	if got != want {
		t.Fatalf("içerik farklı:\n gelen  = %x\n gönderilen = %x", got, want)
	}
	if string(body) != content {
		t.Errorf("baytlar birebir değil")
	}
	t.Logf("yerel kayıt silindi, %d bayt depodan aynen geldi (%s)", len(body), st.ObjectKey)
}

/*
 * ⚠️ YÜKLENEMEYEN KAYIT SİLİNMEMELİ — budayıcının kapısı.
 *
 * Dikkatsiz bir uygulama record.Prune'a hiç dokunmaz ve saklama
 * süresi dolduğunda henüz yüklenmemiş kanıtı sessizce siler.
 */
func TestPrunerKeepsUnarchivedAndDeletesArchived(t *testing.T) {
	endpoint := minioURL(t)
	bucket := newBucket(t, endpoint)
	db := newDB(t)
	dir := t.TempDir()

	const okID = "11112222333344445555666677778888"
	const badID = "99998888777766665555444433332222"
	okPath := seedFinishedSession(t, db, dir, okID, "{\"version\":2}\n")
	badPath := seedFinishedSession(t, db, dir, badID, "{\"version\":2}\n")

	// Yalnızca birini arşivle.
	a := newArchiver(t, db, dir, endpoint, bucket)
	a.RunOnce(context.Background())

	// Diğerini kalıcı hataya düşür: dosyasını sil ve satırı yeniden
	// bekleyene çevir — ama arşivlenmemiş kalsın.
	if st, _, _ := db.ArchiveStateOf(context.Background(), badID); st.Archived {
		// İkisi de yüklendiyse ikincisini elle bekleyene çeviremeyiz;
		// bunun yerine yeni bir bekleyen kayıt kuralım.
		t.Log("ikisi de arşivlendi; üçüncü bir bekleyen kayıtla ölçülecek")
	}

	// Üçüncü: hiç arşivlenmemiş.
	const pendingID = "abcdabcdabcdabcdabcdabcdabcdabcd"
	pendingPath := seedFinishedSession(t, db, dir, pendingID, "{\"version\":2}\n")

	// Hepsini saklama süresinin dışına it.
	old := time.Now().Add(-100 * 24 * time.Hour)
	for _, p := range []string{okPath, badPath, pendingPath} {
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}

	res, err := record.Prune(context.Background(), dir, 24*time.Hour, time.Now(), a)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}

	if _, err := os.Stat(pendingPath); err != nil {
		t.Errorf("ARŞİVLENMEMİŞ KAYIT SİLİNDİ — denetim kanıtı kayboldu: %v", err)
	}
	if _, err := os.Stat(okPath); !os.IsNotExist(err) {
		t.Errorf("arşivlenmiş kayıt silinmedi: %v", err)
	}
	if res.KeptUnarchived == 0 {
		t.Error("tutulanlar sayılmamış — sıkışma görünmez olurdu")
	}
	t.Logf("silinen=%d tutulan=%d (%d bayt)", res.Files, res.KeptUnarchived, res.KeptBytes)
}

/*
 * ⚠️ DEPO CEVAP VERMEZKEN BUDAYICI HİÇBİR ŞEY SİLMEMELİ.
 *
 * "Soramadım" ile "güvende" aynı şey değil. Bu dosyadaki diğer hata
 * davranışlarının tersine, burada fail-closed olmak zorundayız.
 */
func TestPruneDeletesNothingWhenTheGateCannotAnswer(t *testing.T) {
	dir := t.TempDir()
	day := filepath.Join(dir, "2026-09-02")
	if err := os.MkdirAll(day, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(day, "deadbeefdeadbeefdeadbeefdeadbeef.cast")
	if err := os.WriteFile(p, []byte("{\"version\":2}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-100 * 24 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}

	_, err := record.Prune(context.Background(), dir, 24*time.Hour, time.Now(), brokenGate{})
	if err == nil {
		t.Fatal("kapı cevap veremezken Prune hata döndürmedi")
	}
	if _, serr := os.Stat(p); serr != nil {
		t.Errorf("kapı cevap veremezken dosya SİLİNDİ: %v", serr)
	}
}

type brokenGate struct{}

func (brokenGate) ArchivedIDs(context.Context, []string) (map[string]bool, error) {
	return nil, fmt.Errorf("veritabanı yok")
}

/*
 * ⚠️ YENİDEN BAŞLATMADAN SONRA BEKLEYEN İŞ YÜKLENMELİ.
 *
 * Bellekte tutulan bir kuyruk her tek süreçli testi geçer ve gerçek
 * hayatta ilk yeniden başlatmada kanıtı kaybeder. Burada arşivleyici
 * NESNESİ atılıp yenisi kuruluyor: dayanıklılık veritabanında.
 */
func TestPendingWorkSurvivesARestart(t *testing.T) {
	endpoint := minioURL(t)
	bucket := newBucket(t, endpoint)
	db := newDB(t)
	dir := t.TempDir()

	const id = "cafecafecafecafecafecafecafecafe"
	seedFinishedSession(t, db, dir, id, "{\"version\":2}\n[0.1,\"o\",\"x\"]\n")

	// Birinci "süreç": depoya ulaşamıyor.
	dead := newArchiverAt(t, db, dir, "http://127.0.0.1:1", bucket)
	dead.RunOnce(context.Background())

	if st, _, _ := db.ArchiveStateOf(context.Background(), id); st.Archived {
		t.Fatal("ulaşılamayan depoya rağmen arşivlenmiş göründü")
	}

	/*
	 * İkinci "süreç": yeni nesne, aynı veritabanı.
	 *
	 * ⚠️ RetryAfter kısaltılıyor. Başarısız bir deneme satırı geri
	 * çekilme süresi boyunca beklemeye alıyor (varsayılan 2 dakika) —
	 * doğru davranış, çünkü kesinti sırasında depoyu ve log'u
	 * boğmuyor. Test o süreyi beklemek yerine kısaltıyor; ölçtüğümüz
	 * şey dayanıklılık, gecikme değil.
	 */
	/*
	 * ⚠️ BEKLEME SÜRESİ GERİ ÇEKİLMEYE GÖRE — ve bu bir düzeltme.
	 *
	 * Zaman damgaları Unix SANİYE, yani aynı saniye içinde hiçbir
	 * RetryAfter değeri satırı uygun yapmıyor. Buraya 2,5 saniye
	 * yazılmıştı ve geri çekilme SABİTKEN (RetryAfter=1s) yeterliydi.
	 *
	 * Geri çekilme üstel olunca (retryAfter * 2^attempts) ilk
	 * başarısızlıktan sonra pencere 2 saniyeye çıktı ve 2,5 saniye
	 * marjinal kaldı: saniye çözünürlüğünde 2,5 saniyelik uyku 2
	 * saniyelik fark üretebiliyor ve `T + 2 < T + 2` yanlış. Test CI'da
	 * bir kez düştü, yerelde geçti — klasik zamanlama kırılganlığı.
	 *
	 * Beş saniye, iki saniyelik pencerenin epey üstünde. Ölçtüğümüz şey
	 * dayanıklılık, gecikme değil.
	 */
	time.Sleep(5 * time.Second)

	alive := newArchiverAt(t, db, dir, endpoint, bucket)
	alive.RunOnce(context.Background())

	st, _, err := db.ArchiveStateOf(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Archived {
		t.Fatalf("yeniden başlatmadan sonra yüklenmedi (son hata: %s)", st.LastError)
	}
}

func newArchiverAt(t *testing.T, db *store.Store, dir, endpoint, bucket string) *Archiver {
	t.Helper()
	client, err := objstore.New(objstore.Config{
		Endpoint: endpoint, Bucket: bucket, Region: "us-east-1",
		Credentials: objstore.Credentials{
			AccessKeyID: minioUser, SecretAccessKey: minioPass,
		},
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixedArchiver(db, client, Config{RecordingsDir: dir, RetryAfter: time.Second, Bucket: bucket},
		slog.New(slog.NewTextHandler(os.Stderr, nil)))
}

/*
 * ⚠️ VERİTABANINDAN GELEN YOL, KAYIT KÖKÜNÜN DIŞINI GÖSTEREMEZ.
 *
 * recording_path bir veritabanı sütunu. Oraya yazabilen her yol, aksi
 * hâlde keyfi bir dosyayı nesne deposuna YÜKLEMEYE dönüşürdü — bariz
 * hedef ca.key_file. Okuma tarafı (record.Store.Open) bunu zaten
 * engelliyor; yazma tarafında engellememek kapıyı arkadan açmak olurdu.
 */
func TestArchiverRefusesAPathOutsideTheRoot(t *testing.T) {
	endpoint := minioURL(t)
	bucket := newBucket(t, endpoint)
	db := newDB(t)
	dir := t.TempDir()

	secret := filepath.Join(t.TempDir(), "ca_ed25519")
	if err := os.WriteFile(secret, []byte("COK-GIZLI-CA-ANAHTARI"), 0o600); err != nil {
		t.Fatal(err)
	}

	const id = "beefbeefbeefbeefbeefbeefbeefbeef"
	seedFinishedSession(t, db, dir, id, "{\"version\":2}\n")

	/*
	 * Yolu kökün dışına çevir: veritabanına yazabilen bir saldırganın
	 * yapacağı şey. store'un böyle bir yolu yazan API'si YOK — o da
	 * bilinçli — bu yüzden test doğrudan SQL kullanıyor.
	 */
	if err := db.SetRecordingPathForTest(context.Background(), id, secret); err != nil {
		t.Fatal(err)
	}

	a := newArchiver(t, db, dir, endpoint, bucket)
	a.RunOnce(context.Background())

	st, _, err := db.ArchiveStateOf(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if st.Archived {
		t.Fatal("kayıt kökünün DIŞINDAKİ dosya nesne deposuna yüklendi")
	}
	if !contains(st.LastError, "outside") {
		t.Errorf("ret sebebi yolu göstermiyor: %q", st.LastError)
	}
}

/*
 * ⚠️ "PUT 200 DÖNDÜ" İLE "NESNE ORADA" AYNI ŞEY DEĞİL.
 *
 * Bu testi bir mutasyon yazdırdı: HEAD doğrulamasını kaldırdım ve
 * mevcut testlerin hiçbiri düşmedi — çünkü hepsinde PUT gerçekten
 * başarılıydı. Yani doğrulama adımı KORUMASIZDI.
 *
 * Burada depo PUT'a 200, HEAD'e 404 diyor: yükleme başarılı görünüyor
 * ama nesne yok. Damga atılırsa budayıcı yerel kopyayı silmeye izin
 * verir ve kanıt tamamen kaybolur. Bu, özelliğin sessizce yalan
 * söyleyebileceği en kötü yol.
 */
func TestPutSuccessWithoutTheObjectIsNotArchived(t *testing.T) {
	db := newDB(t)
	dir := t.TempDir()

	const id = "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0"
	seedFinishedSession(t, db, dir, id, "{\"version\":2}\n")

	// PUT'a 200, HEAD'e 404 diyen depo.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client, err := objstore.New(objstore.Config{
		Endpoint: srv.URL, Bucket: "kova", Region: "us-east-1",
		Credentials: objstore.Credentials{AccessKeyID: "a", SecretAccessKey: "b"},
		Timeout:     5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	a := fixedArchiver(db, client, Config{RecordingsDir: dir, Bucket: "kova"},
		slog.New(slog.NewTextHandler(os.Stderr, nil)))
	a.RunOnce(context.Background())

	st, _, err := db.ArchiveStateOf(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if st.Archived {
		t.Fatal("nesne depoda YOKKEN arşivlenmiş damgası atıldı — " +
			"budayıcı yerel kopyayı silebilirdi")
	}
	if !contains(st.LastError, "verify") {
		t.Errorf("hata doğrulama adımını göstermiyor: %q", st.LastError)
	}
}
