//go:build integration

package integration

/*
 * Panelin dosya tarayıcısının UÇTAN UCA kanıtı.
 *
 * ⚠️ NİYE GERÇEK BİR SFTP İSTEMCİSİ VE GERÇEK BİR sftp-server:
 * paketleri pkg/sftp üretiyor, cevapları OpenSSH veriyor, arada postern
 * duruyor. Kanalın kendi birim testleri yalnızca "subsystem sftp diye
 * sorduk" diyebiliyor; bu dosya "soru hedefe ULAŞTI, cevap geri geldi ve
 * politika arada ÇALIŞTI" diyor.
 *
 * Ölçülen üç şey, üçü de bu yüzeyin açılma şartıydı:
 *   1. Yol kuralı olmayan hesapta kanal HİÇ açılmıyor (fail-closed).
 *   2. Kural varken gezinme çalışıyor.
 *   3. Rol YAZMAYA İZİNLİ olsa bile panelden yazma reddediliyor.
 *
 *	go test -tags integration -run TestFileBrowser -v ./test/integration/
 */

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/pkg/sftp"

	"github.com/Warewave-Technology/postern/internal/config"
	"github.com/Warewave-Technology/postern/internal/httpapi"
	"github.com/Warewave-Technology/postern/internal/record"
	"github.com/Warewave-Technology/postern/internal/store"
)

/*
 * wsPipe, panelin websocket'ini SFTP istemcisinin beklediği borulara
 * çevirir.
 *
 * ⚠️ ZARFI BURADA AÇIYORUZ ve testin ayırt ediciliği buna dayanıyor:
 * sunucu→istemci her çerçevenin ilk baytı akış etiketi (0 veri, 1
 * stderr). Etiketi ayıklamayan bir okuyucu SFTP çözümleyicisine her
 * çerçevede bir bayt fazla verirdi. Yani bu tip aynı zamanda zarfın
 * tarayıcı tarafındaki sözleşmesinin testi.
 */
type wsPipe struct {
	ctx  context.Context
	c    *websocket.Conn
	rest []byte

	mu     sync.Mutex
	stderr strings.Builder
}

func (p *wsPipe) Read(b []byte) (int, error) {
	for len(p.rest) == 0 {
		typ, data, err := p.c.Read(p.ctx)
		if err != nil {
			return 0, err
		}
		if typ != websocket.MessageBinary || len(data) < 1 {
			continue
		}
		switch data[0] {
		case 0:
			p.rest = data[1:]
		case 1:
			// Gerekçe metni: SFTP akışına KARIŞTIRILMAMALI, yoksa
			// çözümleyici onu paket sanar.
			p.mu.Lock()
			p.stderr.Write(data[1:])
			p.mu.Unlock()
		}
	}
	n := copy(b, p.rest)
	p.rest = p.rest[n:]

	return n, nil
}

func (p *wsPipe) Write(b []byte) (int, error) {
	if err := p.c.Write(p.ctx, websocket.MessageBinary, b); err != nil {
		return 0, err
	}

	return len(b), nil
}

// Close, kapanış el sıkışmasını BEKLEMİYOR: karşı taraf okumayı bırakmış
// olabilir ve o hâlde Close beş saniye boşuna bekliyor.
func (p *wsPipe) Close() error { return p.c.CloseNow() }

/*
 * waitForNotice, gerekçenin gelmesini BEKLER.
 *
 * ⚠️ TEK SEFERLİK OKUMA YARIŞ. Gerekçe stderr akışından asenkron
 * geliyor: istemcinin isteği hata ile dönmüş olsa bile, o metin henüz
 * websocket'ten çıkmamış olabilir. Ölçüldü — testler tek başına
 * geçiyordu, CI'da yükün altında üçü birden düşüyordu ve mesaj "gerekçe
 * salt-okunur demiyor: \"\"" idi. Yani test, sunucunun söylediğini
 * duymadan sormuştu.
 */
func waitForNotice(t *testing.T, pipe *wsPipe, want string) string {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if n := pipe.notices(); strings.Contains(n, want) {
			return n
		}
		time.Sleep(50 * time.Millisecond)
	}

	return pipe.notices()
}

// takeNotices, biriken gerekçeleri OKUYUP TEMİZLER.
//
// ⚠️ Var olma sebebi ölçüldü: bir testin ÖNCEKİ adımı "read-only"
// gerekçesi üretiyorsa, sonraki adımın iddiası onu bulup YANLIŞ SEBEPTEN
// geçiyor. Aradaki sınırı çizmenin tek yolu biriken notları almak.
func (p *wsPipe) takeNotices() string {
	p.mu.Lock()
	defer p.mu.Unlock()

	out := p.stderr.String()
	p.stderr.Reset()

	return out
}

func (p *wsPipe) notices() string {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.stderr.String()
}

/*
 * tuneWebAPI, düzenek kurulurken web API'sine dokunma kancası.
 *
 * ⚠️ Var olma sebebi: dosya tarayıcısı VARSAYILAN KAPALI ve öyle
 * kalmalı. Düzeneğe kalıcı bir "sftpPanel bool" parametresi eklemek,
 * yarın birinin onu true geçmesini bir satırlık iş yapardı; kanca,
 * açmayı bilerek yapan testin dosyasında bırakıyor.
 */
var tuneWebAPI func(*httpapi.Server)

// browserBastionWithFileBrowser, dosya tarayıcısı AÇIK düzenek.
func browserBastionWithFileBrowser(t *testing.T) (apiURL string, db *store.Store) {
	t.Helper()

	return browserBastionWithFiles(t, false)
}

// browserBastionWithUploads, yüklemenin de AÇIK olduğu düzenek.
func browserBastionWithUploads(t *testing.T) (apiURL string, db *store.Store) {
	t.Helper()

	return browserBastionWithFiles(t, true)
}

func browserBastionWithFiles(t *testing.T, write bool) (apiURL string, db *store.Store) {
	t.Helper()

	// session.sftp olmadan alt sistem kapalı; panel bayrağı serve.go'da
	// zaten onunla VE'leniyor, burada ikisini de açıyoruz.
	tuneConfig = func(c *config.Config) { c.Session.SFTP = true }
	tuneWebAPI = func(s *httpapi.Server) {
		s.SetSFTPPanel(true)
		s.SetSFTPPanelWrite(write)
	}
	t.Cleanup(func() { tuneConfig = nil; tuneWebAPI = nil })

	_, apiURL, _, db = oobBastionWithTerminal(t)

	return apiURL, db
}

func dialFileBrowser(t *testing.T, client *http.Client, apiURL, target string) (*websocket.Conn, *http.Response, error) {
	t.Helper()

	wsURL := strings.Replace(apiURL, "http://", "ws://", 1) + "/api/sftp/" + target

	header := http.Header{}
	header.Set("Origin", apiURL)

	return websocket.Dial(context.Background(), wsURL, &websocket.DialOptions{
		HTTPClient: client,
		HTTPHeader: header,
	})
}

/*
 * TestFileBrowserIsClosedWithoutPathRules — bu yüzeyin ERTELEMESİNİ
 * kaldıran gerekçenin testi.
 *
 * ⚠️ NİYE ÖNEMLİ: kuralsız bir rol kısıtsızdır (policy.SFTPDecider) ve
 * taze kurulumda hiçbir rolün kuralı yok. "Yol politikası riski sınırlar"
 * diyerek açtığımız bir özelliğin, politikanın hiç kurulmadığı yerde
 * kendiliğinden AÇIK olması, gerekçeyi tam tersine çevirirdi.
 */
func TestFileBrowserIsClosedWithoutPathRules(t *testing.T) {
	apiURL, _ := browserBastionWithFileBrowser(t)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)

	conn, resp, err := dialFileBrowser(t, client, apiURL, "web01")
	if err == nil {
		conn.CloseNow()
		t.Fatal("yol kuralı yokken kanal AÇILDI — fail-closed değil")
	}
	if resp == nil {
		t.Fatalf("cevap yok: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("durum %d, 403 bekleniyordu", resp.StatusCode)
	}

	// Terminal aynı hesapta ÇALIŞMAYA DEVAM etmeli: kapatılan şey dosya
	// tarayıcısı, oturumun kendisi değil.
	tconn, _, terr := dialTerminal(t, client, apiURL, "web01", apiURL)
	if terr != nil {
		t.Fatalf("terminal de kapandı — kapsam çok geniş: %v", terr)
	}
	tconn.Close(websocket.StatusNormalClosure, "")
}

/*
 * TestFileBrowserBrowsesAndRefusesWrites — asıl kanıt.
 *
 * Rol kuralı /tmp'ye YAZMAYA da izin veriyor; buna rağmen panelden yazma
 * reddedilmeli. Kısıt sunucuda, çünkü panelin JavaScript'i onu taşıyamaz:
 * çalınmış bir oturum FXP_WRITE'ı elle yazar.
 */
func TestFileBrowserBrowsesAndRefusesWrites(t *testing.T) {
	apiURL, db := browserBastionWithFileBrowser(t)

	ctx := context.Background()
	if err := db.SetRolePath(ctx, "ops", "/tmp", true, true); err != nil {
		t.Fatalf("SetRolePath: %v", err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)

	conn, _, err := dialFileBrowser(t, client, apiURL, "web01")
	if err != nil {
		t.Fatalf("dosya tarayıcısı açılamadı: %v", err)
	}
	conn.SetReadLimit(2 << 20)

	dialCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	pipe := &wsPipe{ctx: dialCtx, c: conn}
	defer pipe.Close()

	cli, err := sftp.NewClientPipe(pipe, pipe)
	if err != nil {
		t.Fatalf("SFTP el sıkışması: %v (gerekçe: %q)", err, pipe.notices())
	}

	// 1. GEZİNME ÇALIŞIYOR.
	if _, err := cli.ReadDir("/tmp"); err != nil {
		t.Fatalf("/tmp listelenemedi: %v (gerekçe: %q)", err, pipe.notices())
	}

	// 2. KURAL DIŞI YOL REDDEDİLİYOR.
	if _, err := cli.ReadDir("/etc"); err == nil {
		t.Error("/etc listelendi — yol politikası panelde çalışmıyor")
	}

	// 3. ROL YAZABİLİR OLSA BİLE PANELDEN YAZMA REDDEDİLİYOR.
	f, err := cli.Create("/tmp/postern-panel-write-probe")
	if err == nil {
		f.Close()
		cli.Remove("/tmp/postern-panel-write-probe")
		t.Fatal("panelden dosya YARATILDI — salt-okunur kısıt yok")
	}
	if err := cli.Mkdir("/tmp/postern-panel-dir-probe"); err == nil {
		cli.RemoveDirectory("/tmp/postern-panel-dir-probe")
		t.Error("panelden dizin yaratıldı")
	}

	// 4. GEREKÇE KULLANICIYA ULAŞIYOR — "not found" değil, sebep.
	if n := pipe.notices(); !strings.Contains(n, "read-only") {
		t.Errorf("stderr gerekçesi salt-okunur demiyor: %q", n)
	}
}

/*
 * TestPathRulesWrittenFromThePanelOpenTheBrowser — DÖNGÜNÜN KAPANDIĞININ
 * kanıtı.
 *
 * ⚠️ NİYE BU TEST VAR. Dosya tarayıcısı, yol kuralı olmayan bir hesapta
 * kendini kapatıyor ve kullanıcıya "bir yöneticiden `postern role path
 * set` çalıştırmasını isteyin" diyor. Kuralları yalnızca CLI yazabildiği
 * sürece panel, kendi içinde çözülemeyen bir duvara götürüyordu:
 * yöneticinin panelden çıkıp bir kabuk bulması gerekiyordu.
 *
 * Ölçülen şey, kuralın panelin KENDİ ucundan yazılabildiği ve yazıldığı
 * anda tarayıcının açıldığı. İkisini ayrı ayrı bilmek yetmiyordu —
 * arada duran şey (kuralın rolün adına doğru bağlanması) tam olarak
 * sessizce yanlış olabilecek yer.
 */
func TestPathRulesWrittenFromThePanelOpenTheBrowser(t *testing.T) {
	apiURL, db := browserBastionWithFileBrowser(t)

	ctx := context.Background()
	if err := db.SetUserAdmin(ctx, "yigit", true); err != nil {
		t.Fatal(err)
	}
	if err := db.AllowIdentityBind(ctx, "yigit", time.Now()); err != nil {
		t.Fatal(err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)

	// Kural YOKKEN kapalı.
	if conn, resp, err := dialFileBrowser(t, client, apiURL, "web01"); err == nil {
		conn.CloseNow()
		t.Fatal("kuralsızken açıldı")
	} else if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("beklenen 403 değil: %v", err)
	}

	// Panelin ucundan kuralı yaz.
	if code, body := adminReq(t, client, "POST",
		apiURL+"/api/admin/roles/ops/paths",
		`{"prefix":"/tmp","allow":true,"can_write":false}`); code != http.StatusOK {
		t.Fatalf("kural yazılamadı: %d %s", code, body)
	}

	// Uç, yazdığını geri veriyor.
	code, body := adminReq(t, client, "GET", apiURL+"/api/admin/roles/ops/paths", "")
	if code != http.StatusOK {
		t.Fatalf("kurallar okunamadı: %d %s", code, body)
	}
	var rules []struct {
		Prefix   string `json:"prefix"`
		Allow    bool   `json:"allow"`
		CanWrite bool   `json:"can_write"`
	}
	if err := json.Unmarshal([]byte(body), &rules); err != nil {
		t.Fatalf("cevap çözülemedi: %v (%s)", err, body)
	}
	if len(rules) != 1 || rules[0].Prefix != "/tmp" || !rules[0].Allow || rules[0].CanWrite {
		t.Fatalf("kural beklenen hâlde değil: %+v", rules)
	}

	// ARTIK AÇILIYOR — CLI'ye hiç gidilmeden.
	conn, _, err := dialFileBrowser(t, client, apiURL, "web01")
	if err != nil {
		t.Fatalf("kural yazıldıktan sonra da açılmadı: %v", err)
	}
	defer conn.CloseNow()

	/*
	 * ⚠️ GÖRELİ ÖNEK REDDEDİLİYOR ve sebebi söylüyor. Şemada CHECK de
	 * var; ama "constraint violation" dönen bir cevap, kuralı yazan
	 * kişiye ne yapması gerektiğini söylemiyor.
	 */
	if code, body := adminReq(t, client, "POST",
		apiURL+"/api/admin/roles/ops/paths",
		`{"prefix":"var/log","allow":true}`); code != http.StatusBadRequest {
		t.Errorf("göreli önek kabul edildi: %d %s", code, body)
	} else if !strings.Contains(body, "absolute") {
		t.Errorf("sebep söylenmiyor: %s", body)
	}

	// Silme önekı GÖVDEDEN alıyor: adres parçasına kaçırılmış bir yol,
	// araya giren vekillerce normalleştirilip başkasını silebilirdi.
	if code, body := adminReq(t, client, "DELETE",
		apiURL+"/api/admin/roles/ops/paths", `{"prefix":"/tmp"}`); code != http.StatusOK {
		t.Fatalf("kural silinemedi: %d %s", code, body)
	}
	if left, err := db.RolePaths(ctx, "ops"); err != nil || len(left) != 0 {
		t.Fatalf("kural silinmedi: %v %v", left, err)
	}
}

/*
 * TestBrowsingCostsOneRowPerDirectory — defterin gezinme karşısındaki
 * davranışının ÖLÇÜMÜ.
 *
 * ⚠️ RİSK NEYDİ: proxy.journalCap 10000 ve aşılırsa oturum ÖLÜYOR. Bir
 * arayüz, elle yazan bir SFTP istemcisinden çok daha hızlı istek
 * üretiyor. Satır sayısı gezinmeyle nasıl büyüyorsa, tavanın bu yüzey
 * için ne anlama geldiği de o.
 *
 * ⚠️ ÖLÇÜM BİR VARSAYIMI ÇÜRÜTTÜ. "İzin verilen üstveri okumaları
 * deftere hiç girmiyor" sanıyordum; girmiyorlar, AMA opendir giriyor.
 * Gerçek şu: DİZİN BAŞINA BİR SATIR, içindeki dosya sayısından bağımsız.
 * readdir, stat ve close hiçbir satır bırakmıyor.
 *
 * Bu iyi bir denge ve test onu ikisinden de koruyor:
 *   - Satır sayısı girdi başına OLSAYDI, 500 dosyalık tek bir dizin tek
 *     tıklamada 500 satır yazardı ve tavan gerçek bir sınır olurdu.
 *   - Hiç satır olmasaydı, "hangi dizinlere bakıldı" sorusu cevapsız
 *     kalırdı — bu ürünün iddiasının tam ortasındaki soru.
 *
 * 10000'e ulaşmak için tek oturumda 10000 dizin açmak gerekiyor.
 */
func TestBrowsingCostsOneRowPerDirectory(t *testing.T) {
	apiURL, db := browserBastionWithFileBrowser(t)

	ctx := context.Background()
	if err := db.SetRolePath(ctx, "ops", "/tmp", true, true); err != nil {
		t.Fatalf("SetRolePath: %v", err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)

	conn, _, err := dialFileBrowser(t, client, apiURL, "web01")
	if err != nil {
		t.Fatalf("dosya tarayıcısı açılamadı: %v", err)
	}
	conn.SetReadLimit(2 << 20)

	dialCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	pipe := &wsPipe{ctx: dialCtx, c: conn}
	defer pipe.Close()

	cli, err := sftp.NewClientPipe(pipe, pipe)
	if err != nil {
		t.Fatalf("SFTP el sıkışması: %v", err)
	}

	// Bir arayüzün bir oturumda üreteceğinden fazla gezinme.
	const rounds = 60
	for i := 0; i < rounds; i++ {
		if _, err := cli.ReadDir("/tmp"); err != nil {
			t.Fatalf("%d. listeleme: %v", i, err)
		}
	}

	// Bir de ret: satır bırakması GEREKEN tek şey.
	if _, err := cli.ReadDir("/etc"); err == nil {
		t.Fatal("/etc listelendi")
	}

	pipe.Close()

	/*
	 * Olaylar toplu yazılıyor (flushEvery = 2s), o yüzden bekleniyor.
	 * Oturumun kapanması da yazmayı tetikliyor.
	 */
	sessions, err := db.Sessions(ctx, "", 0)
	if err != nil || len(sessions) == 0 {
		t.Fatalf("oturum bulunamadı: %v", err)
	}
	sid := sessions[0].ID

	var denied, total int
	for i := 0; i < 60; i++ {
		time.Sleep(250 * time.Millisecond)
		rows, err := db.SessionFiles(ctx, sid)
		if err != nil {
			t.Fatalf("session_files: %v", err)
		}
		total = len(rows)
		denied = 0
		for _, r := range rows {
			if strings.HasPrefix(r.Op, "denied.") {
				denied++
			}
		}
		if denied > 0 {
			break
		}
	}

	if denied == 0 {
		t.Fatal("ret satırı yazılmadı — defter gezinmeyi de retleri de kaçırıyor")
	}

	/*
	 * ⚠️ TAVAN: 60 listeleme, journalCap'in (10000) yanına
	 * yaklaşmamalı. Sayıyı buraya yazmak, ileride izin verilen
	 * okumaların da yazılmaya başlaması durumunda bu testin
	 * DÜŞMESİNİ sağlıyor — sessizce tavana yürümek yerine.
	 */
	rows, _ := db.SessionFiles(ctx, sid)
	byOp := map[string]int{}
	for _, r := range rows {
		byOp[r.Op]++
	}
	t.Logf("%d listeleme + 1 ret → %d satır; işlemler: %v", rounds, total, byOp)

	// Dizin başına TAM BİR satır.
	if byOp["opendir"] != rounds {
		t.Errorf("opendir satırı %d, %d bekleniyordu", byOp["opendir"], rounds)
	}

	/*
	 * ⚠️ readdir SATIR YAZMAMALI. Uzun bir dizin birden çok READDIR
	 * turu gerektiriyor (gerçek sunucuda ölçüldü: 500 girdi birkaç
	 * sayfaya bölünüyor). Her tur bir satır yazsaydı, satır sayısı
	 * dizinin BÜYÜKLÜĞÜYLE artardı ve tavan bu yüzeyin sınırı olurdu.
	 */
	for _, quiet := range []string{"readdir", "stat", "lstat", "close", "realpath"} {
		if byOp[quiet] != 0 {
			t.Errorf("%q %d satır yazdı: defter artık dizin başına değil istek başına "+
				"büyüyor, journalCap (10000) bu yüzeyin sınırı hâline gelir",
				quiet, byOp[quiet])
		}
	}

	if total != rounds+1 {
		t.Errorf("toplam %d satır, %d bekleniyordu (%d listeleme + 1 ret)",
			total, rounds+1, rounds)
	}
}

/*
 * TestFetchingAFolderCostsOneRowPerDirectoryAndTwoPerFile — özyineli
 * klasör indirmenin DEFTER MALİYETİNİN ölçümü.
 *
 * ⚠️ NİYE BURADA BİR SAYI SABİTLENİYOR: paneldeki gezginin tavanı
 * (web/src/tree.ts, maxTreeEntries) bu orana dayanıyor. Bir tavanın
 * gerekçesi ölçülmemişse tavan değil temennidir — ve bu ürün o hatayı
 * bir kez yaptı: tavan önce "journalCap aşılırsa oturum ölür" diye
 * yazılmıştı, oysa journalCap oturumun TOPLAMINI değil iki saniyede bir
 * boşalan BİRİKİMİ sınırlıyor.
 *
 * Ölçülen oran:
 *   - dizin başına BİR satır (opendir), içindeki girdi sayısından
 *     bağımsız,
 *   - indirilen dosya başına İKİ satır: OPEN cevabında `open`, tanıtıcı
 *     kapanırken bayt toplamını taşıyan `transfer`,
 *   - okuma, listeleme ve stat HİÇBİR satır bırakmıyor.
 *
 * Oran değişirse bu test düşer ve paneldeki tavanın gerekçesi yeniden
 * yazılmak zorunda kalır — sessizce yanlış kalmak yerine.
 */
func TestFetchingAFolderCostsOneRowPerDirectoryAndTwoPerFile(t *testing.T) {
	apiURL, db := browserBastionWithUploads(t)
	ctx := context.Background()

	if err := db.SetRolePath(ctx, "ops", "/tmp", true, true); err != nil {
		t.Fatalf("SetRolePath: %v", err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)

	/*
	 * ⚠️ AĞAÇ AYRI BİR OTURUMDA KURULUYOR. Hedef kendi konteyneri, yani
	 * dosyaları buradan yaratmanın tek yolu yine SFTP; ama kurulumun
	 * mkdir/write satırları ÖLÇÜLEN oturuma karışırsa sayım anlamsız
	 * olur. Defter satırları oturuma bağlı, o yüzden kurulum kapanıp
	 * ölçüm yeni bir oturumda yapılıyor.
	 */
	root := fmt.Sprintf("/tmp/postern-agac-%d", time.Now().UnixNano())
	files := []string{root + "/bir.txt", root + "/iki.txt", root + "/alt/uc.txt"}

	func() {
		cli, done := panelSFTP(t, client, apiURL)
		defer done()

		for _, d := range []string{root, root + "/alt"} {
			if err := cli.Mkdir(d); err != nil {
				t.Fatalf("%s yaratılamadı: %v", d, err)
			}
		}
		for i, f := range files {
			w, err := cli.Create(f)
			if err != nil {
				t.Fatalf("%s yaratılamadı: %v", f, err)
			}
			if _, err := w.Write([]byte(strings.Repeat("x", 10+i))); err != nil {
				t.Fatalf("%s yazılamadı: %v", f, err)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("%s kapatılamadı: %v", f, err)
			}
		}
	}()

	before := map[string]bool{}
	if list, err := db.Sessions(ctx, "", 0); err == nil {
		for _, s := range list {
			before[s.ID] = true
		}
	}

	// Panelin özyineli indirmesinin yaptığının aynısı: önce ağacı gez,
	// sonra her dosyayı baştan sona oku.
	func() {
		cli, done := panelSFTP(t, client, apiURL)
		defer done()

		for _, dir := range []string{root, root + "/alt"} {
			if _, err := cli.ReadDir(dir); err != nil {
				t.Fatalf("%s listelenemedi: %v", dir, err)
			}
		}
		for _, f := range files {
			fh, err := cli.Open(f)
			if err != nil {
				t.Fatalf("%s açılamadı: %v", f, err)
			}
			if _, err := io.ReadAll(fh); err != nil {
				t.Fatalf("%s okunamadı: %v", f, err)
			}
			if err := fh.Close(); err != nil {
				t.Fatalf("%s kapatılamadı: %v", f, err)
			}
		}
	}()

	// Ölçülen oturum, kurulumdan SONRA açılan.
	var sid string
	for i := 0; i < 60 && sid == ""; i++ {
		time.Sleep(250 * time.Millisecond)
		list, err := db.Sessions(ctx, "", 0)
		if err != nil {
			t.Fatalf("Sessions: %v", err)
		}
		for _, s := range list {
			if !before[s.ID] {
				sid = s.ID
			}
		}
	}
	if sid == "" {
		t.Fatal("ölçülecek oturum bulunamadı")
	}

	// Olaylar toplu yazılıyor (flushEvery = 2s); kapanış da tetikliyor.
	byOp := map[string]int{}
	for i := 0; i < 60; i++ {
		time.Sleep(250 * time.Millisecond)
		rows, err := db.SessionFiles(ctx, sid)
		if err != nil {
			t.Fatalf("session_files: %v", err)
		}
		byOp = map[string]int{}
		for _, r := range rows {
			byOp[r.Op]++
		}
		if byOp["transfer"] >= len(files) {
			break
		}
	}

	t.Logf("2 dizin + %d dosya → %v", len(files), byOp)

	if byOp["opendir"] != 2 {
		t.Errorf("opendir satırı %d, 2 bekleniyordu (dizin başına bir)", byOp["opendir"])
	}
	if byOp["open"] != len(files) {
		t.Errorf("open satırı %d, %d bekleniyordu", byOp["open"], len(files))
	}
	/*
	 * ⚠️ AKTARIM SATIRI DOSYA BAŞINA BİR TANE, PARÇA BAŞINA DEĞİL.
	 * Parça başına olsaydı satır sayısı DOSYANIN BOYUYLA büyürdü ve
	 * paneldeki girdi tavanı hiçbir şeyi bağlamazdı.
	 */
	if byOp["transfer"] != len(files) {
		t.Errorf("transfer satırı %d, %d bekleniyordu — satır sayısı artık "+
			"dosya boyuyla büyüyor olabilir", byOp["transfer"], len(files))
	}

	// Okuma ve listeleme sessiz kalmalı: aksi hâlde oran dosya ve dizin
	// büyüklüğüne bağlanır.
	for _, quiet := range []string{"readdir", "stat", "lstat", "close", "realpath"} {
		if byOp[quiet] != 0 {
			t.Errorf("%q %d satır yazdı: maliyet artık istek başına", quiet, byOp[quiet])
		}
	}

	total := 0
	for _, n := range byOp {
		total += n
	}
	if want := 2 + 2*len(files); total != want {
		t.Errorf("toplam %d satır, %d bekleniyordu (2 dizin + 2×%d dosya)",
			total, want, len(files))
	}
}

// panelSFTP, panelin websocket'i üzerinden bir SFTP istemcisi açar.
func panelSFTP(t *testing.T, client *http.Client, apiURL string) (*sftp.Client, func()) {
	t.Helper()

	conn, _, err := dialFileBrowser(t, client, apiURL, "web01")
	if err != nil {
		t.Fatalf("dosya tarayıcısı açılamadı: %v", err)
	}
	conn.SetReadLimit(2 << 20)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	pipe := &wsPipe{ctx: ctx, c: conn}

	cli, err := sftp.NewClientPipe(pipe, pipe)
	if err != nil {
		cancel()
		pipe.Close()
		t.Fatalf("SFTP el sıkışması: %v", err)
	}

	return cli, func() {
		cli.Close()
		pipe.Close()
		cancel()
	}
}

/*
 * TestBrowsingSessionIsSealed — "kanıt açığı" maddesinin kapandığının
 * UÇTAN UCA kanıtı.
 *
 * ⚠️ AÇIK NEYDİ: SFTP baytları terminal kaydına hiç girmiyor (kanalı
 * baştan kapalı tutan kural buydu ve duruyor), dolayısıyla bir tarama
 * oturumunun .cast dosyası YALNIZCA başlık satırından ibaretti. Zincir o
 * boşluğu mühürlüyor, oturumun gerçek kanıtı olan session_files satırları
 * ise zincirin hiç uzanmadığı bir yerde duruyordu. Yani dosya etkinliği
 * denetleniyor, mühürlenmiyordu.
 *
 * ÖLÇÜLEN: kayıt artık oturumun ANLATISINI taşıyor ve zincir onu
 * kapsıyor. `postern session verify`'ın doğruladığı dosya, oturumda ne
 * olduğunu söyleyen dosya.
 */
func TestBrowsingSessionIsSealed(t *testing.T) {
	apiURL, db := browserBastionWithFileBrowser(t)

	ctx := context.Background()
	if err := db.SetRolePath(ctx, "ops", "/tmp", true, false); err != nil {
		t.Fatalf("SetRolePath: %v", err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)

	conn, _, err := dialFileBrowser(t, client, apiURL, "web01")
	if err != nil {
		t.Fatalf("dosya tarayıcısı açılamadı: %v", err)
	}
	conn.SetReadLimit(2 << 20)

	dialCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	pipe := &wsPipe{ctx: dialCtx, c: conn}
	defer pipe.Close()

	cli, err := sftp.NewClientPipe(pipe, pipe)
	if err != nil {
		t.Fatalf("SFTP el sıkışması: %v", err)
	}
	if _, err := cli.ReadDir("/tmp"); err != nil {
		t.Fatalf("/tmp listelenemedi: %v", err)
	}
	// Bir de reddedilen bir istek: kayıt "denedi ve reddedildi"yi de
	// göstermeli.
	_, _ = cli.ReadDir("/etc")
	pipe.Close()

	// Oturumun kapanmasını ve kaydın yazılmasını bekle.
	var sid, castPath string
	for i := 0; i < 80; i++ {
		time.Sleep(250 * time.Millisecond)
		sessions, err := db.Sessions(ctx, "", 0)
		if err != nil || len(sessions) == 0 {
			continue
		}
		if sessions[0].EndedAt.IsZero() {
			continue
		}
		sid = sessions[0].ID
		castPath = sessions[0].RecordingPath
		if castPath != "" {
			break
		}
	}
	if sid == "" || castPath == "" {
		t.Fatalf("oturum kapanmadı ya da kaydı yok (id=%q path=%q)", sid, castPath)
	}

	body, err := os.ReadFile(castPath)
	if err != nil {
		t.Fatalf("kayıt okunamadı: %v", err)
	}
	cast := string(body)

	/*
	 * ⚠️ ÜÇ ŞEY BİRDEN: oturumun SFTP olduğu, ne yapıldığı, ve neyin
	 * reddedildiği. Üçü de eskiden kayıtta YOKTU.
	 */
	for _, want := range []string{
		"postern: subsystem sftp",
		"postern sftp: opendir /tmp",
		"postern sftp: denied opendir /etc",
		"digest sha256:",
	} {
		if !strings.Contains(cast, want) {
			t.Errorf("kayıtta yok: %q\n---\n%s", want, cast)
		}
	}

	// Ve zincir bu kaydı DOĞRULUYOR: satırlar dosyanın parçası,
	// sonradan yapıştırılmış bir ek değil.
	/*
	 * ⚠️ Sessions() zincir sütunlarını SEÇMİYOR; tek oturumu okuyan
	 * Session() seçiyor. İlk hâlde listeden okunuyordu ve baş her
	 * zaman boş çıkıyordu — yani test, zincir yazılmışken
	 * "yazılmamış" diyordu.
	 */
	se, err := db.Session(ctx, sid)
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	head, links := se.RecordingChain, se.RecordingLinks
	if head == "" {
		t.Fatal("zincir başı yazılmamış")
	}
	if links < 4 {
		t.Errorf("zincir %d halka — anlatı kapsanmıyor", links)
	}

	f, err := os.Open(castPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ok, got, err := record.VerifyChain(f, head)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !ok {
		t.Errorf("zincir tutmadı (%d halka okundu, %d bekleniyordu)", got, links)
	}
}

// panelClient, panelin SFTP kanalını açıp bir istemci kurar.
func panelClient(t *testing.T, apiURL string) (*sftp.Client, *wsPipe) {
	t.Helper()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)

	conn, _, err := dialFileBrowser(t, client, apiURL, "web01")
	if err != nil {
		t.Fatalf("dosya tarayıcısı açılamadı: %v", err)
	}
	conn.SetReadLimit(2 << 20)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	pipe := &wsPipe{ctx: ctx, c: conn}
	cli, err := sftp.NewClientPipe(pipe, pipe)
	if err != nil {
		t.Fatalf("SFTP el sıkışması: %v (gerekçe: %q)", err, pipe.notices())
	}

	return cli, pipe
}

/*
 * TestUploadWorksWhenTheFlagAndTheRuleBothAllowIt — yüklemenin UÇTAN UCA
 * kanıtı.
 *
 * ⚠️ İKİ KOŞUL BİRDEN gerekiyor ve bu ayrım özelliğin tamamı:
 * session.sftp_panel_write kanalın salt-okunur kilidini açıyor, rolün
 * can_write kuralı ise HANGİ yola yazılabileceğini söylüyor. Birini
 * diğerinin yerine geçirmek, "yüklemeyi açtım" diyen bir operatöre
 * hedefin tamamını vermek olurdu.
 */
func TestUploadWorksWhenTheFlagAndTheRuleBothAllowIt(t *testing.T) {
	apiURL, db := browserBastionWithUploads(t)

	ctx := context.Background()
	if err := db.SetRolePath(ctx, "ops", "/tmp", true, true); err != nil {
		t.Fatalf("SetRolePath: %v", err)
	}

	cli, pipe := panelClient(t, apiURL)
	defer pipe.Close()

	const body = "postern-yukleme-kaniti"
	f, err := cli.Create("/tmp/postern-upload.txt")
	if err != nil {
		t.Fatalf("dosya yaratılamadı: %v (gerekçe: %q)", err, pipe.notices())
	}
	if _, err := f.Write([]byte(body)); err != nil {
		t.Fatalf("yazılamadı: %v (gerekçe: %q)", err, pipe.notices())
	}
	if err := f.Close(); err != nil {
		t.Fatalf("kapatılamadı: %v", err)
	}

	// Hedefte GERÇEKTEN var mı: "sunucu hata vermedi" yeterli değil.
	back, err := cli.Open("/tmp/postern-upload.txt")
	if err != nil {
		t.Fatalf("geri okunamadı: %v", err)
	}
	got, err := io.ReadAll(back)
	back.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Errorf("içerik = %q, %q bekleniyordu", got, body)
	}
}

/*
 * ⚠️ BAYRAK KAPALIYKEN YÜKLEME GEÇMEMELİ — panelin JavaScript'i ne
 * çizerse çizsin. Kısıt sunucuda; çalınmış bir oturum FXP_WRITE'ı elle
 * yazar ve buradaki test tam olarak onu taklit ediyor (gerçek bir SFTP
 * istemcisi, panelin kodundan bağımsız).
 */
func TestUploadIsRefusedWhenTheFlagIsOff(t *testing.T) {
	apiURL, db := browserBastionWithFileBrowser(t) // yükleme KAPALI

	ctx := context.Background()
	// Yol kuralı yazmaya İZİNLİ: reddin tek sebebi bayrak olabilir.
	if err := db.SetRolePath(ctx, "ops", "/tmp", true, true); err != nil {
		t.Fatalf("SetRolePath: %v", err)
	}

	cli, pipe := panelClient(t, apiURL)
	defer pipe.Close()

	f, err := cli.Create("/tmp/postern-should-not-exist.txt")
	if err == nil {
		_, werr := f.Write([]byte("x"))
		cerr := f.Close()
		if werr == nil && cerr == nil {
			t.Fatal("yükleme kapalıyken dosya yazıldı")
		}
	}

	if n := waitForNotice(t, pipe, "read-only"); !strings.Contains(n, "read-only") {
		t.Errorf("gerekçe salt-okunur demiyor: %q", n)
	}
}

/*
 * ⚠️ BAYRAK AÇIK OLSA BİLE KURAL YAZMAYA İZİN VERMİYORSA GEÇMEMELİ.
 *
 * can_write bir söz ve postern onu kendisi uygulamalı. Yazma isteği
 * tanıtıcının yolu üzerinden politikaya soruluyor; sorulmasaydı kısıtı
 * uygulayan tek şey hedefin dosya izinleri olurdu.
 */
func TestUploadIsRefusedWhenTheRuleIsReadOnly(t *testing.T) {
	apiURL, db := browserBastionWithUploads(t) // yükleme AÇIK

	ctx := context.Background()
	// Okumaya izinli, YAZMAYA değil.
	if err := db.SetRolePath(ctx, "ops", "/tmp", true, false); err != nil {
		t.Fatalf("SetRolePath: %v", err)
	}

	cli, pipe := panelClient(t, apiURL)
	defer pipe.Close()

	// Gezinme çalışmalı: kural okumaya izinli.
	if _, err := cli.ReadDir("/tmp"); err != nil {
		t.Fatalf("/tmp listelenemedi: %v (gerekçe: %q)", err, pipe.notices())
	}

	f, err := cli.Create("/tmp/postern-readonly-rule.txt")
	if err == nil {
		_, werr := f.Write([]byte("x"))
		cerr := f.Close()
		if werr == nil && cerr == nil {
			t.Fatal("kural salt-okunurken dosya yazıldı")
		}
	}

	if n := waitForNotice(t, pipe, "read-only"); !strings.Contains(n, "read-only") {
		t.Errorf("gerekçe: %q", n)
	}
}

/*
 * TestWriteOnAReadHandleIsRefusedEndToEnd — asıl deliğin kanıtı.
 *
 * ⚠️ NİYE AYRI BİR TEST GEREKİYOR. Sıradan bir yükleme (Create) dosyayı
 * YAZMA bayrağıyla açıyor, dolayısıyla kural yazmaya izin vermiyorsa
 * AÇILIŞ reddediliyor ve yazma hiç denenmiyor. Ölçüldü: FXP_WRITE'ın
 * politikaya sorulmasını kaldıran mutasyon, Create kullanan testten
 * GEÇİYOR — o test deliği hiç görmüyor.
 *
 * Delik şu: yolu OKUMA bayrağıyla açmak (kural izinli), sonra AYNI
 * tanıtıcı üzerine FXP_WRITE göndermek. Eskiden tanıdık tanıtıcı görülüp
 * istek politikaya hiç sorulmadan geçiyordu; kısıtı uygulayan tek şey
 * hedefin açma kipiydi — bastion kendi kuralını hedefe emanet ediyordu.
 *
 * ⚠️ TESTİN İKİ TUZAĞI VAR ve ikisi de ölçülerek bulundu:
 *
 *   1. Gerçek bir DOSYA gerekiyor. Dizin açıp yazmayı denemek, hedefin
 *      kendi hatasını üretiyor ve postern hiç konuşmadan test geçiyor.
 *   2. Gerekçe SIFIRLANMALI. Önceki adımlar "read-only" notu bırakıyor;
 *      sıfırlamayan bir iddia onu bulup yanlış sebepten geçiyor.
 */
func TestWriteOnAReadHandleIsRefusedEndToEnd(t *testing.T) {
	apiURL, db := browserBastionWithUploads(t) // yükleme AÇIK

	ctx := context.Background()
	/*
	 * Kök okumaya izinli, YAZMAYA değil. Kökten veriyoruz ki hedefte
	 * kesin var olan ve okunabilir bir DOSYA açabilelim (/etc/hostname);
	 * dizin açmak hedefin kendi hatasını üretir ve postern'i hiç
	 * konuşturmaz.
	 */
	if err := db.SetRolePath(ctx, "ops", "/", true, false); err != nil {
		t.Fatalf("SetRolePath: %v", err)
	}

	cli, pipe := panelClient(t, apiURL)
	defer pipe.Close()

	rf, err := cli.OpenFile("/etc/hostname", os.O_RDONLY)
	if err != nil {
		t.Fatalf("okuma için açılamadı: %v (gerekçe: %q)", err, pipe.notices())
	}
	defer rf.Close()

	// Buraya kadar biriken her şeyi at: sonraki iddia YALNIZCA yazmanın
	// ürettiği gerekçeye bakmalı.
	pipe.takeNotices()

	if _, err := rf.Write([]byte("bu yazma reddedilmeli")); err == nil {
		t.Fatal("okuma tanıtıcısına yazma GEÇTİ — kısıt hedefin açma kipine bırakılmış")
	}

	/*
	 * Gerekçe asenkron geliyor: yazmanın hata ile dönmesi, metnin
	 * websocket'ten çıktığı anlamına gelmiyor.
	 */
	notice := ""
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		notice += pipe.takeNotices()
		if strings.Contains(notice, "read-only") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !strings.Contains(notice, "postern:") {
		t.Fatalf("reddi postern vermedi (hedefin kendi hatası olabilir): %q", notice)
	}
	if !strings.Contains(notice, "read-only") {
		t.Errorf("gerekçe salt-okunur demiyor: %q", notice)
	}
}
