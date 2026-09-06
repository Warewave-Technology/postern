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
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/pkg/sftp"

	"github.com/Warewave-Technology/postern/internal/config"
	"github.com/Warewave-Technology/postern/internal/httpapi"
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

	// session.sftp olmadan alt sistem kapalı; panel bayrağı serve.go'da
	// zaten onunla VE'leniyor, burada ikisini de açıyoruz.
	tuneConfig = func(c *config.Config) { c.Session.SFTP = true }
	tuneWebAPI = func(s *httpapi.Server) { s.SetSFTPPanel(true) }
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
