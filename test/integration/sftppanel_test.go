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
