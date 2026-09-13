package httpapi

/*
 * Panelden yönetim erişimi denetimi (manage.go).
 *
 * ⚠️ UÇTAN UCA DENETİM SÜREÇ İÇİ BİR SSH SUNUCUSUYLA ÖLÇÜLÜYOR. Sunucu,
 * rolün kurduğu hedefin principal kuralını taklit ediyor: "postern" hesabı
 * yalnızca "postern-manage" principal'ıyla açılıyor. Gerçek OpenSSH, sudo
 * ve visudo üzerindeki karşılığı test/integration/manage_test.go'da.
 */

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/auth"
	"github.com/Warewave-Technology/postern/internal/ca"
	"github.com/Warewave-Technology/postern/internal/model"
)

func manageCA(t *testing.T) *ca.CA {
	t.Helper()
	authority, err := ca.Init(t.TempDir() + "/ca")
	if err != nil {
		t.Fatal(err)
	}

	return authority
}

func edSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	return s
}

/*
 * managedHost, yönetim hesabı kurulu bir hedefi taklit eder ve kabul
 * ettiği bağlantıları sayar. answers nil ise el sıkışmadan sonra her exec
 * isteğine cevapsız kapanır.
 */
func managedHost(t *testing.T, authority *ca.CA, answers map[string]string) (host string, port int, hostKey string, conns *atomic.Int32) {
	t.Helper()

	hk := edSigner(t)
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), authority.PublicKey().Marshal())
		},
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			cert, ok := key.(*ssh.Certificate)
			if !ok || c.User() != model.ManagementAccount {
				return nil, errors.New("refused")
			}
			/*
			 * ⚠️ CA GÜVENİ AYRICA SORULUYOR — CheckCert SORMUYOR, ÖLÇÜLDÜ.
			 * x/crypto'da CheckCert yalnızca imzanın sertifikadaki anahtarla
			 * tutarlı olduğuna bakıyor; "bu CA'ya güveniyor muyum" sorusu
			 * Authenticate'in içinde. İlk hâli CheckCert'i doğrudan çağırıp
			 * o adımı atlıyordu ve bu sahte hedef HER CA'yı kabul ediyordu —
			 * başka bir CA'ya güvenen hedef testi bu yüzden "yönetilebilir"
			 * sonucu aldı.
			 */
			if !checker.IsUserAuthority(cert.SignatureKey) {
				return nil, errors.New("certificate signed by an authority this host does not trust")
			}
			if err := checker.CheckCert(model.ManagementPrincipal, cert); err != nil {
				return nil, err
			}
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(hk)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	conns = &atomic.Int32{}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go serveManaged(c, cfg, answers)
		}
	}()

	h, p, _ := net.SplitHostPort(l.Addr().String())
	port, _ = strconv.Atoi(p)

	return h, port, string(ssh.MarshalAuthorizedKey(hk.PublicKey())), conns
}

func serveManaged(c net.Conn, cfg *ssh.ServerConfig, answers map[string]string) {
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		c.Close()
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)

	for nc := range chans {
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			for req := range creqs {
				if req.Type != "exec" {
					_ = req.Reply(false, nil)
					continue
				}
				var p struct{ Command string }
				_ = ssh.Unmarshal(req.Payload, &p)
				_ = req.Reply(true, nil)
				_, _ = io.ReadAll(ch)
				if answers == nil {
					return
				}
				out, ok := answers[p.Command]
				status := uint32(0)
				if !ok {
					status = 127
				}
				_, _ = ch.Write([]byte(out))
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
				return
			}
		}()
	}
}

// debianAnswers, yönetilebilir bir Debian makinesinin yetenek cevapları.
func debianAnswers() map[string]string {
	return map[string]string{
		"sudo -n -l": "User postern may run the following commands on web01:\n    (ALL) NOPASSWD: ALL\n",
		"for n in useradd adduser groupadd addgroup usermod userdel groupdel visudo; do command -v $n; done": "/usr/sbin/useradd\n/usr/sbin/adduser\n/usr/sbin/groupadd\n" +
			"/usr/sbin/addgroup\n/usr/sbin/usermod\n/usr/sbin/userdel\n/usr/sbin/groupdel\n/usr/sbin/visudo\n",
		"cat /etc/os-release": "ID=debian\n",
	}
}

// checkTarget, denetim ucunu yönetici "ops" olarak çağırır.
func checkTarget(t *testing.T, s *Server, name string) (*httptest.ResponseRecorder, manageCheckResult) {
	t.Helper()

	r := httptest.NewRequest(http.MethodPost, "/api/admin/targets/"+name+"/manage/check", nil)
	r.SetPathValue("name", name)
	r = r.WithContext(context.WithValue(r.Context(), ctxUser, "ops"))
	w := httptest.NewRecorder()
	s.adminManageCheck(w, r)

	var res manageCheckResult
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatalf("cevap okunamadı: %v — %s", err, w.Body.String())
		}
	}

	return w, res
}

/*
 * ⚠️ KAPALIYKEN UÇ YOK — düğme de yok.
 *
 * manage.enabled kapalı bir bastion'da panelin yönetici oturumu hiçbir
 * makineye yönetim bağlantısı açamamalı. "Kapalı özellik, kapalı yüzey":
 * uç mux'a hiç eklenmiyor ve hedef detayı panele bunu söylüyor.
 */
func TestManagementIsAbsentUnlessEnabled(t *testing.T) {
	s := &Server{}
	mux := http.NewServeMux()
	s.registerManageRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/targets/web01/manage/check", nil)
	if _, pattern := mux.Handler(req); pattern != "" {
		t.Errorf("kapalıyken uç kuruldu: %q", pattern)
	}

	s.UseManagement(manageCA(t))
	mux = http.NewServeMux()
	s.registerManageRoutes(mux)
	if _, pattern := mux.Handler(req); pattern == "" {
		t.Error("açıkken uç kurulmadı — yukarıdaki ret yanlış sebepten geliyor olabilir")
	}
}

/*
 * ⚠️ POSTERN SAHİP OLDUĞU BİR HEDEFİ YÖNETİLEBİLİR BULMALI — ve cevap
 * panelin çizeceği her şeyi taşımalı.
 */
func TestManagementCheckFindsAManageableTarget(t *testing.T) {
	s, db := dbServer(t)
	authority := manageCA(t)
	s.UseManagement(authority)

	host, port, hostKey, _ := managedHost(t, authority, debianAnswers())
	if _, err := db.CreateTarget(t.Context(), model.Target{
		Name: "web01", Host: host, Port: port, HostKey: hostKey,
	}); err != nil {
		t.Fatal(err)
	}

	w, res := checkTarget(t, s, "web01")
	if w.Code != http.StatusOK {
		t.Fatalf("durum = %d: %s", w.Code, w.Body.String())
	}
	if res.Stage != "done" || !res.Manageable {
		t.Fatalf("sonuç = %+v, yönetilebilir bekleniyordu", res)
	}
	if res.Family != "debian" || res.Tools["visudo"] != "/usr/sbin/visudo" {
		t.Errorf("makine doğru okunmadı: %+v", res)
	}
	if res.CAFingerprint != ssh.FingerprintSHA256(authority.PublicKey()) {
		t.Errorf("CA parmak izi = %q", res.CAFingerprint)
	}
	if res.Missing == nil {
		t.Error("missing null döndü; panel boş listeyle null'ı ayırmak zorunda kalmamalı")
	}
}

/*
 * ⚠️ BAĞLANAMAMAK "YÖNETİLEMEZ" DEĞİL — aşama ve sebep ayrı söylenmeli.
 *
 * Kapalı bir porta işaret eden hedef: cevap 200, aşama "connect", ve
 * cümle operatörü ağa yollamalı; CA ya da visudo cümlesi onu yanlış yere
 * baktırırdı. Denetim satırı bağlanmadan önce yazılmış olmalı.
 */
func TestManagementCheckSaysWhereItStopped(t *testing.T) {
	s, db := dbServer(t)
	s.UseManagement(manageCA(t))

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, p, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(p)
	l.Close() // port artık kapalı

	if _, err := db.CreateTarget(t.Context(), model.Target{
		Name: "kapali", Host: "127.0.0.1", Port: port,
		HostKey: string(ssh.MarshalAuthorizedKey(edSigner(t).PublicKey())),
	}); err != nil {
		t.Fatal(err)
	}

	w, res := checkTarget(t, s, "kapali")
	if w.Code != http.StatusOK {
		t.Fatalf("durum = %d: %s", w.Code, w.Body.String())
	}
	if res.Stage != "connect" || res.Manageable {
		t.Fatalf("sonuç = %+v, connect aşamasında durması bekleniyordu", res)
	}
	if !strings.Contains(res.Reason, "could not open a connection") {
		t.Errorf("sebep ağı söylemiyor: %q", res.Reason)
	}

	logs, err := db.AdminLog(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range logs {
		if e.Action == "target.manage_check" && e.Entity == "kapali" && e.Actor == "ops" {
			found = true
		}
	}
	if !found {
		t.Errorf("yönetim bağlantısı denemesi deftere yazılmadı: %+v", logs)
	}
}

/*
 * ⚠️ DEFTERE YAZILAMIYORSA HEDEFE HİÇ GİDİLMİYOR.
 *
 * Hedefin günlüğünde postern'in root girişi görünüp postern'in defterinde
 * kimin başlattığı yazmıyorsa, o giriş açıklanamaz. Bağlantı sayacı sıfır
 * kalmalı: ret hedefte değil burada.
 */
func TestManagementCheckDoesNotConnectWithoutAnAuditRow(t *testing.T) {
	s, db, dsn := dbServerDSN(t)
	authority := manageCA(t)
	s.UseManagement(authority)

	host, port, hostKey, conns := managedHost(t, authority, debianAnswers())
	if _, err := db.CreateTarget(t.Context(), model.Target{
		Name: "web01", Host: host, Port: port, HostKey: hostKey,
	}); err != nil {
		t.Fatal(err)
	}

	dropTable(t, dsn, "admin_log")

	w, _ := checkTarget(t, s, "web01")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("durum = %d, 503 bekleniyordu: %s", w.Code, w.Body.String())
	}
	if n := conns.Load(); n != 0 {
		t.Errorf("defter yazılamadığı hâlde hedefe %d bağlantı açıldı", n)
	}
}

/*
 * ⚠️ BAĞLANIP ÖLÇEMEMEK DE AYRI BİR AŞAMA. Sertifika kabul edildi ama makine
 * cevap vermedi: "CA'ya güvenmiyor" demek yanlış olurdu.
 */
func TestManagementCheckSeparatesSilenceFromRefusal(t *testing.T) {
	s, db := dbServer(t)
	authority := manageCA(t)
	s.UseManagement(authority)

	host, port, hostKey, _ := managedHost(t, authority, nil)
	if _, err := db.CreateTarget(t.Context(), model.Target{
		Name: "sessiz", Host: host, Port: port, HostKey: hostKey,
	}); err != nil {
		t.Fatal(err)
	}

	w, res := checkTarget(t, s, "sessiz")
	if w.Code != http.StatusOK {
		t.Fatalf("durum = %d: %s", w.Code, w.Body.String())
	}
	if res.Stage != "measure" || res.Manageable {
		t.Errorf("sonuç = %+v, measure aşamasında durması bekleniyordu", res)
	}
}

/*
 * ⚠️ PANEL DÜĞMEYİ BU BAYRAĞA BAKARAK ÇİZİYOR. Kapalı bir bastion'da
 * "true" dönseydi kart, kurulmamış bir uca basan bir düğme gösterirdi;
 * açıkken "false" dönseydi özellik panelde hiç görünmezdi.
 */
func TestTargetDetailSaysWhetherManagementIsOn(t *testing.T) {
	s, db := dbServer(t)
	if _, err := db.CreateTarget(t.Context(), model.Target{
		Name: "web01", Host: "10.0.0.4", Port: 22,
		HostKey: string(ssh.MarshalAuthorizedKey(edSigner(t).PublicKey())),
	}); err != nil {
		t.Fatal(err)
	}

	flag := func() bool {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/api/admin/targets/web01", nil)
		r.SetPathValue("name", "web01")
		w := httptest.NewRecorder()
		s.adminTargetDetail(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("durum = %d: %s", w.Code, w.Body.String())
		}
		var body struct {
			ManageEnabled *bool `json:"manage_enabled"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.ManageEnabled == nil {
			t.Fatal("manage_enabled cevapta yok")
		}
		return *body.ManageEnabled
	}

	if flag() {
		t.Error("kapalı bastion manage_enabled=true diyor")
	}
	s.UseManagement(manageCA(t))
	if !flag() {
		t.Error("açık bastion manage_enabled=false diyor")
	}
}

/*
 * ⚠️ BAŞKA BİR CA'YA GÜVENEN HEDEF — EN SIK RET, VE CÜMLESİ ONU SÖYLEMELİ.
 *
 * Laboratuvarda tam olarak yaşandı: hedefler bir CA'yla kurulmuş, panel
 * başka bir CA'yla çalışıyordu. "Bağlanılamadı" demek operatörü ağa
 * yollardı; oysa yapılacak iş parmak izlerini karşılaştırmak.
 */
func TestManagementCheckNamesAnUntrustedCA(t *testing.T) {
	s, db := dbServer(t)
	s.UseManagement(manageCA(t))

	other := manageCA(t) // hedefin güvendiği, bastion'unkinden farklı CA
	host, port, hostKey, _ := managedHost(t, other, debianAnswers())
	if _, err := db.CreateTarget(t.Context(), model.Target{
		Name: "baska-ca", Host: host, Port: port, HostKey: hostKey,
	}); err != nil {
		t.Fatal(err)
	}

	w, res := checkTarget(t, s, "baska-ca")
	if w.Code != http.StatusOK {
		t.Fatalf("durum = %d: %s", w.Code, w.Body.String())
	}
	if res.Stage != "connect" || res.Manageable {
		t.Fatalf("sonuç = %+v", res)
	}
	if !strings.Contains(res.Reason, "refused postern's management certificate") ||
		!strings.Contains(res.Reason, "fingerprint") {
		t.Errorf("sebep CA'yı karşılaştırmayı söylemiyor: %q", res.Reason)
	}
	if strings.Contains(res.Detail, "could not be reached") {
		t.Errorf("ham metin reddi 'ulaşılamadı' diye anlatıyor: %q", res.Detail)
	}
}

/*
 * ⚠️ KAPILAR ROTADA — VE ROTADAN GEÇİLMEDEN SINANAMAZLAR. Buradaki öbür
 * testler handler'ı doğrudan çağırıyor; `requireAdmin` ya da `sameOrigin`
 * zincirden silinse hepsi yeşil kalırdı (bir incelemede mutasyonla
 * görüldü). Bu test isteği Handler()'dan, gerçek bir oturum çerezi ile
 * gönderiyor: yönetici olmayan 403, çapraz köken 403, yönetici + aynı
 * köken ise kapıdan geçip hedefin cevabını alıyor.
 */
func TestManagementCheckIsBehindTheAdminAndSameOriginGates(t *testing.T) {
	db := migratedStore(t)
	s := New(auth.NewOIDCHolder(), auth.NewLogins(auth.NewOIDCHolder()), db,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.UseManagement(manageCA(t))

	ctx := t.Context()
	if _, err := db.CreateUser(ctx, "veli", "veli@warewave.io", "veli"); err != nil {
		t.Fatal(err)
	}
	token, err := s.createWebSession(ctx, "veli")
	if err != nil {
		t.Fatal(err)
	}

	post := func(site string) int {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/api/admin/targets/yok/manage/check", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		if site != "" {
			r.Header.Set("Sec-Fetch-Site", site)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w.Code
	}

	if code := post("same-origin"); code != http.StatusForbidden {
		t.Errorf("yönetici olmayan oturum %d aldı, 403 bekleniyordu", code)
	}

	if err := db.SetUserAdmin(ctx, "veli", true); err != nil {
		t.Fatal(err)
	}
	if code := post("cross-site"); code != http.StatusForbidden {
		t.Errorf("çapraz kökenli istek %d aldı, 403 bekleniyordu", code)
	}
	// Karşı örnek: kapılardan geçince handler'a varılıyor — hedef yok, 404.
	if code := post("same-origin"); code != http.StatusNotFound {
		t.Errorf("yönetici + aynı köken %d aldı, handler'ın 404'ü bekleniyordu", code)
	}
}
