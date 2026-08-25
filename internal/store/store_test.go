package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/model"
)

const testHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIcLUQM0UcoZdJVh2EokribDvFZyyNyAVURM/LrCugFM"

func TestUserRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "yigit", "yigit@warewave.io", "yigit"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	u, err := s.User(ctx, "yigit")
	if err != nil {
		t.Fatalf("User: %v", err)
	}
	if u.Name != "yigit" {
		t.Errorf("Name = %q, beklenen %q", u.Name, "yigit")
	}
	if u.OSUser != "yigit" {
		t.Errorf("OSUser = %q, beklenen %q", u.OSUser, "yigit")
	}
	// Rolü olmayan kullanıcı geçerlidir: hiçbir hedefe erişemez, o kadar.
	if len(u.Roles) != 0 {
		t.Errorf("Roles = %v, beklenen boş", u.Roles)
	}
}

func TestUserNotFound(t *testing.T) {
	_, err := newTestStore(t).User(context.Background(), "boyle-biri-yok")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("hata = %v, beklenen ErrNotFound", err)
	}
}

func TestCreateUserDuplicate(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "yigit", "a@warewave.io", "yigit"); err != nil {
		t.Fatal(err)
	}

	_, err := s.CreateUser(ctx, "yigit", "b@warewave.io", "yigit")
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("hata = %v, beklenen ErrConflict — sürücünün ham hatası dışarı sızıyor olabilir", err)
	}
}

// email UNIQUE ama NULL kabul ediyor: e-postasız İKİ kullanıcı olabilmeli.
// Boş string yazılırsa ikincisi UNIQUE'e takılır — asıl sınav bu.
func TestCreateUserWithoutEmail(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "biri", "", "biri"); err != nil {
		t.Fatalf("ilk e-postasız kullanıcı: %v", err)
	}
	if _, err := s.CreateUser(ctx, "digeri", "", "digeri"); err != nil {
		t.Fatalf("ikinci e-postasız kullanıcı: %v — boş string NULL'a çevrilmiyor", err)
	}
}

// E-posta gerçekten yazılıyor mu?
//
// model.User'da Email alanı yok (OIDC ile S3.2'de gelecek), o yüzden bu
// testin doğrulaması tabloya doğrudan bakıyor. Alanın okunmuyor olması,
// yanlış yazılmasını serbest bırakmaz — S3.2'de OIDC kimliğini postern
// kullanıcısına bağlayan şey bu sütun olacak.
func TestCreateUserStoresEmail(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "yigit", "yigit@warewave.io", "yigit"); err != nil {
		t.Fatal(err)
	}

	var email sql.NullString
	if err := s.db.QueryRowContext(ctx,
		`SELECT email FROM users WHERE username = ?`, "yigit").Scan(&email); err != nil {
		t.Fatal(err)
	}

	if !email.Valid {
		t.Fatal("e-posta NULL yazılmış — sql.NullString'in Valid alanı set edilmiyor olabilir")
	}
	if email.String != "yigit@warewave.io" {
		t.Errorf("email = %q, beklenen %q", email.String, "yigit@warewave.io")
	}
}

// Paketin varlık sebebi: config.ModelUser ile AYNI model.User'ı üretmek.
func TestUserResolvesRolesAndTargets(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "yigit", "yigit@warewave.io", "yigit"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateRole(ctx, "ops"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"web01", "db01"} {
		if _, err := s.CreateTarget(ctx, model.Target{
			Name: name, Host: "127.0.0.1", Port: 22, HostKey: testHostKey,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.AssignRole(ctx, "yigit", "ops"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	for _, name := range []string{"web01", "db01"} {
		if err := s.GrantTarget(ctx, "ops", name); err != nil {
			t.Fatalf("GrantTarget(%s): %v", name, err)
		}
	}

	u, err := s.User(ctx, "yigit")
	if err != nil {
		t.Fatalf("User: %v", err)
	}
	if len(u.Roles) != 1 {
		t.Fatalf("Roles = %d adet, beklenen 1: %+v", len(u.Roles), u.Roles)
	}
	if u.Roles[0].Name != "ops" {
		t.Errorf("rol adı = %q, beklenen %q", u.Roles[0].Name, "ops")
	}

	got := map[string]bool{}
	for _, tgt := range u.Roles[0].Targets {
		got[tgt] = true
	}
	if len(got) != 2 || !got["web01"] || !got["db01"] {
		t.Errorf("rolün hedefleri = %v, beklenen web01 + db01", u.Roles[0].Targets)
	}
}

func TestAssignRoleIsIdempotent(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "yigit", "", "yigit"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateRole(ctx, "ops"); err != nil {
		t.Fatal(err)
	}

	if err := s.AssignRole(ctx, "yigit", "ops"); err != nil {
		t.Fatal(err)
	}
	// "Bu kişiye ops ver" isteği, kişi zaten ops ise yerine getirilmiştir.
	if err := s.AssignRole(ctx, "yigit", "ops"); err != nil {
		t.Fatalf("ikinci AssignRole hata verdi: %v", err)
	}

	u, err := s.User(ctx, "yigit")
	if err != nil {
		t.Fatal(err)
	}
	if len(u.Roles) != 1 {
		t.Fatalf("Roles = %d adet, beklenen 1 — rol iki kez eklenmiş olabilir", len(u.Roles))
	}

	// İkinci, FARKLI bir rol yutulmamalı.
	//
	// Idempotency'nin "zaten var" tanımı kullanıcı+rol ÇİFTİ olmalı,
	// yalnızca kullanıcı değil. Tanım kullanıcıya daralırsa bu atama
	// sessizce hiçbir şey yapmaz: hata yok, log yok, sadece eksik yetki.
	if _, err := s.CreateRole(ctx, "dba"); err != nil {
		t.Fatal(err)
	}
	if err := s.AssignRole(ctx, "yigit", "dba"); err != nil {
		t.Fatalf("ikinci rol: %v", err)
	}

	u, err = s.User(ctx, "yigit")
	if err != nil {
		t.Fatal(err)
	}
	if len(u.Roles) != 2 {
		t.Fatalf("Roles = %d adet, beklenen 2 — ikinci rol sessizce yutulmuş olabilir: %+v", len(u.Roles), u.Roles)
	}
}

func TestAssignRoleUnknown(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "yigit", "", "yigit"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateRole(ctx, "ops"); err != nil {
		t.Fatal(err)
	}

	if err := s.AssignRole(ctx, "yok-boyle-biri", "ops"); !errors.Is(err, ErrNotFound) {
		t.Errorf("bilinmeyen kullanıcı: hata = %v, beklenen ErrNotFound", err)
	}
	if err := s.AssignRole(ctx, "yigit", "yok-boyle-rol"); !errors.Is(err, ErrNotFound) {
		t.Errorf("bilinmeyen rol: hata = %v, beklenen ErrNotFound", err)
	}
}

func TestTargetRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	want := model.Target{Name: "web01", Host: "192.168.1.30", Port: 2201, HostKey: testHostKey}
	if _, err := s.CreateTarget(ctx, want); err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}

	got, err := s.Target(ctx, "web01")
	if err != nil {
		t.Fatalf("Target: %v", err)
	}
	if got != want {
		t.Errorf("Target = %+v, beklenen %+v", got, want)
	}

	if _, err := s.Target(ctx, "yok"); !errors.Is(err, ErrNotFound) {
		t.Errorf("bilinmeyen hedef: hata = %v, beklenen ErrNotFound", err)
	}
}

func TestTargetsSortedByName(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	// Kasten alfabetik OLMAYAN sırada, kasten KARIŞIK harf düzeniyle.
	//
	// Zeta/App01 burada bilerek var: SQLite'ın varsayılan metin
	// karşılaştırması bayt sırasıdır ve bütün büyük harfleri bütün küçük
	// harflerden önce dizer ("Zeta" < "app01"). targets.name sütununda
	// COLLATE NOCASE olmasaydı bu test düşerdi — sadece küçük harfli
	// adlarla yazılmış bir test ise farkı hiç göremezdi.
	for _, name := range []string{"web01", "App01", "db01", "Zeta"} {
		if _, err := s.CreateTarget(ctx, model.Target{
			Name: name, Host: "127.0.0.1", Port: 22, HostKey: testHostKey,
		}); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.Targets(ctx)
	if err != nil {
		t.Fatalf("Targets: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("%d hedef döndü, beklenen 4", len(got))
	}
	for i, want := range []string{"App01", "db01", "web01", "Zeta"} {
		if got[i].Name != want {
			t.Errorf("Targets[%d] = %q, beklenen %q", i, got[i].Name, want)
		}
	}
}

// Hedef adı büyük/küçük harf ayrımı gözetmez: sütun COLLATE NOCASE.
//
// İki yönü de önemli. Arama tarafı kolaylık ("yigit:Web01" yazan kullanıcı
// reddedilmesin); UNIQUE tarafı ise güvenlik: aynı makinenin "web01" ve
// "Web01" diye İKİ ayrı hedef olarak tanımlanabilmesi, yetkiyi birine verip
// diğerinden sızdırmayı mümkün kılardı.
func TestTargetNameIsCaseInsensitive(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateTarget(ctx, model.Target{
		Name: "web01", Host: "127.0.0.1", Port: 22, HostKey: testHostKey,
	}); err != nil {
		t.Fatal(err)
	}

	got, err := s.Target(ctx, "WEB01")
	if err != nil {
		t.Fatalf("Target(\"WEB01\"): %v", err)
	}
	if got.Name != "web01" {
		t.Errorf("Name = %q, beklenen %q — saklanan kanonik ad dönmeli", got.Name, "web01")
	}

	_, err = s.CreateTarget(ctx, model.Target{
		Name: "Web01", Host: "10.0.0.1", Port: 22, HostKey: testHostKey,
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("hata = %v, beklenen ErrConflict — aynı makine iki adla tanımlanabiliyor", err)
	}
}

// SQLite, PRAGMA foreign_keys açılmadıkça REFERENCES satırlarını SESSİZCE
// yok sayar. Bu test tam olarak o pragma'nın açık olup olmadığını sorar:
// olmayan bir kullanıcıya rol veren satır kabul EDİLMEMELİ.
func TestForeignKeysAreEnforced(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO user_roles (user_id, role_id) VALUES ('hayalet-kullanici', 'hayalet-rol')`)
	if err == nil {
		t.Fatal("var olmayan kullanıcı/rol'e referans veren satır kabul edildi — " +
			"PRAGMA foreign_keys açık değil, şemadaki REFERENCES satırları etkisiz")
	}
}

// ---------------------------------------------------------------------
// Oturum denetim kaydı
// ---------------------------------------------------------------------

// seedSession, oturum testleri için kullanıcı + hedef hazırlar.
func seedSession(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()

	if _, err := s.CreateUser(ctx, "yigit", "", "yigit"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateTarget(ctx, model.Target{
		Name: "web01", Host: "127.0.0.1", Port: 22, HostKey: testHostKey,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSessionLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedSession(t, s)

	start := time.Now().Truncate(time.Second)
	rec := SessionStart{
		ID:            "0123456789abcdef",
		Username:      "yigit",
		TargetName:    "web01",
		OSUser:        "root", // policy'nin O ANKİ kararı — users.os_user değil
		SrcIP:         "192.168.1.10",
		StartedAt:     start,
		RecordingPath: "/var/lib/postern/recordings/2026-08-21/0123456789abcdef.cast",
	}
	if err := s.StartSession(ctx, rec); err != nil {
		t.Fatalf("StartSession: %v", err)
	}

	got, err := s.Sessions(ctx, "", 0)
	if err != nil {
		t.Fatalf("Sessions: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("%d oturum döndü, beklenen 1", len(got))
	}

	sess := got[0]
	if !sess.Open() {
		t.Error("yeni açılmış oturum kapalı görünüyor — ended_at NULL olmalıydı")
	}
	if sess.User != "yigit" || sess.Target != "web01" {
		t.Errorf("User/Target = %q/%q, beklenen yigit/web01 — JOIN ad döndürmüyor olabilir", sess.User, sess.Target)
	}
	if sess.OSUser != "root" {
		t.Errorf("OSUser = %q, beklenen %q — kaydın kendi değeri değil users.os_user okunmuş olabilir", sess.OSUser, "root")
	}
	if !sess.StartedAt.Equal(start) {
		t.Errorf("StartedAt = %v, beklenen %v", sess.StartedAt, start)
	}
	if sess.RecordingPath != rec.RecordingPath {
		t.Errorf("RecordingPath = %q, beklenen %q", sess.RecordingPath, rec.RecordingPath)
	}

	end := start.Add(3 * time.Minute)
	if err := s.EndSession(ctx, rec.ID, end); err != nil {
		t.Fatalf("EndSession: %v", err)
	}

	got, err = s.Sessions(ctx, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Open() {
		t.Error("kapatılan oturum hâlâ açık görünüyor")
	}
	if !got[0].EndedAt.Equal(end) {
		t.Errorf("EndedAt = %v, beklenen %v", got[0].EndedAt, end)
	}
}

func TestStartSessionUnknownRefs(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedSession(t, s)

	base := SessionStart{ID: "aa", Username: "yigit", TargetName: "web01", OSUser: "yigit", StartedAt: time.Now()}

	bad := base
	bad.Username = "yok-boyle-biri"
	if err := s.StartSession(ctx, bad); !errors.Is(err, ErrNotFound) {
		t.Errorf("bilinmeyen kullanıcı: hata = %v, beklenen ErrNotFound", err)
	}

	bad = base
	bad.TargetName = "yok-boyle-hedef"
	if err := s.StartSession(ctx, bad); !errors.Is(err, ErrNotFound) {
		t.Errorf("bilinmeyen hedef: hata = %v, beklenen ErrNotFound", err)
	}
}

// Denetim kaydı geriye dönük değiştirilemez: ilk kapanış gerçek kapanıştır.
// İkinci çağrı bir hata yolundan gelen tekrar çağrıdır (defer'lı bir Close
// gibi) ve ended_at'i EZMEMELİ.
func TestEndSessionDoesNotOverwrite(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedSession(t, s)

	start := time.Now().Truncate(time.Second)
	if err := s.StartSession(ctx, SessionStart{
		ID: "bb", Username: "yigit", TargetName: "web01", OSUser: "yigit", StartedAt: start,
	}); err != nil {
		t.Fatal(err)
	}

	first := start.Add(1 * time.Minute)
	if err := s.EndSession(ctx, "bb", first); err != nil {
		t.Fatal(err)
	}
	// İkinci kapanış: hata vermese de vermese de olur, ama DEĞİŞTİRMEMELİ.
	_ = s.EndSession(ctx, "bb", start.Add(99*time.Minute))

	got, err := s.Sessions(ctx, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !got[0].EndedAt.Equal(first) {
		t.Fatalf("EndedAt = %v, beklenen %v — ikinci EndSession denetim kaydını ezdi", got[0].EndedAt, first)
	}
}

func TestEndSessionUnknown(t *testing.T) {
	err := newTestStore(t).EndSession(context.Background(), "hic-boyle-oturum-yok", time.Now())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("hata = %v, beklenen ErrNotFound", err)
	}
}

func TestSessionsOrderFilterAndLimit(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedSession(t, s)

	if _, err := s.CreateUser(ctx, "ayse", "", "ayse"); err != nil {
		t.Fatal(err)
	}

	base := time.Now().Truncate(time.Second)
	seed := []struct {
		id   string
		user string
		at   time.Time
	}{
		{"s1", "yigit", base.Add(-3 * time.Hour)},
		{"s2", "ayse", base.Add(-2 * time.Hour)},
		{"s3", "yigit", base.Add(-1 * time.Hour)},
	}
	for _, x := range seed {
		if err := s.StartSession(ctx, SessionStart{
			ID: x.id, Username: x.user, TargetName: "web01", OSUser: x.user, StartedAt: x.at,
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Sıra: yeniden eskiye.
	all, err := s.Sessions(ctx, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"s3", "s2", "s1"} {
		if all[i].ID != want {
			t.Errorf("Sessions[%d] = %q, beklenen %q — sıralama yeniden eskiye değil", i, all[i].ID, want)
		}
	}

	// Filtre: yalnızca o kullanıcı.
	mine, err := s.Sessions(ctx, "yigit", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(mine) != 2 {
		t.Fatalf("yigit için %d oturum döndü, beklenen 2", len(mine))
	}
	for _, sess := range mine {
		if sess.User != "yigit" {
			t.Errorf("filtreye rağmen %q kullanıcısının oturumu döndü", sess.User)
		}
	}

	// Limit: en yeniler.
	one, err := s.Sessions(ctx, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(one) != 1 || one[0].ID != "s3" {
		t.Fatalf("limit=1 sonucu = %+v, beklenen tek eleman s3", one)
	}
}

// ---------------------------------------------------------------------
// Açık anahtarlar
// ---------------------------------------------------------------------

// testKeyBlob, deterministik bir ed25519 açık anahtarının Marshal çıktısı.
// seed'i değiştirmek farklı bir anahtar üretir.
func testKeyBlob(t *testing.T, seed byte) []byte {
	t.Helper()

	raw := make([]byte, ed25519.SeedSize)
	for i := range raw {
		raw[i] = seed
	}
	pub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(raw).Public())
	if err != nil {
		t.Fatal(err)
	}
	return pub.Marshal()
}

func TestPublicKeyRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "yigit", "", "yigit"); err != nil {
		t.Fatal(err)
	}
	blob := testKeyBlob(t, 1)

	if err := s.AddPublicKey(ctx, "yigit", blob, "yigit@laptop"); err != nil {
		t.Fatalf("AddPublicKey: %v", err)
	}

	u, err := s.UserByPublicKey(ctx, blob)
	if err != nil {
		t.Fatalf("UserByPublicKey: %v", err)
	}
	if u.Name != "yigit" || u.OSUser != "yigit" {
		t.Errorf("kullanıcı = %+v, beklenen yigit/yigit", u)
	}

	keys, err := s.PublicKeys(ctx, "yigit")
	if err != nil {
		t.Fatalf("PublicKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("%d anahtar döndü, beklenen 1", len(keys))
	}
	if !bytes.Equal(keys[0].Blob, blob) {
		t.Error("dönen blob yazılanla aynı değil — base64 çevrimi kayıplı olabilir")
	}
	if keys[0].Comment != "yigit@laptop" {
		t.Errorf("comment = %q, beklenen %q", keys[0].Comment, "yigit@laptop")
	}
}

// UserByPublicKey'in dönüşü doğrudan policy'ye gidecek: rolsüz gelirse
// kimliği doğrulanmış kullanıcı hiçbir hedefe erişemez.
func TestUserByPublicKeyCarriesRoles(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "yigit", "", "yigit"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateRole(ctx, "ops"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateTarget(ctx, model.Target{
		Name: "web01", Host: "127.0.0.1", Port: 22, HostKey: testHostKey,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.AssignRole(ctx, "yigit", "ops"); err != nil {
		t.Fatal(err)
	}
	if err := s.GrantTarget(ctx, "ops", "web01"); err != nil {
		t.Fatal(err)
	}

	blob := testKeyBlob(t, 2)
	if err := s.AddPublicKey(ctx, "yigit", blob, ""); err != nil {
		t.Fatal(err)
	}

	u, err := s.UserByPublicKey(ctx, blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(u.Roles) != 1 || u.Roles[0].Name != "ops" {
		t.Fatalf("Roles = %+v, beklenen tek 'ops' rolü", u.Roles)
	}
	if len(u.Roles[0].Targets) != 1 || u.Roles[0].Targets[0] != "web01" {
		t.Fatalf("rolün hedefleri = %v, beklenen [web01]", u.Roles[0].Targets)
	}
}

func TestUnknownPublicKey(t *testing.T) {
	_, err := newTestStore(t).UserByPublicKey(context.Background(), testKeyBlob(t, 9))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("hata = %v, beklenen ErrNotFound", err)
	}
}

// Aynı anahtarı aynı kişiye tekrar eklemek istek zaten yerine getirilmiş
// demektir; AssignRole ile aynı sözleşme.
func TestAddPublicKeyIsIdempotent(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "yigit", "", "yigit"); err != nil {
		t.Fatal(err)
	}
	blob := testKeyBlob(t, 3)

	if err := s.AddPublicKey(ctx, "yigit", blob, "laptop"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddPublicKey(ctx, "yigit", blob, "laptop"); err != nil {
		t.Fatalf("ikinci ekleme hata verdi: %v", err)
	}

	keys, err := s.PublicKeys(ctx, "yigit")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("%d anahtar döndü, beklenen 1 — anahtar iki kez yazılmış olabilir", len(keys))
	}
}

// ⚠️ Bir anahtar TEK bir kimliğe ait olabilir.
//
// İkinci kullanıcıya da bağlanabilseydi, o anahtarla gelen birinin hangi
// hesap olduğu belirsizleşirdi: auth ikisinden birini seçer, denetim kaydı
// o seçimi doğru sanar. "Kim girdi" sorusunun tek cevabı olmalı.
func TestPublicKeyBelongsToOneUser(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	for _, name := range []string{"yigit", "ayse"} {
		if _, err := s.CreateUser(ctx, name, "", name); err != nil {
			t.Fatal(err)
		}
	}
	blob := testKeyBlob(t, 4)

	if err := s.AddPublicKey(ctx, "yigit", blob, ""); err != nil {
		t.Fatal(err)
	}

	err := s.AddPublicKey(ctx, "ayse", blob, "")
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("hata = %v, beklenen ErrConflict — anahtar iki kimliğe bağlanabiliyor", err)
	}

	// Ve sahibi DEĞİŞMEMİŞ olmalı.
	u, err := s.UserByPublicKey(ctx, blob)
	if err != nil {
		t.Fatal(err)
	}
	if u.Name != "yigit" {
		t.Errorf("anahtarın sahibi = %q, beklenen %q — reddedilen ekleme sahipliği devretmiş", u.Name, "yigit")
	}
}

func TestAddPublicKeyUnknownUser(t *testing.T) {
	err := newTestStore(t).AddPublicKey(context.Background(), "yok-boyle-biri", testKeyBlob(t, 5), "")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("hata = %v, beklenen ErrNotFound", err)
	}
}

// Kullanıcı silinince anahtarları da gitmeli (ON DELETE CASCADE).
// Yetim bir anahtar, silinmiş bir kullanıcının hâlâ giriş yapabilmesi demek.
func TestDeletingUserRemovesKeys(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "yigit", "", "yigit"); err != nil {
		t.Fatal(err)
	}
	blob := testKeyBlob(t, 6)
	if err := s.AddPublicKey(ctx, "yigit", blob, ""); err != nil {
		t.Fatal(err)
	}

	if _, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE username = ?`, "yigit"); err != nil {
		t.Fatal(err)
	}

	if _, err := s.UserByPublicKey(ctx, blob); !errors.Is(err, ErrNotFound) {
		t.Fatalf("hata = %v, beklenen ErrNotFound — silinen kullanıcının anahtarı hâlâ tanınıyor", err)
	}
}

func TestUsersListsAllWithRoles(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	// Bilerek alfabetik olmayan sırada ve farklı şekillerde:
	// rolsüz, tek rollü, iki rollü.
	for _, u := range []struct{ name, os string }{
		{"zeynep", "zeynep"}, {"ali", "ali"}, {"yigit", "yigit"},
	} {
		if _, err := s.CreateUser(ctx, u.name, "", u.os); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range []string{"ops", "dba"} {
		if _, err := s.CreateRole(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.CreateTarget(ctx, model.Target{Name: "web01", Host: "h", Port: 22, HostKey: testHostKey}); err != nil {
		t.Fatal(err)
	}
	if err := s.GrantTarget(ctx, "ops", "web01"); err != nil {
		t.Fatal(err)
	}
	if err := s.AssignRole(ctx, "yigit", "ops"); err != nil {
		t.Fatal(err)
	}
	if err := s.AssignRole(ctx, "yigit", "dba"); err != nil {
		t.Fatal(err)
	}
	if err := s.AssignRole(ctx, "ali", "ops"); err != nil {
		t.Fatal(err)
	}

	users, err := s.Users(ctx)
	if err != nil {
		t.Fatalf("Users: %v", err)
	}
	if len(users) != 3 {
		t.Fatalf("%d kullanıcı döndü, beklenen 3: %+v", len(users), users)
	}
	for i, want := range []string{"ali", "yigit", "zeynep"} {
		if users[i].Name != want {
			t.Errorf("users[%d] = %q, beklenen %q — sıralama ada göre değil", i, users[i].Name, want)
		}
	}

	byName := map[string]model.User{}
	for _, u := range users {
		byName[u.Name] = u
	}
	if got := len(byName["zeynep"].Roles); got != 0 {
		t.Errorf("zeynep %d rolle geldi, beklenen 0", got)
	}
	if got := len(byName["yigit"].Roles); got != 2 {
		t.Errorf("yigit %d rolle geldi, beklenen 2: %+v", got, byName["yigit"].Roles)
	}
	// Satır çarpımı tuzağı: ali'nin TEK rolü var; kullanıcı gruplaması
	// yanlışsa ops'un hedef satırları ali'yi çoğaltır ya da rolünü şişirir.
	if got := len(byName["ali"].Roles); got != 1 {
		t.Errorf("ali %d rolle geldi, beklenen 1: %+v", got, byName["ali"].Roles)
	}
	if len(byName["ali"].Roles) == 1 && len(byName["ali"].Roles[0].Targets) != 1 {
		t.Errorf("ali'nin ops rolü %v hedefiyle geldi, beklenen [web01]", byName["ali"].Roles[0].Targets)
	}
}

func TestUserByEmail(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "yigit", "yigit@warewave.io", "yigit"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, "epostasiz", "", "epostasiz"); err != nil {
		t.Fatal(err)
	}

	u, err := s.UserByEmail(ctx, "yigit@warewave.io")
	if err != nil {
		t.Fatalf("UserByEmail: %v", err)
	}
	if u.Name != "yigit" {
		t.Errorf("Name = %q, beklenen %q", u.Name, "yigit")
	}

	// IdP'de hesap olması postern'de hesap olması demek değil.
	if _, err := s.UserByEmail(ctx, "yabanci@ornek.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bilinmeyen e-posta: %v, beklenen ErrNotFound", err)
	}

	// Boş e-posta HİÇBİR kullanıcıyla eşleşmemeli — e-postasız kullanıcılar
	// NULL saklanıyor ama savunma katmanlı olsun.
	if _, err := s.UserByEmail(ctx, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("boş e-posta: %v, beklenen ErrNotFound", err)
	}
}

func TestSessionByID(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedSession(t, s)

	start := time.Now().Truncate(time.Second)
	if err := s.StartSession(ctx, SessionStart{
		ID: "tekil", Username: "yigit", TargetName: "web01", OSUser: "root",
		SrcIP: "192.168.1.10", StartedAt: start,
		RecordingPath: "/var/lib/postern/recordings/tekil.cast",
	}); err != nil {
		t.Fatal(err)
	}

	got, err := s.Session(ctx, "tekil")
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if got.User != "yigit" || got.Target != "web01" {
		t.Errorf("User/Target = %q/%q — JOIN ad döndürmüyor olabilir", got.User, got.Target)
	}
	if got.OSUser != "root" || got.SrcIP != "192.168.1.10" {
		t.Errorf("OSUser/SrcIP = %q/%q", got.OSUser, got.SrcIP)
	}
	if !got.StartedAt.Equal(start) || !got.Open() {
		t.Errorf("zaman/durum bozuk: started=%v open=%v", got.StartedAt, got.Open())
	}
	if got.RecordingPath == "" {
		t.Error("RecordingPath boş")
	}

	if _, err := s.Session(ctx, "yok-boyle-oturum"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bilinmeyen id: %v, beklenen ErrNotFound", err)
	}
}

func TestSetUserEmail(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "yigit", "", "yigit"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, "ayse", "ayse@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}

	// Sonradan eklenen e-posta OIDC eşleşmesinde görünmeli.
	if err := s.SetUserEmail(ctx, "yigit", "yigit@warewave.io"); err != nil {
		t.Fatalf("SetUserEmail: %v", err)
	}
	if u, err := s.UserByEmail(ctx, "yigit@warewave.io"); err != nil || u.Name != "yigit" {
		t.Fatalf("UserByEmail = %+v, %v", u, err)
	}

	// Başkasının adresi alınamaz: OIDC eşleşmesi tekil kalmalı.
	if err := s.SetUserEmail(ctx, "yigit", "ayse@warewave.io"); !errors.Is(err, ErrConflict) {
		t.Fatalf("çakışan adres: %v, beklenen ErrConflict", err)
	}

	// Boş string adresi SİLER (NULL) — ve e-postasız başka kullanıcı
	// varken UNIQUE'e takılmamalı (NULL, '' değil).
	if err := s.SetUserEmail(ctx, "ayse", ""); err != nil {
		t.Fatalf("adres silme: %v", err)
	}
	if _, err := s.UserByEmail(ctx, "ayse@warewave.io"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("silinen adres hâlâ eşleşiyor: %v", err)
	}

	if err := s.SetUserEmail(ctx, "yok-boyle-biri", "x@y.z"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bilinmeyen kullanıcı: %v, beklenen ErrNotFound", err)
	}
}

func TestSetUserOSUser(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "yigit", "", "yigit"); err != nil {
		t.Fatal(err)
	}

	if err := s.SetUserOSUser(ctx, "yigit", "deploy"); err != nil {
		t.Fatalf("SetUserOSUser: %v", err)
	}
	u, err := s.User(ctx, "yigit")
	if err != nil {
		t.Fatal(err)
	}
	if u.OSUser != "deploy" {
		t.Errorf("OSUser = %q, beklenen %q", u.OSUser, "deploy")
	}

	// Boş os_user şemanın CHECK'ine takılmalı: kimliksiz principal olmaz.
	if err := s.SetUserOSUser(ctx, "yigit", ""); err == nil {
		t.Fatal("boş os_user kabul edildi")
	}

	if err := s.SetUserOSUser(ctx, "yok", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bilinmeyen kullanıcı: %v, beklenen ErrNotFound", err)
	}
}
