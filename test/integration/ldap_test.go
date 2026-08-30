//go:build integration

package integration

// S5.3'ün kanıtı: gruplar LDAP dizininden okunuyor.
//
//	go test -tags integration -run TestLDAP -v ./test/integration/

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/ldap"
	"github.com/warewave/postern/internal/store"
)

const (
	ldapBaseDN   = "dc=warewave,dc=io"
	ldapAdminDN  = "cn=admin,dc=warewave,dc=io"
	ldapAdminPwd = "admin-test-123"
	ldapUser     = "yigit.basalma"
)

// startOpenLDAP, tohumlanmış bir dizin kaldırır ve ldap:// URL'ini döner.
//
// Düz ldap:// kullanıyoruz ve bu bilinçli: konteyner loopback'te ve
// ldap.New yalnızca loopback'te düz bağlantıya izin veriyor — testin
// kendisi o kuralı da doğrulamış oluyor.
func startOpenLDAP(t *testing.T) string {
	t.Helper()
	ctx := context.Background()

	ldifPath, err := filepath.Abs(filepath.Join("testdata", "ldap", "seed.ldif"))
	if err != nil {
		t.Fatal(err)
	}

	cont, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "osixia/openldap:1.5.0",
			Cmd:          []string{"--copy-service"},
			ExposedPorts: []string{"389/tcp"},
			Env: map[string]string{
				"LDAP_ORGANISATION":   "Warewave",
				"LDAP_DOMAIN":         "warewave.io",
				"LDAP_ADMIN_PASSWORD": ldapAdminPwd,
			},
			Files: []testcontainers.ContainerFile{{
				HostFilePath:      ldifPath,
				ContainerFilePath: "/container/service/slapd/assets/config/bootstrap/ldif/custom/seed.ldif",
				FileMode:          0o644,
			}},
			WaitingFor: wait.ForLog("slapd starting").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("openldap başlatılamadı (Docker ayakta mı?): %v", err)
	}
	t.Cleanup(func() { _ = cont.Terminate(context.Background()) })

	port, err := cont.MappedPort(ctx, "389")
	if err != nil {
		t.Fatal(err)
	}
	// Konteyner loopback'e eşlendi; ldap.New'in loopback istisnası için
	// 127.0.0.1 kullanıyoruz — testin kendisi o kuralı da doğruluyor.
	return fmt.Sprintf("ldap://127.0.0.1:%d", port.Num())
}

func ldapConfig(url string) ldap.Config {
	return ldap.Config{
		URL:          url,
		BindDN:       ldapAdminDN,
		BindPassword: ldapAdminPwd,
		UserBase:     "ou=people," + ldapBaseDN,
		UserFilter:   "(uid=%s)",
		GroupBase:    "ou=groups," + ldapBaseDN,
		GroupFilter:  "(&(objectClass=groupOfNames)(member=%s))",
	}
}

/*
 * dialLDAP, TESTİN dizini değiştirmek için kullandığı bağlantı.
 *
 * postern'in kendi bağlantısından ayrı ve yönetici olarak bağlanıyor:
 * burada amaç dizini KURCALAMAK (yeniden adlandırma, silme), postern'in
 * gördüğü şeyi taklit etmek değil.
 */
func dialLDAP(t *testing.T, url string) *goldap.Conn {
	t.Helper()
	conn, err := goldap.DialURL(url)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := conn.Bind(ldapAdminDN, ldapAdminPwd); err != nil {
		t.Fatalf("bind: %v", err)
	}
	return conn
}

// Grup araması yolu: üyelik grubun üstünde (groupOfNames).
func TestLDAPGroupsBySearch(t *testing.T) {
	url := startOpenLDAP(t)

	src, err := ldap.New(ldapConfig(url))
	if err != nil {
		t.Fatalf("ldap.New: %v", err)
	}

	ctx := context.Background()
	if err := src.Test(ctx); err != nil {
		t.Fatalf("Test: %v", err)
	}

	res, err := src.Groups(ctx, auth.Identity{Username: ldapUser})
	if err != nil {
		t.Fatalf("Groups: %v", err)
	}
	if res.Presence != auth.GroupsPresent {
		t.Fatalf("varlık = %s, beklenen present", res.Presence)
	}
	groups := res.Groups

	// CN çıkarımı: "cn=sysadmins,ou=groups,..." → "sysadmins".
	// OIDC claim'inden gelen adla aynı isim uzayına düşmeli.
	want := map[string]bool{"sysadmins": false, "dbteam": false}
	for _, g := range groups {
		if _, ok := want[g]; ok {
			want[g] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("%q grubu dönmedi; gelen: %v", name, groups)
		}
	}

	/*
	 * Dizinde olmayan kullanıcı: hata DEĞİL, ama BOŞ LİSTE DE DEĞİL.
	 *
	 * Bu satır eskiden "gruplar boş" diye geçiyordu ve tam olarak
	 * ölçülen arızayı gizliyordu: giriş yolu boş listeyi "hiçbir gruba
	 * üye değil" sanıp bütün SSO rollerini siliyordu. Üç değerli cevapta
	 * bu hâlin ADI var.
	 */
	absent, err := src.Groups(ctx, auth.Identity{Username: "hic-yok"})
	if err != nil {
		t.Fatalf("bilinmeyen kullanıcı hata verdi: %v", err)
	}
	if absent.Presence != auth.GroupsAbsent {
		t.Errorf("bilinmeyen kullanıcı için varlık = %s, beklenen absent", absent.Presence)
	}
	if len(absent.Groups) != 0 {
		t.Errorf("bulunamayan kullanıcı için gruplar = %v", absent.Groups)
	}
}

// Kullanıcı özniteliğinden okuma yolu: üyelik KULLANICININ üstünde.
//
// Gerçek dizinlerde bu öznitelik "memberOf" olur. Testte "ou"
// kullanıyoruz çünkü memberOf operasyoneldir ve bootstrap LDIF'iyle
// yazılamaz; okunan şey aynı — kod öznitelik adını yapılandırmadan
// alıyor ve "memberOf" diye bir varsayımı yok.
func TestLDAPGroupsByUserAttribute(t *testing.T) {
	url := startOpenLDAP(t)

	cfg := ldapConfig(url)
	// GroupFilter kalkıyor (arama yolu kullanılmıyor) ama GroupBase
	// DURUYOR: memberOf yolunda da grup kimliğini kapsamak için zorunlu
	// — dizinin herhangi bir yerindeki bir grup rol veremesin.
	cfg.GroupFilter = ""
	cfg.GroupAttribute = "ou"

	src, err := ldap.New(cfg)
	if err != nil {
		t.Fatalf("ldap.New: %v", err)
	}

	gres, err := src.Groups(context.Background(), auth.Identity{Username: ldapUser})
	if err != nil {
		t.Fatalf("Groups: %v", err)
	}
	groups := gres.Groups
	if len(groups) != 2 {
		t.Fatalf("gruplar = %v, beklenen 2 tane", groups)
	}
	for _, g := range groups {
		if g != "sysadmins" && g != "dbteam" {
			t.Errorf("beklenmeyen grup %q — CN çıkarımı çalışmamış olabilir", g)
		}
	}
}

/*
 * ⚠️ ÖZNİTELİK ADI HARFE DUYARSIZ EŞLENMELİ.
 *
 * ÖLÇÜLEN ARIZA: LDAP'ta öznitelik adları harfe duyarsız ve sunucu,
 * istenen yazımla değil KENDİ ŞEMA YAZIMIYLA döndürüyor. go-ldap'ın düz
 * GetAttributeValues'i harfe duyarlı eşlediği için, "OU" yazan bir ayar
 * sunucudan gelen "ou" özniteliğini GÖREMİYORDU.
 *
 * Sonucu sessiz ve ağır: dizin "present" diyor, teşhis ekranı yeşil
 * kalıyor, ama kullanıcının bütün grupları — dolayısıyla bütün rolleri —
 * yok oluyor. Panelin kendi ipucunda yazan "memberOf"u "memberof" diye
 * yazan operatör tam bu tuzağa düşüyordu.
 */
func TestLDAPGroupAttributeIsCaseInsensitive(t *testing.T) {
	url := startOpenLDAP(t)

	// Şemadaki yazım "ou". Üçü de AYNI özniteliktir.
	for _, spelling := range []string{"ou", "OU", "oU"} {
		t.Run(spelling, func(t *testing.T) {
			cfg := ldapConfig(url)
			cfg.GroupFilter = ""
			cfg.GroupAttribute = spelling

			src, err := ldap.New(cfg)
			if err != nil {
				t.Fatalf("ldap.New: %v", err)
			}
			gres, err := src.Groups(context.Background(), auth.Identity{Username: ldapUser})
			if err != nil {
				t.Fatalf("Groups: %v", err)
			}
			if len(gres.Groups) != 2 {
				t.Fatalf("%q yazımıyla gruplar = %v; yazım farkı yüzünden "+
					"kullanıcı bütün rollerini kaybederdi", spelling, gres.Groups)
			}
		})
	}
}

/*
 * ⚠️ KARARLI KİMLİK: bütün bağlama tasarımının dayandığı özellik.
 *
 * Kullanıcı adı bir kimlik DEĞİL — dizinde değişir, hatta yeniden
 * kullanılır. entryUUID ise aynı kişi için sabit kalır. Bu test o
 * varsayımı DOĞRULUYOR, çünkü yanlış olsaydı üstüne kurulan her şey
 * sessizce yanlış olurdu.
 *
 * Üç olay ölçülüyor ve üçünün de sonucu farklı:
 *   yeniden adlandırma → DN değişir, kimlik AYNI kalır
 *   OU taşıma          → DN değişir, kimlik AYNI kalır
 *   sil + aynı adla aç → DN aynıdır, kimlik DEĞİŞİR
 *
 * Sonuncusu güvenlik tarafı: ayrılan çalışanın adını alan kişi, eski
 * postern hesabını devralamaz.
 */
func TestLDAPIdentityIsStableAcrossRename(t *testing.T) {
	url := startOpenLDAP(t)
	cfg := ldapConfig(url)
	cfg.GroupFilter = ""
	cfg.GroupAttribute = "ou"

	src, err := ldap.New(cfg)
	if err != nil {
		t.Fatalf("ldap.New: %v", err)
	}
	ctx := context.Background()

	before, err := src.Lookup(ctx, auth.Identity{Username: ldapUser})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if before.Identity == "" {
		t.Fatal("dizin kararlı kimlik vermedi — entryUUID açıkça istenmiyor olabilir")
	}
	// Kanonik biçim: küçük harfli 8-4-4-4-12.
	if len(before.Identity) != 36 || strings.ToLower(before.Identity) != before.Identity {
		t.Fatalf("kimlik kanonik değil: %q", before.Identity)
	}

	// ⚠️ -r karşılığı: eski RDN değeri KALDIRILIYOR. Kaldırılmazsa eski
	// uid kayıtta kalır, eski adla arama çalışmaya devam eder ve test
	// yanlış sebeple geçer. (Bu tuzağa elle ölçerken düşüldü.)
	conn := dialLDAP(t, url)
	defer conn.Close()
	oldDN := "uid=" + ldapUser + ",ou=people," + ldapBaseDN
	newDN := "uid=yigit.can,ou=people," + ldapBaseDN
	if err := conn.ModifyDN(goldap.NewModifyDNRequest(oldDN, "uid=yigit.can", true, "")); err != nil {
		t.Fatalf("modrdn: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.ModifyDN(goldap.NewModifyDNRequest(newDN, "uid="+ldapUser, true, ""))
	})

	// Eski ad artık YOK: bugün freshen ve senkronizasyon döngüsünün
	// gördüğü şey bu.
	stale, err := src.Lookup(ctx, auth.Identity{Username: ldapUser})
	if err != nil {
		t.Fatalf("Lookup(eski ad): %v", err)
	}
	if stale.Presence != ldap.PresenceAbsent {
		t.Fatalf("eski ad hâlâ çözülüyor (%v) — yeniden adlandırma gerçekleşmemiş olabilir",
			stale.Presence)
	}

	// Yeni adla aynı kişi, AYNI kimlik.
	after, err := src.Lookup(ctx, auth.Identity{Username: "yigit.can"})
	if err != nil {
		t.Fatalf("Lookup(yeni ad): %v", err)
	}
	if after.Presence != ldap.PresencePresent {
		t.Fatalf("yeni ad çözülmedi: %v", after.Presence)
	}
	if after.Identity != before.Identity {
		t.Fatalf("kimlik yeniden adlandırmada DEĞİŞTİ: %q → %q; "+
			"bağlama tasarımının dayandığı özellik yok",
			before.Identity, after.Identity)
	}
}

/*
 * ⚠️ YENİDEN ADLANDIRILAN KULLANICI, SİLİNMİŞ SAYILMAMALI.
 *
 * Adla arama ikisini ayırt edemiyor: dizinde adı değişen kişi de,
 * silinen kişi de PresenceAbsent döndürüyor. O cevabı alan taraflar —
 * oturum açılışındaki tazeleme ve senkron döngüsü — onu erişim iptaline
 * çeviriyor. Yani hiçbir şey yapmayan bir kullanıcı, İK'nın soyadını
 * güncellemesi yüzünden bütün oturumlarını ve rollerini kaybediyordu.
 *
 * Kimlikle arama bu farkı görüyor ve bu testin varlık sebebi o.
 */
func TestLDAPLookupBySubjectSurvivesRename(t *testing.T) {
	url := startOpenLDAP(t)
	cfg := ldapConfig(url)
	cfg.GroupFilter = ""
	cfg.GroupAttribute = "ou"

	src, err := ldap.New(cfg)
	if err != nil {
		t.Fatalf("ldap.New: %v", err)
	}
	ctx := context.Background()

	before, err := src.Lookup(ctx, auth.Identity{Username: ldapUser})
	if err != nil || before.Identity == "" {
		t.Fatalf("başlangıç: %v / %q", err, before.Identity)
	}

	conn := dialLDAP(t, url)
	defer conn.Close()
	oldDN := "uid=" + ldapUser + ",ou=people," + ldapBaseDN
	newDN := "uid=yigit.can,ou=people," + ldapBaseDN
	if err := conn.ModifyDN(goldap.NewModifyDNRequest(oldDN, "uid=yigit.can", true, "")); err != nil {
		t.Fatalf("modrdn: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.ModifyDN(goldap.NewModifyDNRequest(newDN, "uid="+ldapUser, true, ""))
	})

	// Adla: "yok" — ve bu cevap erişimi kesiyor.
	byName, err := src.Lookup(ctx, auth.Identity{Username: ldapUser})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if byName.Presence != ldap.PresenceAbsent {
		t.Fatalf("adla arama = %v; yeniden adlandırma gerçekleşmemiş olabilir", byName.Presence)
	}

	// Kimlikle: AYNI kişi, grupları yerinde.
	bySubject, err := src.LookupBySubject(ctx, before.Identity)
	if err != nil {
		t.Fatalf("LookupBySubject: %v", err)
	}
	if bySubject.Presence != ldap.PresencePresent {
		t.Fatalf("kimlikle arama = %v; yeniden adlandırılan kişi silinmiş sayıldı",
			bySubject.Presence)
	}
	if bySubject.Identity != before.Identity {
		t.Fatalf("kimlik değişti: %q → %q", before.Identity, bySubject.Identity)
	}
	if len(bySubject.Groups) != len(before.Groups) {
		t.Fatalf("gruplar = %v, önce %v", bySubject.Groups, before.Groups)
	}
}

// Gerçekten SİLİNEN kullanıcı, kimlikle de bulunamamalı — yoksa
// yeniden adlandırma düzeltmesi, iptali de bozardı.
func TestLDAPLookupBySubjectStillReportsDeleted(t *testing.T) {
	url := startOpenLDAP(t)
	cfg := ldapConfig(url)
	cfg.GroupFilter = ""
	cfg.GroupAttribute = "ou"

	src, err := ldap.New(cfg)
	if err != nil {
		t.Fatalf("ldap.New: %v", err)
	}
	ctx := context.Background()
	conn := dialLDAP(t, url)
	defer conn.Close()

	const name = "ayrilan.kisi"
	dn := "uid=" + name + ",ou=people," + ldapBaseDN
	req := goldap.NewAddRequest(dn, nil)
	req.Attribute("objectClass", []string{"inetOrgPerson"})
	req.Attribute("uid", []string{name})
	req.Attribute("cn", []string{"Ayrilan Kisi"})
	req.Attribute("sn", []string{"Kisi"})
	if err := conn.Add(req); err != nil {
		t.Fatalf("add: %v", err)
	}

	res, err := src.Lookup(ctx, auth.Identity{Username: name})
	if err != nil || res.Identity == "" {
		t.Fatalf("kurulum: %v / %q", err, res.Identity)
	}

	if err := conn.Del(goldap.NewDelRequest(dn, nil)); err != nil {
		t.Fatalf("del: %v", err)
	}

	gone, err := src.LookupBySubject(ctx, res.Identity)
	if err != nil {
		t.Fatalf("LookupBySubject: %v", err)
	}
	if gone.Presence != ldap.PresenceAbsent {
		t.Fatalf("silinen kullanıcı = %v; iptal yolu bozulmuş", gone.Presence)
	}
}

/*
 * ⚠️ AD GERİ DÖNÜŞÜMÜ YENİ BİR KİMLİK ÜRETMELİ.
 *
 * Üretmezse: ayrılan çalışanın kullanıcı adı yeni birine verildiğinde,
 * yeni kişi eskisinin postern hesabını — rolleriyle ve is_admin
 * bayrağıyla — devralır. 011 göçünün OIDC için kapattığı açığın dizin
 * karşılığı tam olarak budur.
 */
func TestLDAPIdentityChangesWhenNameIsRecycled(t *testing.T) {
	url := startOpenLDAP(t)
	cfg := ldapConfig(url)
	cfg.GroupFilter = ""
	cfg.GroupAttribute = "ou"

	src, err := ldap.New(cfg)
	if err != nil {
		t.Fatalf("ldap.New: %v", err)
	}
	ctx := context.Background()
	conn := dialLDAP(t, url)
	defer conn.Close()

	const name = "gecici.kisi"
	dn := "uid=" + name + ",ou=people," + ldapBaseDN
	add := func() {
		req := goldap.NewAddRequest(dn, nil)
		req.Attribute("objectClass", []string{"inetOrgPerson"})
		req.Attribute("uid", []string{name})
		req.Attribute("cn", []string{"Gecici Kisi"})
		req.Attribute("sn", []string{"Kisi"})
		if err := conn.Add(req); err != nil {
			t.Fatalf("add: %v", err)
		}
	}

	add()
	t.Cleanup(func() { _ = conn.Del(goldap.NewDelRequest(dn, nil)) })

	first, err := src.Lookup(ctx, auth.Identity{Username: name})
	if err != nil || first.Identity == "" {
		t.Fatalf("ilk kayıt: %v / %q", err, first.Identity)
	}

	if err := conn.Del(goldap.NewDelRequest(dn, nil)); err != nil {
		t.Fatalf("del: %v", err)
	}
	add()

	second, err := src.Lookup(ctx, auth.Identity{Username: name})
	if err != nil || second.Identity == "" {
		t.Fatalf("ikinci kayıt: %v / %q", err, second.Identity)
	}

	if second.Identity == first.Identity {
		t.Fatalf("aynı adla yeniden açılan kayıt AYNI kimliği aldı (%q) — "+
			"ad geri dönüşümü hesap devralmaya dönüşürdü", first.Identity)
	}
}

// DN modu: eşlemeler tam DN yazılacaksa.
func TestLDAPGroupNameFromDN(t *testing.T) {
	url := startOpenLDAP(t)

	cfg := ldapConfig(url)
	cfg.GroupNameFrom = "dn"

	src, err := ldap.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	gres, err := src.Groups(context.Background(), auth.Identity{Username: ldapUser})
	if err != nil {
		t.Fatal(err)
	}
	groups := gres.Groups
	for _, g := range groups {
		if len(g) < len("cn=x,ou=groups") {
			t.Errorf("DN modunda kısa ad döndü: %q", g)
		}
	}
}

// Yanlış bind parolası ilk gerçek girişte değil, Test'te ortaya çıkmalı.
func TestLDAPTestCatchesBadConfig(t *testing.T) {
	url := startOpenLDAP(t)
	ctx := context.Background()

	bad := ldapConfig(url)
	bad.BindPassword = "yanlis-parola"
	src, err := ldap.New(bad)
	if err != nil {
		t.Fatal(err)
	}
	if err := src.Test(ctx); err == nil {
		t.Error("yanlış bind parolası testten geçti")
	}

	bad = ldapConfig(url)
	bad.UserBase = "ou=yok," + ldapBaseDN
	src, err = ldap.New(bad)
	if err != nil {
		t.Fatal(err)
	}
	if err := src.Test(ctx); err == nil {
		t.Error("olmayan user_base testten geçti")
	}
}

// Düz ldap:// yalnızca loopback'te: servis hesabı parolası ağdan geçiyor.
func TestLDAPRefusesPlaintextOffLoopback(t *testing.T) {
	cfg := ldapConfig("ldap://ldap.uzak-sunucu.example:389")
	if _, err := ldap.New(cfg); err == nil {
		t.Fatal("loopback dışında düz ldap:// kabul edildi")
	}

	// ldaps:// serbest.
	cfg.URL = "ldaps://ldap.uzak-sunucu.example:636"
	if _, err := ldap.New(cfg); err != nil {
		t.Fatalf("ldaps reddedildi: %v", err)
	}
}

// Zincirin tamamı: kimlik OIDC'den, GRUPLAR LDAP'tan, sonuç postern
// kullanıcısı. Kimliğin ve yetkinin ayrı kaynaklardan gelmesi bu
// tasarımın omurgasıydı — burada birlikte çalıştıkları görülüyor.
func TestLDAPGroupsDriveProvisioning(t *testing.T) {
	ldapURL := startOpenLDAP(t)
	_, apiURL, _, db := oobBastionFresh(t)
	ctx := context.Background()

	// Rol + hedef + eşleme var; kullanıcı YOK.
	if _, err := db.CreateRole(ctx, "ops"); err != nil {
		t.Fatal(err)
	}
	if err := db.GrantTarget(ctx, "ops", "web01"); err != nil {
		t.Fatal(err)
	}
	// Eşleme LDAP grubunun CN'iyle: OIDC claim'iyle aynı isim uzayı.
	if err := db.AddGroupMapping(ctx, "sysadmins", "ops", "test"); err != nil {
		t.Fatal(err)
	}

	src, err := ldap.New(ldapConfig(ldapURL))
	if err != nil {
		t.Fatal(err)
	}

	// IdP'nin verdiği kimlik; gruplar artık token'dan DEĞİL dizinden.
	gres, err := src.Groups(ctx, auth.Identity{Username: ldapUser})
	if err != nil {
		t.Fatal(err)
	}

	u, err := db.ProvisionUser(ctx, store.ProvisionRequest{
		Username: ldapUser,
		Email:    "yigit@warewave.io",
		Groups:   gres.Groups,
		// ⚠️ Cevabın GÜVENİLİR olduğu ayrıca söyleniyor: boş bir grup
		// listesi tek başına "yetkisi yok" demek değil.
		GroupsResolved: gres.Presence == auth.GroupsPresent,
		// Kimlik (issuer, subject) ile bağlanıyor (göç 011).
		Issuer:  "https://idp.test",
		Subject: "sub-" + ldapUser,
	})
	if err != nil {
		t.Fatalf("ProvisionUser: %v", err)
	}

	if u.Name != ldapUser || u.OSUser != ldapUser {
		t.Errorf("kullanıcı = %+v — os_user IdP kullanıcı adı olmalı", u)
	}
	if len(u.Roles) != 1 || u.Roles[0].Name != "ops" {
		t.Fatalf("roller = %+v, beklenen [ops] — LDAP grubu role dönüşmemiş", u.Roles)
	}
	if len(u.Roles[0].Targets) != 1 || u.Roles[0].Targets[0] != "web01" {
		t.Errorf("hedefler = %v", u.Roles[0].Targets)
	}
	if !u.SSOOnly {
		t.Error("JIT kullanıcı sso_only doğmamış")
	}

	// Eşlenmemiş LDAP grubu (dbteam) teşhis tablosuna düşmeli.
	unmapped, err := db.UnmappedGroups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var sawDBTeam bool
	for _, g := range unmapped {
		if g.Name == "dbteam" {
			sawDBTeam = true
		}
	}
	if !sawDBTeam {
		t.Errorf("eşlenmemiş LDAP grubu kaydedilmemiş: %+v", unmapped)
	}

	_ = apiURL
}

/*
 * Dizin parolasıyla kimlik doğrulama, GERÇEK bir OpenLDAP'a karşı.
 *
 * ⚠️ En kritik vaka boş parola. DN verip parolayı boş bırakmak
 * "unauthenticated bind"dir ve sonucu SUNUCUNUN yapılandırmasına
 * bağlıdır — ölçtük: bu OpenLDAP reddediyor, Active Directory ise
 * varsayılan olarak kabul eder. postern bağlandığı dizinin nasıl
 * ayarlandığını bilemeyeceği için kontrolü kendisi yapıyor.
 */
func TestLDAPAuthenticate(t *testing.T) {
	url := startOpenLDAP(t)
	src, err := ldap.New(ldapConfig(url))
	if err != nil {
		t.Fatalf("ldap.New: %v", err)
	}
	ctx := context.Background()

	t.Run("dogru parola", func(t *testing.T) {
		res, err := src.Authenticate(ctx, ldapUser, "dizin-parolasi")
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if !res.Authenticated {
			t.Fatal("doğru parola reddedildi")
		}
		if res.Presence != ldap.PresencePresent {
			t.Fatalf("varlık = %v", res.Presence)
		}
		if len(res.Groups) == 0 {
			t.Error("gruplar boş: kimlik doğrulandıktan sonra da okunmalı")
		}
	})

	t.Run("yanlis parola", func(t *testing.T) {
		res, err := src.Authenticate(ctx, ldapUser, "yanlis")
		if err != nil {
			t.Fatalf("yanlış parola HATA döndürdü: %v — bu bir arıza değil, "+
				"kimlik doğrulanamaması", err)
		}
		if res.Authenticated {
			t.Fatal("yanlış parola kabul edildi")
		}
		if res.Presence != ldap.PresencePresent {
			t.Errorf("kullanıcı bulunmuş olmalı: %v", res.Presence)
		}
	})

	t.Run("bos parola bind'e ULASMIYOR", func(t *testing.T) {
		res, err := src.Authenticate(ctx, ldapUser, "")
		if !errors.Is(err, ldap.ErrEmptySecret) {
			t.Fatalf("hata = %v, ErrEmptySecret bekleniyordu", err)
		}
		if res.Authenticated {
			t.Fatal("boş parola kimlik doğrulanmış sayıldı")
		}
	})

	/*
	 * Sunucunun boş parolaya NE dediğini kayda geçiriyoruz.
	 *
	 * Bu bir iddia değil, bir ölçüm: sonucu ne olursa olsun test
	 * geçiyor. Amacı, postern'deki kontrolün neden uzaktaki ayara
	 * bırakılamayacağını belgelemek — aynı kod farklı dizinlerde
	 * farklı cevap alıyor.
	 */
	t.Run("sunucunun kimliksiz bind politikasi", func(t *testing.T) {
		conn, err := goldap.DialURL(url)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		dn := "uid=" + ldapUser + ",ou=people,dc=warewave,dc=io"
		if berr := conn.UnauthenticatedBind(dn); berr != nil {
			t.Logf("bu sunucu kimliksiz bind'i REDDEDİYOR: %v", berr)
			return
		}
		t.Log("bu sunucu kimliksiz bind'i KABUL EDİYOR — postern'in kontrolü " +
			"olmasaydı boş parola içeri girerdi")
	})

	t.Run("dizinde olmayan kullanici", func(t *testing.T) {
		res, err := src.Authenticate(ctx, "hic-yok", "herhangi")
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if res.Presence != ldap.PresenceAbsent {
			t.Fatalf("varlık = %v, absent bekleniyordu", res.Presence)
		}
		if res.Authenticated {
			t.Fatal("olmayan kullanıcı kimlik doğrulanmış sayıldı")
		}
	})
}
