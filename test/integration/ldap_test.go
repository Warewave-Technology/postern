//go:build integration

package integration

// S5.3'ün kanıtı: gruplar LDAP dizininden okunuyor.
//
//	go test -tags integration -run TestLDAP -v ./test/integration/

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

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
