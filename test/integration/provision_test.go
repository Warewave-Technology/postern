//go:build integration

package integration

// S5.2'nin "Bitti" kanıtı: IdP'de grubu eşlenmiş bir kullanıcı, postern'de
// hiç kaydı olmadan giriş yapıyor ve kullanıcısı otomatik oluşuyor.
//
//	go test -tags integration -run TestProvision -v ./test/integration/

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/auth"
)

// JIT sağlamanın uçtan uca kanıtı: postern'de "yigit" diye bir kullanıcı
// YOKKEN, IdP'deki grubu sayesinde giriş yapıp erişim kazanıyor.
func TestProvisionCreatesUserFromMappedGroup(t *testing.T) {
	_, apiURL, _, db := oobBastionFresh(t)
	ctx := context.Background()

	// Rol ve hedef var, eşleme var — ama KULLANICI yok.
	if _, err := db.CreateRole(ctx, "ops"); err != nil {
		t.Fatal(err)
	}
	if err := db.GrantTarget(ctx, "ops", "web01"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddGroupMapping(ctx, "sysadmins", "ops", "test"); err != nil {
		t.Fatal(err)
	}

	if _, err := db.User(ctx, kcUser); err == nil {
		t.Fatal("test kullanıcısı önceden var — JIT kanıtı anlamsızlaşır")
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)

	me, status := fetchMe(t, client, apiURL)
	if status != http.StatusOK {
		t.Fatalf("/api/me = %d — JIT giriş başarısız", status)
	}
	if me.Name != kcUser {
		t.Errorf("Name = %q, beklenen %q", me.Name, kcUser)
	}
	// os_user = IdP kullanıcı adı: tasarımın çekirdek kararı.
	if me.OSUser != kcUser {
		t.Errorf("OSUser = %q, beklenen %q — os_user IdP kullanıcı adı olmalı", me.OSUser, kcUser)
	}
	if len(me.Targets) != 1 || me.Targets[0] != "web01" {
		t.Errorf("targets = %v, beklenen [web01] — grup eşlemesi rol vermemiş", me.Targets)
	}

	// Kullanıcı gerçekten oluşmuş ve SSO'ya bağlı doğmuş olmalı.
	u, err := db.User(ctx, kcUser)
	if err != nil {
		t.Fatalf("kullanıcı oluşmamış: %v", err)
	}
	if !u.SSOOnly {
		t.Error("JIT kullanıcı sso_only doğmamış — IdP'de kapatılınca anahtarla girebilir")
	}

	// Eşlenmemiş grup (hr) teşhis tablosuna düşmüş olmalı.
	unmapped, err := db.UnmappedGroups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var sawHR bool
	for _, g := range unmapped {
		if g.Name == "hr" {
			sawHR = true
		}
	}
	if !sawHR {
		t.Errorf("eşlenmemiş grup kaydedilmemiş: %+v", unmapped)
	}
}

// Hiçbir grubu eşlenmemiş kullanıcı giremez ve kaydı OLUŞMAZ.
func TestProvisionDeniesUnmappedUser(t *testing.T) {
	_, apiURL, _, db := oobBastionFresh(t)
	ctx := context.Background()

	// Eşleme YOK (rol var ama hiçbir gruba bağlanmamış).
	if _, err := db.CreateRole(ctx, "ops"); err != nil {
		t.Fatal(err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignInExpectingDenial(t, client, apiURL)

	if _, status := fetchMe(t, client, apiURL); status != http.StatusUnauthorized {
		t.Fatalf("/api/me = %d, beklenen 401 — eşleşmesiz kullanıcı oturum almış", status)
	}
	if _, err := db.User(ctx, kcUser); err == nil {
		t.Fatal("eşleşmesi olmayan kullanıcı yine de oluşturulmuş")
	}
}

// Gruptan çıkarılan kullanıcının rolleri bir sonraki girişte düşer.
func TestProvisionSyncsRolesOnEachLogin(t *testing.T) {
	_, apiURL, _, db := oobBastionFresh(t)
	ctx := context.Background()

	if _, err := db.CreateRole(ctx, "ops"); err != nil {
		t.Fatal(err)
	}
	if err := db.GrantTarget(ctx, "ops", "web01"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddGroupMapping(ctx, "sysadmins", "ops", "test"); err != nil {
		t.Fatal(err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)

	if me, _ := fetchMe(t, client, apiURL); len(me.Targets) != 1 {
		t.Fatalf("ilk girişte hedef yok: %+v", me)
	}

	// Yönetici eşlemeyi kaldırdı: IdP hâlâ grubu gönderiyor ama artık
	// karşılığı yok.
	if err := db.RemoveGroupMapping(ctx, "sysadmins", "ops"); err != nil {
		t.Fatal(err)
	}

	// Yeni oturum: roller yenilenmeli ve erişim düşmeli.
	jar2, _ := cookiejar.New(nil)
	client2 := &http.Client{Jar: jar2, Timeout: 30 * time.Second}
	browserSignIn(t, client2, apiURL)

	me, status := fetchMe(t, client2, apiURL)
	if status != http.StatusOK {
		t.Fatalf("/api/me = %d — var olan kullanıcı girememiş", status)
	}
	if len(me.Targets) != 0 {
		t.Errorf("targets = %v, beklenen boş — eşleme kalkınca erişim düşmeli", me.Targets)
	}

	// Kullanıcı SİLİNMEMİŞ olmalı: denetim kaydı ona bağlı.
	if _, err := db.User(ctx, kcUser); err != nil {
		t.Error("erişimi biten kullanıcı silinmiş — denetim izi sahipsiz kalır")
	}
}

/*
 * ⚠️ OTOMATİK AÇILIŞ KAPALIYKEN OIDC KAPISI DA KUYRUĞA YAZMALI.
 *
 * ÖLÇÜLEN ARIZA: auth.auto_create yalnızca dizin kapısında okunuyordu.
 * OIDC kurulumlarında sihirbaz "kuyruğa al" diyor, ayar yazılıyor ve
 * hiçbir şey olmuyordu — hesaplar yine kendiliğinden açılıyordu. Yani
 * ekran yalan söylüyordu ve kuyruk hiç dolmuyordu.
 */
func TestOIDCQueuesWhenAutoCreateIsOff(t *testing.T) {
	_, apiURL, _, db := oobBastionFresh(t)
	ctx := context.Background()

	if err := db.SetSetting(ctx, auth.KeyAutoCreate, "false", false, "test"); err != nil {
		t.Fatal(err)
	}
	// ⚠️ Eşleme VAR: reddin sebebi "grubu yok" değil, "otomatik açılış
	// kapalı" olsun. Aksi halde test kendi konusunu ölçmez.
	if _, err := db.CreateRole(ctx, "ops"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddGroupMapping(ctx, "sysadmins", "ops", "test"); err != nil {
		t.Fatal(err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignInExpectingDenial(t, client, apiURL)

	// Hesap AÇILMAMIŞ olmalı...
	if _, err := db.User(ctx, kcUser); err == nil {
		t.Fatal("otomatik açılış kapalıyken hesap yine de açıldı")
	}

	// ...ama kişi KAPIDA da kalmamalı: kuyrukta olmalı.
	pending, err := db.ListPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("kuyruk = %d satır, 1 bekleniyordu — kapı kapandı ama kimse "+
			"kuyruğa yazılmadı", len(pending))
	}
	if pending[0].Username != kcUser {
		t.Fatalf("kuyruktaki ad = %q", pending[0].Username)
	}
	// ⚠️ Kuyruk KARARLI KİMLİKLE anahtarlı: IdP'de adını değiştiren
	// kişi yeniden başvuramasın diye.
	if pending[0].Subject == "" {
		t.Fatal("kuyruk satırı kimliksiz — adını değiştiren yeniden başvurabilir")
	}
	if pending[0].Source != "oidc" {
		t.Fatalf("kaynak = %q, oidc bekleniyordu", pending[0].Source)
	}
}
