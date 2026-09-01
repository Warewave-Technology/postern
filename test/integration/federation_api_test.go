//go:build integration

package integration

// S5.4: kimlik federasyonunun yönetim yüzeyi.
//
//	go test -tags integration -run TestFederationAPI -v ./test/integration/

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/warewave/postern/internal/secret"
	"net/http"
	"net/http/cookiejar"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFederationAPIMappings(t *testing.T) {
	_, apiURL, _, db := oobBastionFresh(t)
	ctx := context.Background()

	// Giriş yapabilmek için eşleme + admin gerekiyor.
	if _, err := db.CreateRole(ctx, "ops"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddGroupMapping(ctx, "sysadmins", "ops", "bootstrap"); err != nil {
		t.Fatal(err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)

	// JIT ile oluşan kullanıcıyı admin yap (bayrak yalnızca host tarafından
	// değişir — testte store üzerinden, üretimde CLI'dan).
	if err := db.SetUserAdmin(ctx, kcUser, true); err != nil {
		t.Fatal(err)
	}
	// ⚠️ Bağlanmamış bir YÖNETİCİ hesabını ilk girişin
	// sahiplenmesi artık açık izin istiyor: yalnızca adla
	// devralma ölçülmüş bir saldırıydı (bkz. göç 020).
	if err := db.AllowIdentityBind(ctx, kcUser, time.Now()); err != nil {
		t.Fatal(err)
	}

	// Yeni eşleme ekle.
	if status, body := adminReq(t, client, "POST", apiURL+"/api/admin/mappings",
		`{"group":"developers","role":"ops"}`); status != 200 {
		t.Fatalf("eşleme ekleme = %d: %s", status, body)
	}
	// Aynısı ikinci kez: 409.
	if status, _ := adminReq(t, client, "POST", apiURL+"/api/admin/mappings",
		`{"group":"developers","role":"ops"}`); status != 409 {
		t.Errorf("çakışan eşleme = %d, beklenen 409", status)
	}
	// Olmayan rol: 404.
	if status, _ := adminReq(t, client, "POST", apiURL+"/api/admin/mappings",
		`{"group":"x","role":"yok-boyle-rol"}`); status != 404 {
		t.Errorf("bilinmeyen rol = %d, beklenen 404", status)
	}

	status, body := adminReq(t, client, "GET", apiURL+"/api/admin/mappings", "")
	if status != 200 || !strings.Contains(body, "developers") {
		t.Fatalf("eşleme listesi: %d %s", status, body)
	}

	// Eşlenmemiş gruplar: giriş sırasında "hr" görülmüş olmalı.
	status, body = adminReq(t, client, "GET", apiURL+"/api/admin/unmapped-groups", "")
	if status != 200 || !strings.Contains(body, "hr") {
		t.Fatalf("eşlenmemiş gruplar: %d %s", status, body)
	}

	// Silme.
	if status, body := adminReq(t, client, "DELETE",
		apiURL+"/api/admin/mappings/developers/ops", ""); status != 200 {
		t.Fatalf("eşleme silme = %d: %s", status, body)
	}

	// Defterde iz olmalı.
	status, body = adminReq(t, client, "GET", apiURL+"/api/admin/log", "")
	if status != 200 {
		t.Fatal(body)
	}
	for _, want := range []string{"mapping.create", "mapping.delete"} {
		if !strings.Contains(body, want) {
			t.Errorf("defterde %q izi yok", want)
		}
	}
}

func TestFederationAPISettings(t *testing.T) {
	_, apiURL, _, db := oobBastionFresh(t)
	ctx := context.Background()

	if _, err := db.CreateRole(ctx, "ops"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddGroupMapping(ctx, "sysadmins", "ops", "bootstrap"); err != nil {
		t.Fatal(err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)
	if err := db.SetUserAdmin(ctx, kcUser, true); err != nil {
		t.Fatal(err)
	}
	// ⚠️ Bağlanmamış bir YÖNETİCİ hesabını ilk girişin
	// sahiplenmesi artık açık izin istiyor: yalnızca adla
	// devralma ölçülmüş bir saldırıydı (bkz. göç 020).
	if err := db.AllowIdentityBind(ctx, kcUser, time.Now()); err != nil {
		t.Fatal(err)
	}

	// Şifresiz ayar yazılabilmeli.
	status, body := adminReq(t, client, "PUT", apiURL+"/api/admin/settings",
		`{"key":"ldap.url","value":"ldaps://ldap.example:636"}`)
	if status != 200 {
		t.Fatalf("ayar yazma = %d: %s", status, body)
	}

	// Tanınmayan anahtar reddedilmeli: tablo çöplüğe dönmesin.
	if status, _ := adminReq(t, client, "PUT", apiURL+"/api/admin/settings",
		`{"key":"uydurma.ayar","value":"x"}`); status != 400 {
		t.Errorf("tanınmayan anahtar = %d, beklenen 400", status)
	}

	// Sır yazma: anahtar yapılandırılmadığı için REDDEDİLMELİ — düz metin
	// yazılıp "şifreledim" sanılmamalı.
	status, body = adminReq(t, client, "PUT", apiURL+"/api/admin/settings",
		`{"key":"ldap.bind_password","value":"gizli"}`)
	if status != 400 || !strings.Contains(body, "secret init") {
		t.Fatalf("anahtarsız sır yazma = %d: %s — ne yapılacağını söylemeli", status, body)
	}

	// Liste: şifresiz değer görünür.
	status, body = adminReq(t, client, "GET", apiURL+"/api/admin/settings", "")
	if status != 200 || !strings.Contains(body, "ldaps://ldap.example:636") {
		t.Fatalf("ayar listesi: %d %s", status, body)
	}
	// Parola hiç yazılmadığı için listede de olmamalı.
	if strings.Contains(body, "gizli") {
		t.Fatal("reddedilen sır yine de saklanmış")
	}

	// LDAP testi: yapılandırma eksik (user_base yok) → hata bildirmeli
	// ama istek başarılı olmalı (teşhis aracı).
	status, body = adminReq(t, client, "POST", apiURL+"/api/admin/ldap/test", `{}`)
	if status != 200 && status != 400 {
		t.Fatalf("ldap test = %d: %s", status, body)
	}

	// Defterde ayar değişikliği izi.
	status, body = adminReq(t, client, "GET", apiURL+"/api/admin/log", "")
	if status != 200 || !strings.Contains(body, "setting.set") {
		t.Errorf("defterde setting.set izi yok: %s", body)
	}
}

// Federasyon uçları da admin zincirinde: admin olmayan göremez.
func TestFederationAPIForbidsNonAdmins(t *testing.T) {
	_, apiURL, _, db := oobBastionFresh(t)
	ctx := context.Background()

	if _, err := db.CreateRole(ctx, "ops"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddGroupMapping(ctx, "sysadmins", "ops", "bootstrap"); err != nil {
		t.Fatal(err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL) // admin DEĞİL

	for _, path := range []string{"/api/admin/mappings", "/api/admin/settings", "/api/admin/unmapped-groups"} {
		if status, _ := adminReq(t, client, "GET", apiURL+path, ""); status != http.StatusForbidden {
			t.Errorf("%s = %d, beklenen 403", path, status)
		}
	}
	if status, _ := adminReq(t, client, "PUT", apiURL+"/api/admin/settings",
		`{"key":"ldap.url","value":"x"}`); status != http.StatusForbidden {
		t.Error("admin olmayan ayar yazabildi")
	}
}

var _ = json.Marshal

// ⚠️ LDAP ADRESİ DEĞİŞİRSE SAKLANAN BIND PAROLASI DÜŞMELİ.
//
// Kapatılan sızıntı: panel admini ldap.url'i kendi kontrolündeki bir
// sunucuya çeviriyor, "test bağlantısı"na basıyor ve postern o sunucuya
// SAKLANAN parolayla bağlanıyordu — parolayı düz metin olarak saldırgana
// vererek. Parolanın mühürlenmesinin ve panelde maskelenmesinin tüm
// amacı ("admin bile okuyamaz") bu yolla boşa çıkıyordu.
func TestChangingLDAPURLDropsTheStoredBindPassword(t *testing.T) {
	_, apiURL, _, db := oobBastion(t, 0)

	if err := db.SetUserAdmin(context.Background(), "yigit", true); err != nil {
		t.Fatal(err)
	}
	// ⚠️ Bağlanmamış bir YÖNETİCİ hesabını ilk girişin
	// sahiplenmesi artık açık izin istiyor: yalnızca adla
	// devralma ölçülmüş bir saldırıydı (bkz. göç 020).
	if err := db.AllowIdentityBind(context.Background(), "yigit", time.Now()); err != nil {
		t.Fatal(err)
	}

	// Sır saklamak için mühür anahtarı gerekiyor: üretimde
	// `postern secret init` kuruyor, testte burada.
	box, err := secret.Init(filepath.Join(t.TempDir(), "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	db.UseSecretBox(box)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)

	set := func(key, value string) {
		t.Helper()
		body := fmt.Sprintf(`{"key":%q,"value":%q}`, key, value)
		if status, out := adminReq(t, client, "PUT", apiURL+"/api/admin/settings", body); status != 200 {
			t.Fatalf("%s yazılamadı: %d %s", key, status, out)
		}
	}

	set("ldap.url", "ldaps://dc.sirket.local")
	set("ldap.bind_password", "COK-GIZLI-PAROLA")

	// Parola gerçekten saklandı mı?
	if v, err := db.Setting(context.Background(), "ldap.bind_password"); err != nil || v == "" {
		t.Fatalf("parola saklanmadı: %q %v", v, err)
	}

	// SALDIRI: adresi saldırganın sunucusuna çevir.
	set("ldap.url", "ldaps://saldirgan.example.com")

	if _, err := db.Setting(context.Background(), "ldap.bind_password"); err == nil {
		t.Error("ADRES DEĞİŞTİ AMA PAROLA DURUYOR — " +
			"bir sonraki 'test' onu saldırganın sunucusuna gönderir")
	}

	// Aynı adresi yeniden yazmak parolayı DÜŞÜRMEMELİ: gereksiz yere
	// yeniden girmek zorunda bırakmak operatörü yorar.
	set("ldap.bind_password", "YENI-PAROLA")
	set("ldap.url", "ldaps://saldirgan.example.com")
	if _, err := db.Setting(context.Background(), "ldap.bind_password"); err != nil {
		t.Error("aynı adres yeniden yazılınca parola gereksiz yere düştü")
	}
}

/*
 * verify ucu ADAY yapılandırmayı sınıyor ve saklanan parolayı yalnızca
 * SAKLANAN ADRESE gönderiyor.
 *
 * Kapatılan sızıntı adminSetSetting'dekiyle aynı sınıftan: aday URL'i
 * saldırganın sunucusuna çevirip parolayı boş bırakmak, postern'in
 * SAKLANAN parolayla oraya bağlanmasını sağlardı. Yeni bir uç, eski bir
 * korumayı sessizce boşa çıkarabilir — bu test onu bekliyor.
 */
func TestVerifyLDAPWontSendStoredPasswordElsewhere(t *testing.T) {
	_, apiURL, _, db := oobBastion(t, 0)

	if err := db.SetUserAdmin(context.Background(), "yigit", true); err != nil {
		t.Fatal(err)
	}
	// ⚠️ Bağlanmamış bir YÖNETİCİ hesabını ilk girişin
	// sahiplenmesi artık açık izin istiyor: yalnızca adla
	// devralma ölçülmüş bir saldırıydı (bkz. göç 020).
	if err := db.AllowIdentityBind(context.Background(), "yigit", time.Now()); err != nil {
		t.Fatal(err)
	}
	box, err := secret.Init(filepath.Join(t.TempDir(), "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	db.UseSecretBox(box)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)

	set := func(key, value string) {
		t.Helper()
		body := fmt.Sprintf(`{"key":%q,"value":%q}`, key, value)
		if status, out := adminReq(t, client, "PUT", apiURL+"/api/admin/settings", body); status != 200 {
			t.Fatalf("%s yazılamadı: %d %s", key, status, out)
		}
	}
	set("ldap.url", "ldaps://dc.sirket.local")
	set("ldap.bind_password", "COK-GIZLI-PAROLA")

	verify := func(url string) (int, string) {
		t.Helper()
		body := fmt.Sprintf(`{"url":%q,"bind_dn":"cn=postern","bind_password":"",`+
			`"user_base":"ou=people","user_filter":"(uid=%%s)",`+
			`"group_base":"ou=groups","group_attribute":"memberOf"}`, url)
		return adminReq(t, client, "POST", apiURL+"/api/admin/ldap/verify", body)
	}

	// SALDIRI: başka bir adres, parola boş.
	status, out := verify("ldaps://saldirgan.example.com")
	if status != 400 {
		t.Errorf("BAŞKA ADRESE SAKLANAN PAROLAYLA GİDİLDİ: %d %s", status, out)
	}
	if !strings.Contains(out, "bind password") {
		t.Errorf("red sebebi anlatmıyor: %s", out)
	}

	// Saklanan adres için parolasız sınama KABUL edilmeli — aksi hâlde
	// operatör her denemede parolayı yeniden yazmak zorunda kalırdı.
	// Bağlantı kurulamayacağı için ok:false döner; önemli olan 400
	// DÖNMEMESİ, yani isteğin reddedilmemesi.
	status, out = verify("ldaps://dc.sirket.local")
	if status != 200 {
		t.Errorf("saklanan adres için parolasız sınama reddedildi: %d %s", status, out)
	}
	if strings.Contains(out, "COK-GIZLI-PAROLA") {
		t.Error("PAROLA CEVAPTA GERİ DÖNDÜ")
	}
}

/*
 * ⚠️ DOĞRULAMA, KAYDEDİLDİKTEN SONRA ÇALIŞACAK KAPSAMLA KOŞMALI.
 *
 * ÖLÇÜLEN ARIZA: adminVerifyLDAP ldap.Config'i kurarken GroupScope'u
 * hiç göndermiyordu, yani doğrulama HER ZAMAN varsayılan kapsamla
 * (direct) koşuyordu. `subtree` kayıtlı bir kurulumda ekran "bu
 * değerler çalışıyor" derken, gerçekten çalışacak olandan BAŞKA bir
 * kapsam altında kanıt topluyordu — grupları taban DN'in bir OU altında
 * duran kurum yeşil bir doğrulama görüp kaydediyor ve rolleri sessizce
 * kaybediyordu.
 *
 * ⚠️ Kapsam DOĞRULAMASI üzerinden ölçüyoruz: ldap.New, subtree ile
 * group_name_from="dn" olmasını ŞART koşuyor. Kapsam taşınıyorsa o
 * kural tetiklenir; taşınmıyorsa istek varsayılan kapsamla kurulur ve
 * kural hiç görünmez. Yani hata mesajının kendisi, kapsamın gerçekten
 * gittiğinin kanıtı.
 */
func TestVerifyUsesTheStoredGroupScope(t *testing.T) {
	_, apiURL, _, db := oobBastionFresh(t)
	ctx := context.Background()

	seedRole(t, db)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)
	if err := db.SetUserAdmin(ctx, kcUser, true); err != nil {
		t.Fatal(err)
	}

	// Kayıtlı kapsam: subtree.
	if err := db.SetSetting(ctx, "ldap.group_scope", "subtree", false, "test"); err != nil {
		t.Fatal(err)
	}

	// group_name_from "cn" — subtree ile UYUMSUZ. Kapsam taşınıyorsa
	// ldap.New bunu reddediyor.
	body := `{"url":"ldaps://dc.sirket.local","bind_dn":"cn=postern",` +
		`"bind_password":"x","user_base":"ou=people","user_filter":"(uid=%s)",` +
		`"group_base":"ou=groups","group_filter":"(member=%s)","group_name_from":"cn"}`
	status, out := adminReq(t, client, "POST", apiURL+"/api/admin/ldap/verify", body)

	if !strings.Contains(strings.ToLower(out), "subtree") {
		t.Fatalf("doğrulama kayıtlı kapsamı kullanmadı (%d): %s\n"+
			"— ekran 'bu değerler çalışıyor' derken başka bir kapsam altında "+
			"kanıt topluyor demektir", status, out)
	}
}
