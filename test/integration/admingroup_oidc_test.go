//go:build integration

package integration

// Dizini OLMAYAN bir kurulumda yönetici grubunu ayarlayabilmek.
//
//	go test -tags integration -run TestAdminGroupWithoutDirectory -v ./test/integration/

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/auth"
)

// adminGroupSet, ucu çağırır ve cevabı döner.
func adminGroupSet(t *testing.T, client *http.Client, apiURL, group string,
	confirm []string) (int, map[string]any) {
	t.Helper()
	if confirm == nil {
		confirm = []string{}
	}
	body, _ := json.Marshal(map[string]any{"group": group, "confirm": confirm})
	req, err := http.NewRequest("POST", apiURL+"/api/admin/ldap/admin-group",
		bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

/*
 * ⚠️ DİZİNİ OLMAYAN KURULUM DA YÖNETİCİ GRUBUNU AYARLAYABİLMELİ.
 *
 * ÖLÇÜLEN ÇIKMAZ: uç, önizleme yapamadığı için "ldap is not configured"
 * ile reddediyordu. Ama OIDC girişinde yöneticilik YALNIZCA grup
 * iddiasından geliyor (weblogin.go) ve kaynağı OIDC'ye çevirmek grubun
 * ayarlı olmasını ŞART koşuyor (canSwitchTo). Yani dizini olmayan bir
 * kurulum OIDC'ye hiçbir zaman geçemiyordu — ayarı yapmanın tek yolu,
 * ihtiyacı olmayan bir dizin kurmaktı.
 */
func TestAdminGroupWithoutDirectory(t *testing.T) {
	_, apiURL, _, db := oobBastionFresh(t)
	ctx := context.Background()

	seedRole(t, db)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)
	// ⚠️ CLI yöneticisi: refuseIfLastAdmin'in koruduğu şey tam olarak
	// bunun VARLIĞI ve onsuz kaydetme reddedilmeli.
	if err := db.SetUserAdmin(ctx, kcUser, true); err != nil {
		t.Fatal(err)
	}

	// Dizin YOK.
	if _, err := db.Setting(ctx, "ldap.url"); err == nil {
		t.Skip("bu düzenekte dizin yapılandırılmış; test dizinsiz kurulumu ölçüyor")
	}

	code, out := adminGroupSet(t, client, apiURL, "platform-admins", nil)
	if code != http.StatusOK {
		t.Fatalf("dizinsiz kurulumda yönetici grubu ayarlanamadı (%d): %v", code, out)
	}
	if out["deferred"] != true {
		t.Fatal("cevap 'deferred' demiyor — panel 'şu kişiler yönetici oldu' " +
			"gibi bir cümle kurar ve bu yalan olur")
	}

	stored, err := db.Setting(ctx, auth.KeyAdminGroup)
	if err != nil {
		t.Fatalf("ayar yazılmamış: %v", err)
	}
	if stored != "platform-admins" {
		t.Fatalf("ayar = %q", stored)
	}

	// ⚠️ ASIL KAZANIM: kaynak seçimindeki GRUP engeli kalkmış olmalı.
	// (OIDC ayrıca sağlayıcının ayarlı olmasını da istiyor; burada
	// ölçtüğümüz şey grubun artık engel OLMAMASI.)
	resp, err := client.Get(apiURL + "/api/admin/auth/source")
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Options []struct {
			Source   string `json:"source"`
			Eligible bool   `json:"eligible"`
			Why      string `json:"why"`
		} `json:"options"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&st)
	resp.Body.Close()
	for _, o := range st.Options {
		if o.Source == "oidc" && strings.Contains(o.Why, "administrator group") {
			t.Fatalf("grup ayarlandı ama engel hâlâ grup: %s", o.Why)
		}
	}
}

/*
 * ⚠️ ÖNİZLENEMEYEN GRUP, MEVCUT GRUP YÖNETİCİLERİNİ DÜŞÜRMEMELİ.
 *
 * Bilinmeyen bir küme, BOŞ bir küme değil. ApplyAdminGroup boş kümeyle
 * çağrılsaydı "bu grupta kimse yok" demiş olurduk ve grup üzerinden
 * yönetici olan herkes o anda yetkisini kaybederdi — üstelik operatör
 * yalnızca bir grup ADI yazdığını sanarken.
 */
func TestUnpreviewableGroupDoesNotDemoteAnyoneNow(t *testing.T) {
	_, apiURL, _, db := oobBastionFresh(t)
	ctx := context.Background()

	seedRole(t, db)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	browserSignIn(t, client, apiURL)
	if err := db.SetUserAdmin(ctx, kcUser, true); err != nil {
		t.Fatal(err)
	}

	// Grup üzerinden yönetici olmuş bir hesap.
	if _, err := db.CreateUser(ctx, "ayse", "ayse@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.ApplyAdminGroup(ctx, []string{"ayse"}); err != nil {
		t.Fatal(err)
	}
	before, err := db.User(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if !before.Admin {
		t.Fatal("düzenek kurulamadı: ayse grup yöneticisi değil")
	}

	if code, out := adminGroupSet(t, client, apiURL, "baska-grup", nil); code != http.StatusOK {
		t.Fatalf("kaydetme %d: %v", code, out)
	}

	after, err := db.User(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if !after.Admin {
		t.Fatal("önizlenemeyen bir grup kaydedilince mevcut grup yöneticisi " +
			"O ANDA düşürüldü — bilinmeyen küme boş küme sayılmış")
	}
}
