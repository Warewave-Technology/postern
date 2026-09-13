package httpapi

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

/*
 * ⚠️ VERİLEN PAROLA EKRANDA BOŞ ÇİZİLİYORDU — ve iki taraf da yeşildi.
 *
 * ÖLÇÜLEN ARIZA: 0c9bce2 sunucunun cevabındaki anahtarı "secret"tan
 * "password"a çevirdi; panelin IssuedCredential tipi "secret" okumaya
 * devam etti. Go testleri cevabın anahtarını hiç ölçmüyordu, panel
 * testleri ise sunucuyu kendi yazdıkları sahte cevapla ("secret")
 * taklit ediyordu — yani ikisi de kendi hâlini doğruluyor, sözleşmeyi
 * kimse doğrulamıyordu. Sonuç: yönetici "Reset sign-in"e basıyor, kutu
 * "bu değer bir daha gösterilmez" diyor ve değer yok.
 *
 * Bu test sözleşmeyi ölçüyor: sunucunun DÖNDÜĞÜ her anahtar, panelin
 * api.ts'te OKUDUĞU tipin bir alanı olmak zorunda; ve parola gerçekten
 * dolu. Anahtar bir daha adlandırılırsa iki taraftan biri değil, bu
 * test düşer.
 */
func TestIssuedCredentialKeysAreWhatThePanelReads(t *testing.T) {
	s, _ := dbServer(t)

	r := httptest.NewRequest(http.MethodPost, "/api/admin/users",
		strings.NewReader(`{"name":"suheda","os_user":"suheda"}`))
	w := httptest.NewRecorder()
	s.adminCreateUser(w, asAdmin(r))
	created := decode(t, w)
	mustMatchPanelType(t, "CreateUserResult", created)
	if p, _ := created["password"].(string); p == "" {
		t.Fatalf("hesap açılışı parola döndürmedi: %v", created)
	}

	r = httptest.NewRequest(http.MethodPost, "/api/admin/users/suheda/credential", nil)
	r.SetPathValue("name", "suheda")
	w = httptest.NewRecorder()
	s.adminIssueCredential(w, asAdmin(r))
	issued := decode(t, w)
	mustMatchPanelType(t, "IssuedCredential", issued)
	if p, _ := issued["password"].(string); p == "" {
		t.Fatalf("sıfırlama parola döndürmedi: %v", issued)
	}
	if issued["replaced"] != true {
		t.Errorf("ikinci verme 'replaced' demiyor: %v", issued)
	}
}

// mustMatchPanelType, cevabın her anahtarının api.ts'teki tipin bir
// alanı olduğunu doğrular.
func mustMatchPanelType(t *testing.T, typeName string, body map[string]any) {
	t.Helper()
	fields := panelFields(t, typeName)
	for k := range body {
		// "ok", ok(w)'nin genel başarı işareti; panel onu tipe koymuyor.
		if k == "ok" {
			continue
		}
		if !fields[k] {
			t.Errorf("sunucu %q anahtarını dönüyor ama panelin %s tipinde öyle bir alan yok "+
				"(web/src/api.ts): panel bu değeri hiç okumuyor", k, typeName)
		}
	}
}

// panelFields, api.ts'teki `export type <Ad> = { ... };` bloğunun alan
// adlarını okur. Dosya okunamıyorsa test DÜŞER: sözleşmeyi ölçemeyen
// bir test yeşil kalmamalı.
func panelFields(t *testing.T, typeName string) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "api.ts"))
	if err != nil {
		t.Fatalf("api.ts okunamadı: %v", err)
	}
	src := string(raw)
	head := "export type " + typeName + " = {"
	start := strings.Index(src, head)
	if start < 0 {
		t.Fatalf("api.ts'te %q yok", head)
	}
	end := strings.Index(src[start:], "\n};")
	if end < 0 {
		t.Fatalf("api.ts'te %s bloğu kapanmıyor", typeName)
	}
	block := src[start : start+end]
	fields := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s+(\w+)\??:`).FindAllStringSubmatch(block, -1) {
		fields[m[1]] = true
	}
	if len(fields) == 0 {
		t.Fatalf("%s bloğunda alan bulunamadı:\n%s", typeName, block)
	}
	return fields
}
