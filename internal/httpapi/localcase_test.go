package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Warewave-Technology/postern/internal/auth"
)

/*
 * ⚠️ ACİL ÇIKIŞ KAPISI, ADIN HARF YAZIMINA TAKILMAMALI.
 *
 * Yerel parola kapısı, kullanıcı adını LocalCredential'a ham geçiriyordu
 * ve sorgu harf duyarlıydı. "Ayse" hesabına ait doğru sır, "ayse" diye
 * yazılınca reddediliyor (401) ve denetim satırı "unknown account"a
 * yazılıyordu — yani doğru sırla yapılan giriş, hiç var olmayan bir
 * hesaba yapılmış bir deneme gibi kayda geçiyordu. Acil çıkış kapısında
 * bu, en kötü anda kilitlenmek demek.
 *
 * LocalCredential artık ciEq kullanıyor (kullanıcı adı 019'dan beri harf
 * duyarsız benzersiz). Test uçtan uca: harf farkıyla doğru sır GİRMELİ
 * ve denetim doğru hesabı yazMALI.
 */
func TestLocalDoorAcceptsCaseVariantWithCorrectSecret(t *testing.T) {
	ctx := context.Background()
	db := migratedStore(t)

	if _, err := db.CreateUser(ctx, "Ayse", "ayse@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}
	secret, verifier, err := auth.NewLocalSecret()
	if err != nil {
		t.Fatal(err)
	}
	// created_by 'cli': acil çıkış sırrı gibi.
	if _, err := db.ReplaceLocalCredential(ctx, "Ayse", verifier, "cli"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting(ctx, auth.KeyLoginSource, "local", false, "test"); err != nil {
		t.Fatal(err)
	}

	s := New(auth.NewOIDCHolder(), auth.NewLogins(auth.NewOIDCHolder()), db,
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Kullanıcı adı KÜÇÜK harfle, sır DOĞRU.
	body := `{"username":"ayse","secret":"` + secret + `"}`
	r := httptest.NewRequest(http.MethodPost, "/auth/local", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.RemoteAddr = "10.0.0.2:5555"
	w := httptest.NewRecorder()

	s.handleLocalLogin(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("harf farkıyla doğru sır reddedildi: %d %s — acil çıkış "+
			"kapısı adın yazımına takılıyor", w.Code, w.Body.String())
	}

	// Denetim, DOĞRU hesabı yazmalı — "unknown account" değil.
	rows, err := db.AdminLog(ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	var loggedIn bool
	for _, e := range rows {
		if e.Action == "auth.local_login" && e.Entity == "Ayse" {
			loggedIn = true
		}
		if e.Action == "auth.local_denied" {
			t.Errorf("doğru sırla giriş 'denied' olarak kaydedildi: entity=%q", e.Entity)
		}
	}
	if !loggedIn {
		t.Errorf("başarılı giriş doğru hesap adıyla kaydedilmedi; defter: %+v", rows)
	}
}
