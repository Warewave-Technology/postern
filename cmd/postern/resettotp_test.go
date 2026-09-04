package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warewave-Technology/postern/internal/secret"
)

/*
 * `postern admin reset-totp`, telefonunu kaybeden kişinin yolu.
 *
 * ⚠️ ASIL SINANAN ŞEY, KOMUTUN VAR OLMASI DEĞİL, TABAN DURUMU OLMASI.
 * Panelde de bir sıfırlama var ve çoğu gün doğru kapı o. Ama TOTP giriş
 * faktörü olunca panel yolunun özyinelemesi bitmiyor: yöneticiyi kim
 * sıfırlayacak? Bu komut o soruya host'tan cevap veriyor.
 */
func TestAdminResetTOTPRemovesTheAuthenticator(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	if _, err := e.db.CreateUser(ctx, "yigit", "", "yigit"); err != nil {
		t.Fatal(err)
	}

	// Kaydı açmak için kutu şart (göç 033) — ama SİLMEK için değil, ve
	// testin harness'ı CLI'a anahtar VERMİYOR. Aşağısı tam olarak bunu
	// doğruluyor: anahtarı olmayan bir host'tan da sıfırlanabilmeli.
	box, err := secret.Init(filepath.Join(t.TempDir(), "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	e.db.UseSecretBox(box)
	if err := e.db.BeginTOTP(ctx, "yigit", "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}
	if err := e.db.ConfirmTOTP(ctx, "yigit", 1); err != nil {
		t.Fatal(err)
	}

	out, err := e.run(t, newAdminCmd(), "reset-totp", "--name", "yigit")
	if err != nil {
		t.Fatalf("reset-totp: %v\n%s", err, out)
	}

	if _, err := e.db.TOTP(ctx, "yigit"); err == nil {
		t.Fatal("ikinci faktör hâlâ duruyor")
	}

	// ⚠️ KOMUTUN ASIL KATTIĞI ŞEY YETKİ DEĞİL, İZ. Host'a erişen zaten
	// psql ile satırı silebilirdi; o silme deftere hiçbir şey yazmıyor.
	// Bir ikinci faktörün ortadan kalkması izsiz olmamalı.
	row := hasAction(ledger(t, e), "admin.totp_reset")
	if row == nil {
		t.Fatal("denetim defterinde admin.totp_reset yok")
	}
	if row.Via != "cli" {
		t.Errorf("via = %q, \"cli\" bekleniyordu", row.Via)
	}
	if row.Entity != "yigit" {
		t.Errorf("entity = %q, \"yigit\" bekleniyordu", row.Entity)
	}

	// Hesabın kendisi durmalı: sıfırlanan faktör, silinen hesap değil.
	if _, err := e.db.User(ctx, "yigit"); err != nil {
		t.Errorf("hesap da gitmiş: %v", err)
	}
}

func TestAdminResetTOTPSaysWhenThereIsNothingToRemove(t *testing.T) {
	e := newEnv(t)
	if _, err := e.db.CreateUser(context.Background(), "yigit", "", "yigit"); err != nil {
		t.Fatal(err)
	}

	out, err := e.run(t, newAdminCmd(), "reset-totp", "--name", "yigit")
	if err == nil {
		t.Fatalf("ikinci faktörü olmayan hesapta başarı döndü: %s", out)
	}
	/*
	 * ⚠️ HAM "not found" YETMİYOR. İki farklı sebebi var — hesap yok, ya
	 * da hesap var ama faktörü yok — ve operatör ilkini gördüğünde adı
	 * yanlış yazdığını sanıp aramaya koyulur. Mesaj ayrımı söylemeli.
	 */
	if !strings.Contains(err.Error(), "no authenticator") {
		t.Errorf("mesaj sebebi söylemiyor: %v", err)
	}
	if !strings.Contains(err.Error(), "postern admin list") {
		t.Errorf("mesaj diğer ihtimali kontrol etmenin yolunu vermiyor: %v", err)
	}
}

func TestAdminResetTOTPNeedsAName(t *testing.T) {
	e := newEnv(t)
	if _, err := e.run(t, newAdminCmd(), "reset-totp"); err == nil {
		t.Fatal("--name olmadan geçti; hangi hesabın sıfırlandığı belirsiz kalırdı")
	}
}
