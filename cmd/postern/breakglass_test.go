package main

import (
	"context"
	"strings"
	"testing"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/store"
)

/*
 * ACİL DURUM KAPISI.
 *
 * ⚠️ BURADAKİ HER TEST, PANELE KİMSENİN GİREMEDİĞİ GÜN KOŞULACAK BİR
 * KOMUTU ÖLÇÜYOR. Ürünün "her şey bozulduğunda içeri girilir" iddiası
 * bu üç komuda dayanıyor ve üçü de test edilmemişti — yani iddia
 * ölçülmemişti.
 */

// secretFrom, komutun bir kez bastığı sırrı çıkarır.
func secretFrom(t *testing.T, out string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "sign-in secret:") {
			continue
		}
		parts := strings.Fields(line)
		return parts[len(parts)-1]
	}
	t.Fatalf("çıktıda sır yok:\n%s", out)
	return ""
}

/*
 * ⚠️ BOOTSTRAP: İLK YÖNETİCİ VE SIRRI BİR KEZ.
 *
 * Bu, boş bir kurulumda panele girmenin TEK yolu. Sırrın bir kez
 * basılması ve saklanmaması ürünün iddiası; sakladığı şey doğrulayıcı
 * ve geri okunamıyor.
 */
func TestBootstrapCreatesAnAdminAndPrintsTheSecretOnce(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	out, err := e.run(t, newAdminCmd(), "bootstrap")
	if err != nil {
		t.Fatalf("bootstrap: %v\n%s", err, out)
	}
	secret := secretFrom(t, out)

	u, err := e.db.User(ctx, "admin")
	if err != nil {
		t.Fatalf("yönetici oluşmamış: %v", err)
	}
	if !u.Admin {
		t.Fatal("oluşan hesap yönetici değil — boş kurulumda panele kimse giremez")
	}

	// ⚠️ SAKLANAN ŞEY DOĞRULAYICI: sır geri okunamıyor ama doğrulanıyor.
	cred, err := e.db.LocalCredential(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cred.Verifier, secret) {
		t.Fatal("SIR VERİTABANINDA DÜZ METİN")
	}
	if !auth.VerifyLocalSecret(cred.Verifier, secret) {
		t.Fatal("basılan sır doğrulanmıyor — operatör elindeki değerle giremez")
	}
	/*
	 * ⚠️ YÖNETİCİ SIRRI 'cli' KAYNAKLI ve parola DEĞİL.
	 * Göç 026 bunu şart koşuyor: acil durum kapısı tahmin edilebilir
	 * bir değere bağlanamaz.
	 */
	if cred.Chosen || cred.MustChange {
		t.Fatalf("yönetici kimlik bilgisi parolaya dönebilir hâlde: %+v", cred)
	}

	// İkinci bootstrap AYNI hesabı ezmemeli: elindeki sırla çalışan
	// operatörü sessizce dışarıda bırakırdı.
	out2, err2 := e.run(t, newAdminCmd(), "bootstrap")
	if err2 == nil {
		t.Fatalf("ikinci bootstrap kabul edildi:\n%s", out2)
	}
}

/*
 * ⚠️ REVOKE + ISSUE: SIRRINI KAYBEDEN YÖNETİCİNİN TEK YOLU.
 *
 * `issue` üstüne YAZMIYOR (bkz. store.AddLocalCredential) — o yüzden
 * kurtarma iki adım ve komut bunu söylemek zorunda. Söylemezse operatör
 * "issue çalışmıyor" diye bakar.
 */
func TestRevokeThenIssueRecoversAnAdmin(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	if _, err := e.run(t, newAdminCmd(), "bootstrap"); err != nil {
		t.Fatal(err)
	}

	// Üstüne yazma REDDEDİLİYOR ve sebebi ile çıkış yolu yazıyor.
	out, err := e.run(t, newAdminCmd(), "issue", "--name", "admin")
	if err == nil {
		t.Fatal("var olan sır sessizce değiştirildi")
	}
	if !strings.Contains(err.Error(), "revoke") {
		t.Errorf("hata çıkış yolunu söylemiyor: %v", err)
	}
	_ = out

	if _, err := e.run(t, newAdminCmd(), "revoke", "--name", "admin"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	out, err = e.run(t, newAdminCmd(), "issue", "--name", "admin")
	if err != nil {
		t.Fatalf("issue: %v\n%s", err, out)
	}
	fresh := secretFrom(t, out)

	cred, err := e.db.LocalCredential(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !auth.VerifyLocalSecret(cred.Verifier, fresh) {
		t.Fatal("yeni sır doğrulanmıyor")
	}
	// ⚠️ HESAP VE DENETİM İZİ DURUYOR: revoke yalnızca giriş yolunu
	// kaldırıyor, kimliği değil.
	if u, uerr := e.db.User(ctx, "admin"); uerr != nil || !u.Admin {
		t.Fatalf("revoke hesabı da götürmüş: %v", uerr)
	}
}

/*
 * ⚠️ SIRADAN HESABA VERİLEN DEĞER GEÇİCİ VE KOMUT BUNU SÖYLÜYOR.
 *
 * Söylemezse operatör değeri kalıcı sanıp bir kasaya koyar; kişi ilk
 * girişte değiştirince o kayıt sessizce ölür.
 */
func TestIssueToANonAdminSaysTheValueIsTemporary(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	if _, err := e.db.CreateUser(ctx, "ayse", "a@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}
	out, err := e.run(t, newAdminCmd(), "issue", "--name", "ayse")
	if err != nil {
		t.Fatalf("issue: %v\n%s", err, out)
	}
	if !strings.Contains(strings.ToUpper(out), "TEMPORARY") {
		t.Errorf("çıktı değerin geçici olduğunu söylemiyor:\n%s", out)
	}

	cred, err := e.db.LocalCredential(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if !cred.MustChange {
		t.Fatal("sıradan hesaba verilen değer 'değiştir' istemiyor — " +
			"veren kişi onu bilmeye devam ediyor")
	}
}

/*
 * ⚠️ CLI KAYNAK DEĞİŞİKLİĞİNİ REDDETMİYOR, UYARIYOR — VE BU DOĞRU.
 *
 * Panel bu geçişi reddedebiliyor; CLI edemez, çünkü acil çıkışı
 * kilitlemek onu acil çıkış olmaktan çıkarır. Geriye kalan tek doğru
 * davranış, kapıyı kapatan bir değişikliği SESSİZ yapmamak.
 *
 * Bu testi önce "reddetmeli" diye yazdım ve düştü: davranışı ölçmeden
 * varsaymıştım. Ölçülen davranış daha iyi ve gerekçesi kodda yazılı.
 */
func TestSettingsSetWarnsWhenLocalWouldCloseThePanel(t *testing.T) {
	e := newEnv(t)

	out, err := e.run(t, newSettingsCmd(), "set", "--key", "auth.source", "--value", "local")
	if err != nil {
		t.Fatalf("kaynak değişikliği reddedildi — acil çıkış kilitlenmiş: %v", err)
	}
	if !strings.Contains(out, "admin issue") {
		t.Fatalf("yerel yönetici yokken uyarı yok; operatör 'yerele döndüm' "+
			"deyip panele giremediğinde sebebi hiçbir yerde yazmıyor:\n%s", out)
	}

	// Yerel yönetici VARKEN uyarı susmalı: her seferinde uyaran bir
	// metin, gerçekten uyarması gereken günde de görülmez.
	if _, berr := e.run(t, newAdminCmd(), "bootstrap"); berr != nil {
		t.Fatal(berr)
	}
	out2, err2 := e.run(t, newSettingsCmd(), "set",
		"--key", "auth.source", "--value", "local")
	if err2 != nil {
		t.Fatal(err2)
	}
	if strings.Contains(out2, "admin issue") {
		t.Errorf("yerel yönetici varken de uyarıyor:\n%s", out2)
	}
}

/*
 * ⚠️ UYARI, SİLİNMİŞ BİR YÖNETİCİYE ALDANMAMALI.
 *
 * Kontrol yalnızca "yerel kimlik bilgisi olan bir yönetici var mı" diye
 * bakıyordu, ama locallogin.go silinmiş hesabı REDDEDİYOR. Silinmiş bir
 * yönetici uyarıyı susturup paneli kimsenin giremediği bir hâlde
 * bırakabiliyordu — panelde aynı kontrol bu yüzden düzeltilmişti,
 * burası bayat kalmıştı.
 */
func TestLocalWarningIgnoresADeletedAdmin(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	if _, err := e.run(t, newAdminCmd(), "bootstrap"); err != nil {
		t.Fatal(err)
	}
	if err := e.db.SetAccountState(ctx, "admin", store.StateDeleted); err != nil {
		t.Fatal(err)
	}

	out, err := e.run(t, newSettingsCmd(), "set", "--key", "auth.source", "--value", "local")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "admin issue") {
		t.Fatalf("silinmiş yönetici uyarıyı susturdu — o hesap giriş "+
			"yapamıyor, yani panel kimsenin giremediği hâlde kalıyor:\n%s", out)
	}
}

/*
 * ⚠️ PAROLA TABANI CLI'DAN DA DELİNEMİYOR.
 *
 * API tarafında bu kontrol "sessizce başka bir şey yapmayı" kapatmak
 * için eklenmişti; CLI'da yoktu. Aynı ayarı host'tan yazan operatör
 * "on iki" yazıp politikanın 12'de kaldığını fark etmeyebiliyordu.
 */
func TestSettingsSetValidatesThePasswordFloor(t *testing.T) {
	e := newEnv(t)

	for _, bad := range []string{"on iki", "4", "0", "-3"} {
		if _, err := e.run(t, newSettingsCmd(), "set",
			"--key", auth.KeyPasswordMinLength, "--value", bad); err == nil {
			t.Errorf("min_length=%q kabul edildi — politika kapatılabilir", bad)
		}
	}
	if _, err := e.run(t, newSettingsCmd(), "set",
		"--key", auth.KeyPasswordMinLength, "--value", "16"); err != nil {
		t.Fatalf("geçerli değer reddedildi: %v", err)
	}
}

/*
 * ⚠️ HESAP DURUMUNU HOST'TAN GERİ ALMAK.
 *
 * Yaşam döngüsü işi bir hesabı 'deleted' işaretleyebiliyor ve giriş onu
 * canlandırmıyor (göç 023). Panelin açılmadığı gün bunu geri alacak tek
 * yol bu komut; olmadığında "buradan çıkış yok" bir hâl vardı.
 */
func TestUserStateBringsADeletedAccountBack(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	if _, err := e.db.CreateUser(ctx, "ayse", "a@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.run(t, newUserCmd(), "state", "--name", "ayse", "--set", "deleted"); err != nil {
		t.Fatal(err)
	}
	if st, _, err := e.db.AccountState(ctx, "ayse"); err != nil || st != store.StateDeleted {
		t.Fatalf("durum = %q %v", st, err)
	}

	out, err := e.run(t, newUserCmd(), "state", "--name", "ayse", "--set", "active")
	if err != nil {
		t.Fatalf("geri açılamadı: %v", err)
	}
	if st, _, serr := e.db.AccountState(ctx, "ayse"); serr != nil || st != store.StateActive {
		t.Fatalf("durum = %q %v", st, serr)
	}
	// ⚠️ Komut bunun KALICI bir çözüm olmadığını söylemeli: kaynak hâlâ
	// doğrulamıyorsa iş yeniden kapatır.
	if !strings.Contains(out, "reprieve") {
		t.Errorf("çıktı geçici olabileceğini söylemiyor:\n%s", out)
	}
}

/*
 * ⚠️ BOOTSTRAP'IN KENDİ TAVSİYESİ YÜRÜMÜYORDU.
 *
 * Başarıyla açılan bir yönetici hesabı şunu basıyordu: "If you lose it,
 * run `postern admin revoke` and bootstrap a new account." O yol bir
 * çıkmaz sokak — revoke hesabı BIRAKIYOR, bootstrap var olan hesabı
 * reddediyor. Üstelik bu tavsiyeyi yalnızca ZATEN kilitlenmiş bir
 * operatör okuyor: sırrını kaybetmiş, panele giremiyor, ve elindeki tek
 * kâğıt onu yürümeyen bir komuta gönderiyor.
 *
 * Aynı dosyanın bootstrap hatası bu çıkmazı zaten anlatıyordu; basılan
 * tavsiye onunla çelişiyordu.
 *
 * Test tavsiyeyi OKUYUP KOŞUYOR: çıktıdan komutları çıkarmıyor ama
 * anlattığı iki adımı gerçekten yürüyor ve sonunda çalışan bir sırla
 * çıkıyor.
 */
func TestBootstrapAdviceForALostSecretActuallyWorks(t *testing.T) {
	e := newEnv(t)

	out, err := e.run(t, newAdminCmd(), "bootstrap")
	if err != nil {
		t.Fatalf("bootstrap: %v\n%s", err, out)
	}

	// Tavsiye, çıkmaz sokağa göndermemeli.
	if strings.Contains(out, "bootstrap a new account") {
		t.Errorf("bootstrap hâlâ 'revoke edip yeniden bootstrap et' diyor — "+
			"bootstrap var olan hesabı reddediyor, yani kilitlenmiş "+
			"operatör iki komut arasında sıkışıyor; çıktı:\n%s", out)
	}
	for _, want := range []string{"admin revoke --name", "admin issue --name"} {
		if !strings.Contains(out, want) {
			t.Errorf("tavsiye %q içermiyor; çıktı:\n%s", want, out)
		}
	}

	// ⚠️ VE TAVSİYE GERÇEKTEN YÜRÜYOR. Önce sırasız hâli: issue tek
	// başına reddediyor — belgelerin eskiden söylediği şey buydu.
	if _, ierr := e.run(t, newAdminCmd(), "issue", "--name", "admin"); ierr == nil {
		t.Error("var olan sırrın üzerine issue sessizce yazdı — " +
			"sır bu yoldan da sessizce değişmemeli")
	}

	if rout, rerr := e.run(t, newAdminCmd(), "revoke", "--name", "admin"); rerr != nil {
		t.Fatalf("tavsiyenin ilk adımı düştü: %v\n%s", rerr, rout)
	}
	iout, ierr := e.run(t, newAdminCmd(), "issue", "--name", "admin")
	if ierr != nil {
		t.Fatalf("tavsiyenin ikinci adımı düştü: %v\n%s", ierr, iout)
	}
	if !strings.Contains(iout, "sign-in secret") {
		t.Errorf("issue taze bir sır basmadı; çıktı:\n%s", iout)
	}
}
