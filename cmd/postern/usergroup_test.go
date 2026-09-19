package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/v2/internal/model"
	"github.com/Warewave-Technology/postern/v2/internal/store"
)

// seedUserAndGroup, testler için bir kullanıcı, bir grup ve bir hedef kurar.
func seedUserAndGroup(t *testing.T, e *testEnv) {
	t.Helper()
	ctx := context.Background()
	if _, err := e.db.CreateUser(ctx, "yigit", "", "yigit"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.CreateGroup(ctx, "ops"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.CreateTarget(ctx, model.Target{
		Name: "web01", Host: "10.0.0.1", Port: 22, HostKey: testTargetKey,
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.db.GrantTarget(ctx, "ops", "web01"); err != nil {
		t.Fatal(err)
	}
}

/*
 * ⚠️ ASIL KANITI: grup VERİLDİ demek yetmez, KULLANICI HEDEFE ERİŞMELİ.
 *
 * S4'ün derdi "user_groups'a satır düştü mü" değil, panelin çalışmadığı
 * gün birine erişim verilebiliyor mu. Satırı kontrol eden bir test,
 * atamayı yanlış group bağlayan bir uygulamayı da geçirirdi.
 */
func TestGrantGroupGivesTheUserTheTarget(t *testing.T) {
	e := newEnv(t)
	seedUserAndGroup(t, e)
	ctx := context.Background()

	// ⚠️ ÖNCE ERİŞEMEDİĞİNİ GÖSTER: bu satır olmadan test, kullanıcının
	// zaten erişimi olması yüzünden de geçerdi.
	before, err := e.db.User(ctx, "yigit")
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Groups) != 0 {
		t.Fatalf("başlangıçta grup var: %+v — test kendi konusunu ölçemez", before.Groups)
	}

	out, err := e.run(t, newUserCmd(), "grant-group", "--name", "yigit", "--group", "ops")
	if err != nil {
		t.Fatalf("grant-group: %v (%s)", err, out)
	}
	if !strings.Contains(out, `group "ops" granted`) {
		t.Errorf("çıktı: %q", out)
	}

	after, err := e.db.User(ctx, "yigit")
	if err != nil {
		t.Fatal(err)
	}
	var reaches bool
	for _, r := range after.Groups {
		for _, tgt := range r.Targets {
			if tgt == "web01" {
				reaches = true
			}
		}
	}
	if !reaches {
		t.Fatalf("kullanıcı hedefe erişemiyor: %+v — grup verildi ama işe yaramadı", after.Groups)
	}

	// ⚠️ DENETİM SATIRI PANELLE AYNI ADI TAŞIMALI. CLI bir zamanlar
	// "user.role_assign" yazıyordu; action=user.grant_role diye süzen
	// bir denetçi, break-glass yoluyla verilmiş HER grubu kaçırırdı.
	entries, err := e.db.AdminLog(ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	var logged bool
	for _, en := range entries {
		if en.Action == "user.grant_role" && en.Entity == "yigit" {
			logged = true
			if en.Via != "cli" {
				t.Errorf("via = %q, cli bekleniyordu", en.Via)
			}
			if en.Actor == "" {
				t.Error("denetim satırı aktörsüz")
			}
		}
	}
	if !logged {
		t.Error("user.grant_role denetim satırı yok")
	}
}

/*
 * ⚠️ VERİLMEMİŞ ROLÜ "ALDIM" DİYE RAPORLAMAK YASAK.
 *
 * store.RevokeGroup bağ yokken sessiz no-op. Var olan ama hiç verilmemiş
 * bir grup adını yazan operatör (ops yerine ops-admin) "revoked" okuyup
 * erişimi kestiğini sanardı.
 */
func TestRevokeGroupSaysWhenThereWasNothingToRevoke(t *testing.T) {
	e := newEnv(t)
	seedUserAndGroup(t, e)

	out, err := e.run(t, newUserCmd(), "revoke-group", "--name", "yigit", "--group", "ops")
	if err != nil {
		t.Fatalf("revoke-group: %v (%s)", err, out)
	}
	if !strings.Contains(out, "held no active grant") {
		t.Errorf("verilmemiş grup için yanlış cümle: %q", out)
	}
	if strings.Contains(out, `group "ops" revoked`) {
		t.Error("verilmemiş grup 'revoked' diye raporlandı")
	}
}

/*
 * ⚠️ GERÇEK BİR İPTAL, ERİŞİMİ GERÇEKTEN KALDIRMALI — ve komut dizinden
 * gelen grupların geri döneceğini SÖYLEMELİ.
 *
 * RevokeGroup kaynak süzmüyor ama SyncGroups her SSO girişinde IdP'nin
 * listesini yeniden yazıyor. Uyarı olmadan komut "erişimi kestim" diye
 * okunur ve bu, panelin çalışmadığı gün en yanlış anlaşılacak cümle.
 */
func TestRevokeGroupRemovesAccessAndWarnsAboutDirectoryGroups(t *testing.T) {
	e := newEnv(t)
	seedUserAndGroup(t, e)
	ctx := context.Background()

	if err := e.db.AssignGroup(ctx, "yigit", "ops", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if u, _ := e.db.User(ctx, "yigit"); len(u.Groups) != 1 {
		t.Fatal("hazırlık başarısız: grup atanmadı")
	}

	out, err := e.run(t, newUserCmd(), "revoke-group", "--name", "yigit", "--group", "ops")
	if err != nil {
		t.Fatalf("revoke-group: %v (%s)", err, out)
	}
	if !strings.Contains(out, `group "ops" revoked`) {
		t.Errorf("çıktı: %q", out)
	}
	if !strings.Contains(out, "next sign-in") {
		t.Errorf("dizin uyarısı yok: %q", out)
	}

	after, err := e.db.User(ctx, "yigit")
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Groups) != 0 {
		t.Errorf("iptalden sonra grup duruyor: %+v", after.Groups)
	}
}

/*
 * ⚠️ SİLİNMİŞ HESAP: REDDETME, SÖYLE.
 *
 * Bu CLI acil çıkış yolu ve ilk kuralı kimseyi kilitlememek — "önce
 * grupları geri ver, sonra hesabı aç" meşru bir sıra. Ama grubun şu an
 * hiçbir şey vermediğini de söylemek zorunda: sessizce başarılı görünen
 * bir komut, operatöre erişim verdiğini düşündürürdü.
 */
func TestGrantGroupWarnsOnADeletedAccountButStillGrants(t *testing.T) {
	e := newEnv(t)
	seedUserAndGroup(t, e)
	ctx := context.Background()

	if err := e.db.SetAccountState(ctx, "yigit", store.StateDeleted); err != nil {
		t.Fatal(err)
	}

	out, err := e.run(t, newUserCmd(), "grant-group", "--name", "yigit", "--group", "ops")
	if err != nil {
		t.Fatalf("acil çıkış yolu engelledi: %v (%s)", err, out)
	}
	if !strings.Contains(out, "cannot sign in") {
		t.Errorf("hesabın giremediği söylenmiyor: %q", out)
	}
	if !strings.Contains(out, "--set active") {
		t.Errorf("çıkış yolu gösterilmiyor: %q", out)
	}

	// Atama GERÇEKTEN yazılmış olmalı: hesap geri açıldığında grup orada
	// olsun diye bu sıraya izin veriyoruz.
	src, found, serr := e.db.GroupGrantSource(ctx, "yigit", "ops")
	if serr != nil {
		t.Fatal(serr)
	}
	if !found || src != "manual" {
		t.Errorf("atama yazılmamış: found=%v source=%q", found, src)
	}
}

/*
 * ⚠️ EN CİDDİ TUZAK: DİZİNDEN GELEN ROLÜ ELLE VERMEK ONU KALICI YAPAR.
 *
 * AssignGroup'un ON CONFLICT dalı source'u 'manual' yapıyor, SyncGroups
 * ise yalnızca 'sso' satırlarını siliyor. Yani kişi gruptan
 * çıkarıldığında grup üzerinde KALIR ve hiçbir otomatik yol geri alamaz.
 * Komut bunu söylemezse sessizce kalıcı yetki üretmiş olur.
 */
func TestGrantGroupSaysWhenItDetachesAnSSOGroupFromSync(t *testing.T) {
	e := newEnv(t)
	seedUserAndGroup(t, e)
	ctx := context.Background()

	// Dizinin verdiği hâli kur.
	if err := e.db.SyncGroups(ctx, "yigit", []string{"ops"}); err != nil {
		t.Fatal(err)
	}
	if src, _, _ := e.db.GroupGrantSource(ctx, "yigit", "ops"); src != "sso" {
		t.Fatalf("hazırlık başarısız: source=%q, sso bekleniyordu", src)
	}

	out, err := e.run(t, newUserCmd(), "grant-group", "--name", "yigit", "--group", "ops")
	if err != nil {
		t.Fatalf("grant-group: %v (%s)", err, out)
	}
	if !strings.Contains(out, "directory synchronisation will no longer take it away") {
		t.Errorf("kalıcılaşma uyarısı yok: %q", out)
	}

	// Ve gerçekten kalıcılaşmış olmalı — uyarı doğruyu söylüyor.
	src, _, serr := e.db.GroupGrantSource(ctx, "yigit", "ops")
	if serr != nil {
		t.Fatal(serr)
	}
	if src != "manual" {
		t.Errorf("source = %q, manual bekleniyordu", src)
	}
}

/*
 * ⚠️ KOMUT KÖKTEN ULAŞILABİLİR OLMALI.
 *
 * Diğer testler alt komutu doğrudan kuruyor ve AddCommand satırı
 * unutulsa bile geçerlerdi — bu depodaki tekrar eden arıza sınıfı tam
 * olarak bu: "yazıldı, test edildi, çağrılmıyor". Bu test kabuktan
 * yazılan komutun gerçekten var olduğunu ölçüyor.
 */
func TestGroupCommandsAreReachableFromTheRoot(t *testing.T) {
	e := newEnv(t)
	seedUserAndGroup(t, e)

	if out, err := e.run(t, newRootCmd(), "user", "grant-group",
		"--name", "yigit", "--group", "ops"); err != nil {
		t.Fatalf("user grant-group kökten çalışmıyor: %v (%s)", err, out)
	}
	if out, err := e.run(t, newRootCmd(), "user", "revoke-group",
		"--name", "yigit", "--group", "ops"); err != nil {
		t.Fatalf("user revoke-group kökten çalışmıyor: %v (%s)", err, out)
	}
	if out, err := e.run(t, newRootCmd(), "group", "list"); err != nil {
		t.Fatalf("group list kökten çalışmıyor: %v (%s)", err, out)
	}
	if out, err := e.run(t, newRootCmd(), "group", "revoke-target",
		"--name", "ops", "--target", "web01"); err != nil {
		t.Fatalf("group revoke-target kökten çalışmıyor: %v (%s)", err, out)
	}
}

/*
 * ⚠️ ROLDEN HEDEF ALMAK, O ROLÜ TAŞIYAN HERKESİ ETKİLER.
 *
 * store.RevokeTarget yazılmıştı ve CLI'dan çağıranı yoktu: panelin
 * çalışmadığı gün yanlışlıkla bağlanmış bir makine geri alınamıyordu.
 */
func TestRevokeTargetRemovesTheMachineFromTheGroup(t *testing.T) {
	e := newEnv(t)
	seedUserAndGroup(t, e)
	ctx := context.Background()

	if err := e.db.AssignGroup(ctx, "yigit", "ops", time.Time{}); err != nil {
		t.Fatal(err)
	}
	before, _ := e.db.User(ctx, "yigit")
	if len(before.Groups) != 1 || len(before.Groups[0].Targets) != 1 {
		t.Fatalf("hazırlık başarısız: %+v", before.Groups)
	}

	out, err := e.run(t, newGroupCmd(), "revoke-target", "--name", "ops", "--target", "web01")
	if err != nil {
		t.Fatalf("revoke-target: %v (%s)", err, out)
	}
	if !strings.Contains(out, `target "web01" revoked`) {
		t.Errorf("çıktı: %q", out)
	}

	after, _ := e.db.User(ctx, "yigit")
	for _, r := range after.Groups {
		if len(r.Targets) != 0 {
			t.Errorf("hedef hâlâ erişilebilir: %+v", r.Targets)
		}
	}

	// İkinci kez: "zaten bağlı değildi" demeli, "aldım" değil.
	out2, err := e.run(t, newGroupCmd(), "revoke-target", "--name", "ops", "--target", "web01")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out2, "did not reach") {
		t.Errorf("ikinci çağrı yanlış cümle: %q", out2)
	}
}

// Yanlış grup adı, hangi adın yanlış olduğunu söylemeli — ve iç hata
// zinciri operatöre gitmemeli.
func TestGrantGroupNamesTheWrongName(t *testing.T) {
	e := newEnv(t)
	seedUserAndGroup(t, e)

	_, err := e.run(t, newUserCmd(), "grant-group", "--name", "yigit", "--group", "yokboyle")
	if err == nil {
		t.Fatal("olmayan grup kabul edildi")
	}
	if !strings.Contains(err.Error(), `no group "yokboyle"`) {
		t.Errorf("hata grubu adıyla anmıyor: %v", err)
	}
	if strings.Contains(err.Error(), "sql:") || strings.Contains(err.Error(), "store.") {
		t.Errorf("iç hata zinciri operatöre sızdı: %v", err)
	}
}

func TestGrantGroupRejectsAnUnknownUser(t *testing.T) {
	e := newEnv(t)
	seedUserAndGroup(t, e)

	_, err := e.run(t, newUserCmd(), "grant-group", "--name", "yokkimse", "--group", "ops")
	if err == nil {
		t.Fatal("olmayan kullanıcı kabul edildi")
	}
	if !strings.Contains(err.Error(), `no user "yokkimse"`) {
		t.Errorf("hata kullanıcıyı adıyla anmıyor: %v", err)
	}
}

// testTargetKey, hedefin host anahtarı — CreateTarget boş kabul etmiyor.
const testTargetKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIcLUQM0UcoZdJVh2EokribDvFZyyNyAVURM/LrCugFM"

/*
 * ⚠️ YANLIŞ YAZILAN AD, DOĞRU OLANI DEĞİL KENDİSİNİ GÖSTERMELİ.
 *
 * ÖLÇÜLEN ARIZA: revoke-group kullanıcıyı döngü içinde okuyordu ve
 * olmayan bir KULLANICI adı `no group "developer"` diye raporlanıyordu.
 * Operatör, doğru yazdığı grup adını düzeltmeye gönderiliyordu — panelin
 * çalışmadığı gün en son isteyeceğin ipucu.
 */
func TestRevokeGroupNamesTheUserWhenTheUserIsWrong(t *testing.T) {
	e := newEnv(t)
	seedUserAndGroup(t, e)

	_, err := e.run(t, newUserCmd(), "revoke-group", "--name", "yokkimse", "--group", "ops")
	if err == nil {
		t.Fatal("olmayan kullanıcı kabul edildi")
	}
	if !strings.Contains(err.Error(), `no user "yokkimse"`) {
		t.Errorf("hata kullanıcıyı adıyla anmıyor: %v", err)
	}
	if strings.Contains(err.Error(), "no group") {
		t.Errorf("yanlış adı gösteriyor — operatör doğru olanı düzeltmeye gider: %v", err)
	}
}

// Rol adı yanlışsa da grubu göstermeli (kullanıcı doğruyken).
func TestRevokeGroupNamesTheGroupWhenTheGroupIsWrong(t *testing.T) {
	e := newEnv(t)
	seedUserAndGroup(t, e)

	_, err := e.run(t, newUserCmd(), "revoke-group", "--name", "yigit", "--group", "yokboyle")
	if err == nil {
		t.Fatal("olmayan grup kabul edildi")
	}
	if !strings.Contains(err.Error(), `no group "yokboyle"`) {
		t.Errorf("hata grubu adıyla anmıyor: %v", err)
	}
}
