package main

import (
	"strings"
	"testing"

	"github.com/Warewave-Technology/postern/internal/store"
)

func boundUser(t *testing.T, e *testEnv, name, subject string) {
	t.Helper()
	ctx := t.Context()
	if _, err := e.db.CreateUser(ctx, name, "", name); err != nil {
		t.Fatal(err)
	}
	if err := e.db.BindDirIdentity(ctx, name, subject); err != nil {
		t.Fatal(err)
	}
}

/*
 * ⚠️ KİLİTLENMİŞ HESABIN TEK ÇIKIŞI BUYDU.
 *
 * Dizinde silinip yeniden açılan kişi YENİ bir kararlı kimlik alıyor;
 * postern'deki satır hâlâ eskisine bağlı olduğu için web girişi 403,
 * SSH "dizinde yok" diyor, DeleteUser oturum kaydı yüzünden reddediyor
 * ve `user modify` bu alanı kabul etmiyordu. store.UnbindDirIdentity
 * bunu çözmek için yazılmıştı, testi vardı, hiçbir yerden
 * çağrılmıyordu — yani gerçekte tek çıkış veritabanına elle girmekti.
 */
func TestUnbindDirectoryDetachesTheAccount(t *testing.T) {
	e := newEnv(t)
	boundUser(t, e, "ayse", "aaaa-1")

	out, err := e.run(t, newRootCmd(),
		"user", "unbind-directory", "--name", "ayse", "--yes")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "detached") {
		t.Errorf("koparıldığı söylenmiyor:\n%s", out)
	}

	subject, err := e.db.DirSubjectOf(t.Context(), "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if subject != "" {
		t.Fatalf("bağ hâlâ duruyor: %q", subject)
	}

	// ⚠️ Koparmak, yeniden bağlanabilmek DEMEK. Asıl kurtarma bu:
	// aksi hâlde komut hesabı bir adım daha kilitlerdi.
	if err := e.db.BindDirIdentity(t.Context(), "ayse", "bbbb-2"); err != nil {
		t.Fatalf("yeni kimliğe bağlanamadı: %v", err)
	}
}

/*
 * ⚠️ BU KOMUT DEFTERE YAZMALI.
 *
 * Bir hesabı BAŞKA bir dizin kimliğine açan tek komut bu. İzsiz
 * çalışması, hesap devralmanın en sessiz yolunu bırakmak olurdu.
 */
func TestUnbindDirectoryIsRecorded(t *testing.T) {
	e := newEnv(t)
	boundUser(t, e, "ayse", "aaaa-1")

	if _, err := e.run(t, newRootCmd(),
		"user", "unbind-directory", "--name", "ayse", "--yes"); err != nil {
		t.Fatal(err)
	}

	entries, err := e.db.AdminLog(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	var found *store.AdminLogEntry
	for i := range entries {
		if entries[i].Action == "user.unbind_directory" {
			found = &entries[i]
			break
		}
	}
	if found == nil {
		t.Fatal("defterde satır yok: hesabı başka bir kimliğe açan komut izsiz çalıştı")
	}
	if found.Entity != "ayse" || !strings.Contains(found.Details, "aaaa-1") {
		t.Errorf("hangi kimlikten koparıldığı yazılmamış: %+v", *found)
	}
}

/*
 * ⚠️ BAĞI OLMAYAN HESAPTA "BAŞARDIM" DEMİYOR.
 *
 * Deseydi, operatör asıl sorunu başka yerde aramaya devam ederdi — ve
 * komut hiçbir şey yapmadan başarılı görünürdü.
 */
func TestUnbindDirectorySaysWhenThereIsNothingToDetach(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	if _, err := e.db.CreateUser(ctx, "yalniz", "", "yalniz"); err != nil {
		t.Fatal(err)
	}

	out, err := e.run(t, newRootCmd(),
		"user", "unbind-directory", "--name", "yalniz", "--yes")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "not bound") {
		t.Errorf("bağ olmadığı söylenmiyor:\n%s", out)
	}
	if strings.Contains(out, "detached") {
		t.Errorf("yapılmamış bir iş yapılmış gibi raporlandı:\n%s", out)
	}
}

/*
 * ⚠️ ONAY, "y" DEĞİL HESABIN ADI.
 *
 * Yanlış hesapta çalıştırıldığında zarar sessiz: yanlış kişinin bağı
 * kopar ve bir sonraki dizin girişi onun hesabını devralır. Refleksle
 * onaylanabilen bir soru, bu komut için yeterli değil.
 */
func TestUnbindDirectoryRefusesAWrongConfirmation(t *testing.T) {
	e := newEnv(t)
	boundUser(t, e, "ayse", "aaaa-1")

	cmd := newRootCmd()
	cmd.SetIn(strings.NewReader("y\n"))
	out, err := e.run(t, cmd, "user", "unbind-directory", "--name", "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "left untouched") {
		t.Errorf("yanlış onayla devam etti:\n%s", out)
	}

	subject, err := e.db.DirSubjectOf(t.Context(), "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if subject == "" {
		t.Fatal("ONAY YANLIŞTI AMA BAĞ KOPARILDI")
	}
}
