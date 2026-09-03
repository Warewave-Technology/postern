package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/store"
)

func seedLog(t *testing.T, e *testEnv, entries ...store.AdminLogEntry) {
	t.Helper()
	for _, en := range entries {
		if err := e.db.LogAdmin(context.Background(), en); err != nil {
			t.Fatal(err)
		}
		// Aynı saniyeye düşmesinler: sıralama id ile çözülüyor ama
		// testin okuması net olsun.
		time.Sleep(time.Millisecond)
	}
}

/*
 * ⚠️ KÖKTEN ÇAĞRILIYOR: komutun gerçekten kaydedildiğini de ölçüyor.
 * Alt komutu doğrudan kurmak, AddCommand satırı unutulsa bile geçerdi —
 * bu depodaki tekrar eden arıza sınıfı tam olarak o.
 *
 * ⚠️ DENETİMİN OKUMA YARISI HOST'TAN ÇALIŞMALI.
 *
 * admin_log'a hem panel hem CLI yazıyordu ama CLI'dan okunamıyordu —
 * yani panelin çalışmadığı gün yapılan değişikliklerin izi yine
 * panelden okunuyordu.
 */
func TestLogShowsWhoDidWhat(t *testing.T) {
	e := newEnv(t)
	seedLog(t, e,
		store.AdminLogEntry{Actor: "yigit", Via: "cli", Action: "user.grant_role",
			Entity: "suheda", Details: "role ops"},
		store.AdminLogEntry{Actor: "admin", Via: "web", Action: "session.terminate",
			Entity: "abc123", Details: "suheda on web01"},
	)

	out, err := e.run(t, newRootCmd(), "log")
	if err != nil {
		t.Fatalf("log: %v (%s)", err, out)
	}
	for _, must := range []string{"yigit", "cli", "user.grant_role", "suheda",
		"admin", "web", "session.terminate"} {
		if !strings.Contains(out, must) {
			t.Errorf("çıktı %q içermiyor:\n%s", must, out)
		}
	}
}

/*
 * ⚠️ SÜZGEÇ, LİMİTİN ARDINA BAKMALI.
 *
 * ÖLÇÜLEN TUZAK: süzme istemcide yapılıyor. Limiti olduğu gibi
 * kullansaydık, "--actor yigit --limit 5" SON 5 SATIRDAN yigit'e ait
 * olanları gösterirdi — yani çoğu zaman boş çıkar ve operatör "hiç
 * yapmamış" diye okurdu. Yanlış cevabın en sinsi biçimi.
 */
func TestLogFilterLooksPastTheLimit(t *testing.T) {
	e := newEnv(t)

	// Aradığımız satır EN ESKİ olsun.
	seedLog(t, e, store.AdminLogEntry{Actor: "yigit", Via: "cli",
		Action: "user.admin", Entity: "suheda", Details: "admin set to true"})

	// Üstüne başkasının 30 satırı.
	for range 30 {
		seedLog(t, e, store.AdminLogEntry{Actor: "baskasi", Via: "web",
			Action: "target.probe", Entity: "web01"})
	}

	out, err := e.run(t, newRootCmd(), "log", "--actor", "yigit", "--limit", "5")
	if err != nil {
		t.Fatalf("log: %v (%s)", err, out)
	}
	if !strings.Contains(out, "user.admin") {
		t.Errorf("limitin ardındaki satır bulunamadı — operatör 'hiç yapmamış' "+
			"diye okurdu:\n%s", out)
	}
}

// Eylem öneği aile getirmeli: operatörün aradığı çoğu zaman tek bir
// olay değil.
func TestLogActionFilterIsAPrefix(t *testing.T) {
	e := newEnv(t)
	seedLog(t, e,
		store.AdminLogEntry{Actor: "a", Via: "cli", Action: "user.grant_role", Entity: "x"},
		store.AdminLogEntry{Actor: "a", Via: "cli", Action: "user.revoke_role", Entity: "x"},
		store.AdminLogEntry{Actor: "a", Via: "cli", Action: "role.revoke", Entity: "y"},
	)

	out, err := e.run(t, newRootCmd(), "log", "--action", "user.")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "user.grant_role") || !strings.Contains(out, "user.revoke_role") {
		t.Errorf("aile getirilmedi:\n%s", out)
	}
	if strings.Contains(out, "role.revoke") {
		t.Errorf("önek dışı satır geldi:\n%s", out)
	}
}

/*
 * ⚠️ "DEFTER BOŞ" İLE "ARADIĞIN YOK" AYRI CÜMLELER.
 *
 * İkisini aynı boşlukla göstermek, hiç kayıt tutulmadığını sanmaya yol
 * açardı — bir denetim aracında en pahalı yanlış anlama.
 */
func TestLogDistinguishesEmptyFromNoMatch(t *testing.T) {
	e := newEnv(t)

	out, err := e.run(t, newRootCmd(), "log")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "audit trail is empty") {
		t.Errorf("boş defter için yanlış cümle: %q", out)
	}

	seedLog(t, e, store.AdminLogEntry{Actor: "a", Via: "cli", Action: "user.create", Entity: "x"})

	out2, err := e.run(t, newRootCmd(), "log", "--actor", "yokkimse")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out2, "no entries matched") {
		t.Errorf("eşleşmeyen süzgeç için yanlış cümle: %q", out2)
	}
	if strings.Contains(out2, "audit trail is empty") {
		t.Error("dolu defter boş gösterildi")
	}
	// ⚠️ Başlık, eşleşme yokken de basılmamalı: bir tablo başlığı
	// "burada veri var" demek.
	if strings.Contains(out2, "ACTOR") {
		t.Errorf("eşleşme yokken başlık basıldı:\n%s", out2)
	}
}

/*
 * ⚠️ KESİLDİYSE SÖYLE.
 *
 * Sessizce ilk N'i göstermek, operatörün "hepsi bu" sanması demek.
 */
func TestLogSaysWhenItTruncated(t *testing.T) {
	e := newEnv(t)
	for range 10 {
		seedLog(t, e, store.AdminLogEntry{Actor: "a", Via: "cli",
			Action: "user.create", Entity: "x"})
	}

	out, err := e.run(t, newRootCmd(), "log", "--limit", "3")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "older entries") {
		t.Errorf("kesildiği söylenmiyor:\n%s", out)
	}
}

/*
 * ⚠️ İKİNCİ KESİLME DE SÖYLENMELİ — VE BOŞLUK ORTADAKİ DURUMDA.
 *
 * Süzme istemcide, dolayısıyla komut --limit'in çok üstünde
 * (limit*50, en çok 5000) satır okuyor. Üç durum var:
 *
 *   matched == 0            → "no entries matched (searched the newest N)"
 *   matched == limit        → "(showing N; there are older entries)"
 *   0 < matched < limit     → HİÇBİR ŞEY
 *
 * Üçüncüsü tam da operatörün "demek ki bu kadarmış" diyeceği durum:
 * birkaç satır geldi, liste sınıra dayanmış görünmüyor, ve defter
 * aslında iç tavanda kesilmiş. İlk yazdığım test bunu ölçmüyordu —
 * mutasyon geçti ve yanlış yere baktığımı gösterdi.
 */
func TestLogSaysWhenItStoppedAtTheReadCap(t *testing.T) {
	e := newEnv(t)
	// --limit 2 → iç tavan 100. 120 satır yazıyoruz; yalnızca biri
	// süzgece uyuyor, yani matched=1 (0 < 1 < 2) ve okuma tavana
	// dayanıyor.
	// ⚠️ SIRA ÖNEMLİ: eşleşen satır EN YENİ olmalı ki okuma
	// penceresinin İÇİNDE kalsın. Dolgu önce yazılıyor.
	for range 120 {
		seedLog(t, e, store.AdminLogEntry{Actor: "baskasi", Via: "cli",
			Action: "user.create", Entity: "x"})
	}
	seedLog(t, e, store.AdminLogEntry{Actor: "yigit", Via: "cli",
		Action: "user.create", Entity: "son"})

	out, err := e.run(t, newRootCmd(), "log", "--actor", "yigit", "--limit", "2")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "yigit") {
		t.Fatalf("eşleşen satır hiç gelmedi:\n%s", out)
	}
	if !strings.Contains(out, "not examined") {
		t.Errorf("okuma tavanına dayandığı söylenmiyor:\n%s", out)
	}
}
