package main

// Listenin "hangi oturumu açayım" sorusuna verdiği cevap (göç 038).

import (
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/store"
)

// evidenceEnv, oturum kurabilen bir ortam hazırlar.
func evidenceEnv(t *testing.T) *testEnv {
	t.Helper()
	e := newEnv(t)
	ctx := t.Context()
	if _, err := e.db.CreateUser(ctx, "yigit", "", "yigit"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.CreateTarget(ctx, model.Target{
		Name: "web01", Host: "127.0.0.1", Port: 22,
		HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIcLUQM0UcoZdJVh2EokribDvFZyyNyAVURM/LrCugFM",
	}); err != nil {
		t.Fatal(err)
	}
	return e
}

// closed, kapanmış bir oturum kurup defter işaretini yazar.
func closed(t *testing.T, e *testEnv, id string, mark model.SFTPJournal) {
	t.Helper()
	ctx := t.Context()
	if err := e.db.StartSession(ctx, store.SessionStart{
		ID: id, Username: "yigit", TargetName: "web01", OSUser: "yigit",
		SrcIP: "10.0.0.1", StartedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.db.EndSession(ctx, id, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := e.db.MarkSFTPJournal(ctx, id, mark); err != nil {
		t.Fatal(err)
	}
}

/*
 * ⚠️ AYNI SORUYA İKİ YÜZEY AYNI CEVABI VERMELİ.
 *
 * Panelin denetim tablosu bu iki sayıyı çiziyor; bu komut ise paneli hiç
 * görmeyen denetçinin — bastion'a SSH ile giren kişinin — elindeki tek
 * liste. Yalnızca panelde olsaydı postern aynı soruya duruşa göre iki
 * farklı cevap veriyor olurdu, ve komut satırındaki denetçi ısrarla
 * reddedilmiş bir oturumu hiçbir şey olmamış bir oturumdan ayırt
 * edemezdi.
 */
func TestSessionListShowsWhichSessionsHaveSomethingToLookAt(t *testing.T) {
	e := evidenceEnv(t)

	closed(t, e, "sess-ret", model.SFTPJournal{
		Measured: true, Events: 4, Denied: 17, Counted: true,
	})
	closed(t, e, "sess-kayip", model.SFTPJournal{
		Measured: true, Events: 4, Lost: 2, Denied: 9, Counted: true,
	})

	out, err := e.run(t, newRootCmd(), "session", "list")
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(out, "17 refused") {
		t.Errorf("ret sayısı listede yok:\n%s", out)
	}
	/*
	 * ⚠️ HÜCREDE EN FAZLA BİR ŞEY. Kayıp daha ağır bulgu olduğu için
	 * önce o; ikisini yan yana basmak satırı okunur kılmak yerine
	 * kalabalıklaştırırdı.
	 */
	if !strings.Contains(out, "2 events lost") {
		t.Errorf("kayıp listede yok:\n%s", out)
	}
	if strings.Contains(out, "9 refused") {
		t.Errorf("kayıp varken ret de basıldı — hücre tek yönlü değil:\n%s", out)
	}
}

/*
 * ⚠️ İŞARETSİZ SATIRA ONAY VERİLMİYOR.
 *
 * Listeden hesaplanabilen tek şey iki sayı; defterin İÇERİĞİNİN kayıtla
 * tutup tutmadığını yalnızca `postern session verify` söyler. Boş bir
 * hücreye "ok" yazmak, koşulmamış bir kontrolü koşulmuş saymak olurdu —
 * ve bunu okuyan denetçi, en çok güvenmemesi gereken satıra güvenirdi.
 */
func TestSessionListDoesNotBlessAnUnflaggedSession(t *testing.T) {
	e := evidenceEnv(t)

	closed(t, e, "sess-temiz", model.SFTPJournal{
		Measured: true, Events: 4, Denied: 0, Counted: true,
	})

	out, err := e.run(t, newRootCmd(), "session", "list")
	if err != nil {
		t.Fatal(err)
	}

	for _, word := range []string{"ok", "clean", "verified", "0 refused"} {
		if strings.Contains(strings.ToLower(out), word) {
			t.Errorf("işaretsiz satıra %q yazıldı:\n%s", word, out)
		}
	}
}

/*
 * ⚠️ SAYILMAMIŞ RET, SIFIR DEĞİL — VE İKİSİ AYNI GÖRÜNMELİ AMA AYNI
 * SEBEPLE DEĞİL.
 *
 * Göç 038'den önce kapanmış oturumlarda sayım yapılmadı. İkisi de boş
 * hücre bırakıyor, ama "sayılmadı" durumunda hücrenin boş olması bir
 * BİLGİSİZLİK; "sayıldı ve sıfır"da ise bir cevap. Fark, sıfırın hiçbir
 * zaman rakam olarak basılmamasında duruyor: basılsaydı sayılmamış
 * oturumun boşluğu, sayılmış sıfırdan daha iyi bir haber gibi okunurdu.
 */
func TestSessionListDoesNotTurnAnUncountedSessionIntoZero(t *testing.T) {
	e := evidenceEnv(t)

	closed(t, e, "sess-sayilmadi", model.SFTPJournal{
		Measured: true, Events: 0, Counted: false,
	})

	out, err := e.run(t, newRootCmd(), "session", "list")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "refused") {
		t.Errorf("sayılmamış oturum için ret basıldı:\n%s", out)
	}
}

/*
 * ⚠️ "AÇIK" İLE "AKIYOR" AYNI ŞEY DEĞİL — ve bu komut ikincisini
 * BİLEMEZ.
 *
 * Bitişin boş olması yalnızca bitişin yazılmadığını söylüyor; postern
 * SIGKILL yerse o satır sonsuza dek boş kalıyor. Oturumun hâlâ akıp
 * akmadığını yalnızca çalışan sürecin kendi defteri biliyor ve bu komut
 * ayrı bir süreç — veritabanından okuyor. "running" yazmak, ölçemediği
 * bir sağlık iddiası olurdu.
 */
func TestSessionListDoesNotClaimAnOpenSessionIsStreaming(t *testing.T) {
	e := evidenceEnv(t)

	ctx := t.Context()
	if err := e.db.StartSession(ctx, store.SessionStart{
		ID: "sess-acik", Username: "yigit", TargetName: "web01", OSUser: "yigit",
		SrcIP: "10.0.0.1", StartedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	out, err := e.run(t, newRootCmd(), "session", "list")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "running") {
		t.Errorf("ölçülemeyen bir sağlık iddiası basıldı:\n%s", out)
	}
	if !strings.Contains(out, "open") {
		t.Errorf("açık oturum açık olduğunu söylemiyor:\n%s", out)
	}
}
