package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/record"
	"github.com/Warewave-Technology/postern/internal/store"
)

/*
 * kayitliOturum, gerçek bir .cast dosyası ve zinciriyle bir oturum satırı
 * kurar; dosyanın yolunu döner.
 *
 * Sahte bir zincir yazmıyoruz: baş, yazıcının kendi ürettiği. Uydurma bir
 * başla yapılan test, doğrulayıcının yazıcıyla aynı fikirde olduğunu
 * ölçmez — yalnızca kendi kendisiyle tutarlı olduğunu.
 */
func kayitliOturum(t *testing.T, e *testEnv, id string, zincirYaz bool) string {
	t.Helper()
	ctx := context.Background()

	if _, err := e.db.CreateUser(ctx, "yigit", "", "yigit"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.CreateTarget(ctx, model.Target{
		Name: "web-01", Host: "127.0.0.1", Port: 22, HostKey: testTargetKey,
	}); err != nil {
		t.Fatal(err)
	}

	rs, err := record.NewStore(filepath.Join(e.dir, "rec"))
	if err != nil {
		t.Fatal(err)
	}
	f, path, err := rs.Create(id)
	if err != nil {
		t.Fatal(err)
	}

	w, err := record.NewWriter(f, 80, 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Output([]byte("uname -a\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	if err := e.db.StartSession(ctx, store.SessionStart{
		ID: id, Username: "yigit", TargetName: "web-01", OSUser: "yigit",
		SrcIP: "127.0.0.1", StartedAt: time.Now(), RecordingPath: path,
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.db.EndSession(ctx, id, time.Now()); err != nil {
		t.Fatal(err)
	}

	if zincirYaz {
		head, links := w.Chain()
		if head == "" {
			t.Fatal("yazıcı boş baş döndü")
		}
		if err := e.db.SetRecordingChain(ctx, id, head, links); err != nil {
			t.Fatal(err)
		}
	}

	// rs.Create zaten mutlak yol dönüyor; tekrar birleştirmek rec dizinini
	// iki kez yazardı.
	return path
}

func TestSessionVerifyPassesForAnUntouchedRecording(t *testing.T) {
	e := newEnv(t)
	kayitliOturum(t, e, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true)

	out, err := e.run(t, newSessionCmd(), "verify", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("dokunulmamış kayıt doğrulanamadı: %v\n%s", err, out)
	}
	if !strings.HasPrefix(out, "OK") {
		t.Errorf("çıktı OK ile başlamıyor: %s", out)
	}

	/*
	 * ⚠️ ÇIKTI, KANITLAMADIĞI ŞEYİ DE SÖYLEMELİ. "OK" satırını görüp
	 * bunun kaydı her türlü değişikliğe karşı koruduğunu sanmak, bu
	 * özelliğin verebileceği en kötü izlenim.
	 */
	if !strings.Contains(out, "does not prove more than that") {
		t.Error("çıktı sınırını söylemiyor; okuyan olmayan bir güvence çıkarır")
	}
	if !strings.Contains(out, "root") {
		t.Error("çıktı, host'ta root olanın ikisini birden yazabileceğini söylemiyor")
	}
}

/*
 * ⚠️ ASIL ÖLÇÜM. Tek bayt değişmiş bir kayıt hem BAŞARISIZ olmalı hem de
 * sıfırdan farklı çıkış kodu vermeli — bu komut betikten çağrılacak ve
 * "değişmiş" hâli 0 dönerse kimse fark etmez.
 */
func TestSessionVerifyFailsForATamperedRecording(t *testing.T) {
	e := newEnv(t)
	path := kayitliOturum(t, e, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", true)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(string(raw), "uname")
	if i < 0 {
		t.Fatal("kayıtta beklenen içerik yok")
	}
	raw[i] = 'U'
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := e.run(t, newSessionCmd(), "verify", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err == nil {
		t.Fatalf("değiştirilmiş kayıt sıfır çıkış kodu verdi: %s", out)
	}
	if !strings.Contains(out, "FAILED") {
		t.Errorf("çıktı FAILED demiyor: %s", out)
	}
}

/*
 * Zinciri olmayan oturum: "geçti" DEĞİL, "doğrulanamaz". Bu ayrımı
 * yapmayan bir komut, kanıtı olmayan bir kaydı kanıtlanmış gösterir.
 */
func TestSessionVerifySaysWhenThereIsNoChain(t *testing.T) {
	e := newEnv(t)
	kayitliOturum(t, e, "cccccccccccccccccccccccccccccccc", false)

	out, err := e.run(t, newSessionCmd(), "verify", "cccccccccccccccccccccccccccccccc")
	if err == nil {
		t.Fatalf("zincirsiz kayıt başarı döndürdü: %s", out)
	}
	if !strings.Contains(err.Error(), "cannot be verified") {
		t.Errorf("mesaj 'doğrulanamaz' demiyor: %v", err)
	}
	if strings.Contains(out, "OK") {
		t.Errorf("zincirsiz kayıt için OK yazıldı: %s", out)
	}
}
