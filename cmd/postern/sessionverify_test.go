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
	"github.com/Warewave-Technology/postern/internal/sftpaudit"
	"github.com/Warewave-Technology/postern/internal/sftpcast"
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

	/*
	 * ⚠️ DEFTER SATIRI HER YOLDA BASILIYOR — printOffBox'la aynı
	 * gerekçeyle. Bu oturum göç 037'den önce kapanmış bir oturum gibi:
	 * karşılaştıracak sayı yok. Sessiz geçilseydi okuyan kişi kontrolün
	 * yapıldığını ve tuttuğunu varsayardı.
	 */
	if !strings.Contains(out, "JOURNAL  NOT CHECKED") {
		t.Errorf("ölçülmemiş defter için satır basılmadı: %s", out)
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

/*
 * ⚠️ DEFTERDEN SATIR SİLMEK, KAYDI YENİDEN YAZMAKTAN ÇOK DAHA UCUZ.
 *
 * Zincir dosyayı koruyor ve `session verify` onu doğruluyordu; aynı
 * oturumun `session_files` satırları ise hiçbir şeyle karşılaştırılmıyordu.
 * Kaydın mühür satırı kaç dosya olayı olduğunu SÖYLÜYOR (proxy/sftpcast.go)
 * ama o sayının programatik bir tüketicisi yoktu — yani bir DELETE,
 * doğrulaması geçen bir kaydın altında iz bırakmadan duruyordu.
 */
func TestSessionVerifySaysWhenJournalRowsAreMissing(t *testing.T) {
	e := newEnv(t)
	const id = "dddddddddddddddddddddddddddddddd"
	kayitliOturum(t, e, id, true)

	ctx := context.Background()
	// Oturum üç dosya olayı üretmiş ve postern hiçbirini kaybetmemiş.
	if err := e.db.MarkSFTPJournal(ctx, id,
		model.SFTPJournal{Measured: true, Events: 3}); err != nil {
		t.Fatal(err)
	}
	// Deftere yalnızca biri duruyor: ikisi silinmiş.
	if err := e.db.AddSessionFiles(ctx, id, []store.SessionFile{{
		At: time.Now(), Op: "open", Path: "/etc/shadow", OK: true, InRecording: true,
	}}); err != nil {
		t.Fatal(err)
	}

	out, err := e.run(t, newSessionCmd(), "verify", id)
	if err == nil {
		t.Fatalf("EKSİK DEFTER SIFIR ÇIKIŞ KODU VERDİ: %s", out)
	}
	if !strings.Contains(out, "ROWS MISSING") {
		t.Errorf("çıktı eksik satırları söylemiyor: %s", out)
	}
	// Kayıt DEĞİŞMEDİ: iki bulgu ayrı kalmalı, yoksa olay müdahalesi
	// betiği yanlış olaya bakar.
	if strings.Contains(out, "FAILED") {
		t.Errorf("dokunulmamış kayıt için FAILED yazıldı: %s", out)
	}
	if !strings.HasPrefix(out, "OK") {
		t.Errorf("zincir raporu kayboldu: %s", out)
	}
}

/*
 * ⚠️ POSTERN'İN KENDİ KAYBI, MÜDAHALEDEN AYRI RAPORLANMALI.
 *
 * Aritmetiği aynı (satır sayısı mühürden eksik) ama olayı bambaşka.
 * İkisini tek cümleye indirmek, tampon taşması yaşamış her oturumu
 * kurcalanmış diye bildirirdi — ve o alarm birkaç kez yanlış çıktıktan
 * sonra kimse gerçeğine bakmaz.
 */
func TestSessionVerifySaysWhenPosternLostTheEventsItself(t *testing.T) {
	e := newEnv(t)
	const id = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	kayitliOturum(t, e, id, true)

	ctx := context.Background()
	if err := e.db.MarkSFTPJournal(ctx, id,
		model.SFTPJournal{Measured: true, Events: 3, Lost: 2}); err != nil {
		t.Fatal(err)
	}
	if err := e.db.AddSessionFiles(ctx, id, []store.SessionFile{{
		At: time.Now(), Op: "open", Path: "/etc/shadow", OK: true, InRecording: true,
	}}); err != nil {
		t.Fatal(err)
	}

	out, err := e.run(t, newSessionCmd(), "verify", id)
	// Çıkış kodu YİNE sıfırdan farklı: kanıt eksik, sebebi ne olursa
	// olsun. Betikten çağıran "eksiksiz" ile "eksik ama sebebi belli"yi
	// ayırt etmek zorunda değil; ikisi de tam bir defter değil.
	if err == nil {
		t.Fatalf("eksik defter sıfır çıkış kodu verdi: %s", out)
	}
	if !strings.Contains(out, "INCOMPLETE") {
		t.Errorf("çıktı postern'in kendi kaybını söylemiyor: %s", out)
	}
	if strings.Contains(out, "ROWS MISSING") {
		t.Errorf("BİLİNEN KAYIP MÜDAHALE DİYE RAPORLANDI: %s", out)
	}
}

/*
 * Defteri tam olan oturum: kontrolün ÇALIŞTIĞI da yazılmalı. Yalnızca
 * kötü haberde konuşan bir kontrol, hiç koşmadığında da sessiz kalır ve
 * ikisi ayırt edilemez.
 */
func TestSessionVerifyReportsAnIntactJournal(t *testing.T) {
	e := newEnv(t)
	const id = "ffffffffffffffffffffffffffffffff"
	kayitliOturum(t, e, id, true)

	ctx := context.Background()
	if err := e.db.MarkSFTPJournal(ctx, id,
		model.SFTPJournal{Measured: true, Events: 2}); err != nil {
		t.Fatal(err)
	}
	if err := e.db.AddSessionFiles(ctx, id, []store.SessionFile{
		{At: time.Now(), Op: "open", Path: "/tmp/a", OK: true, InRecording: true},
		{At: time.Now(), Op: "transfer", Path: "/tmp/a", Read: 9, OK: true, InRecording: true},
		// ⚠️ KANAL DÜZEYİNDEKİ RET SAYIMA GİRMEMELİ: kayda girmiyor.
		// Sayılsaydı bu oturum "mühürden fazla satır var" diye
		// raporlanırdı — yani doğru çalışan bir bastion, kontrolün
		// yanlış alarmıyla suçlanırdı.
		{At: time.Now(), Op: "denied.x11-req", OK: false, Detail: "x11 forwarding is off"},
	}); err != nil {
		t.Fatal(err)
	}

	out, err := e.run(t, newSessionCmd(), "verify", id)
	if err != nil {
		t.Fatalf("defteri tam oturum düştü: %v\n%s", err, out)
	}
	if !strings.Contains(out, "JOURNAL  OK") {
		t.Errorf("çıktı defterin kontrol edildiğini söylemiyor: %s", out)
	}
	if !strings.Contains(out, "2 events in the recording's seal, 2 rows") {
		t.Errorf("çıktı karşılaştırılan sayıları vermiyor: %s", out)
	}
}

/*
 * ⚠️ SAYIYA BAKAN BİR KONTROL, DEĞİŞTİRİLMİŞ SATIRI GÖREMEZ.
 *
 * Defterden satır silmek bir boşluk bırakıyor ve sayım onu görüyor. Bir
 * satırı değiştirmek — "/etc/shadow" yazan yolu "/tmp/notlar" yapan bir
 * UPDATE — hiçbir boşluk bırakmıyor: liste tam görünüyor, sayı tutuyor,
 * ve müdahale tam bir denetim kaydı gibi duruyor. Onu gören tek şey,
 * mühürdeki özet.
 */
func TestSessionVerifySeesAChangedJournalRow(t *testing.T) {
	e := newEnv(t)
	const id = "11111111111111111111111111111111"
	kayitliOturum(t, e, id, true)

	ctx := context.Background()

	// Oturumda gerçekten olan olay: /etc/shadow açıldı.
	gercek := sftpaudit.Event{Op: sftpaudit.OpOpen, Path: "/etc/shadow", OK: true}
	var seal sftpcast.Seal
	seal.Add(sftpcast.Line(gercek))

	if err := e.db.MarkSFTPJournal(ctx, id, model.SFTPJournal{
		Measured: true, Events: 1, Digest: seal.Head(),
	}); err != nil {
		t.Fatal(err)
	}
	// Deftere yazılan satır ise başka bir yol gösteriyor: satır sayısı
	// doğru, içeriği değil.
	if err := e.db.AddSessionFiles(ctx, id, []store.SessionFile{{
		At: time.Now(), Op: "open", Path: "/tmp/notlar", OK: true, InRecording: true,
	}}); err != nil {
		t.Fatal(err)
	}

	out, err := e.run(t, newSessionCmd(), "verify", id)
	if err == nil {
		t.Fatalf("DEĞİŞTİRİLMİŞ DEFTER SIFIR ÇIKIŞ KODU VERDİ: %s", out)
	}
	if !strings.Contains(out, "ROWS ALTERED") {
		t.Errorf("çıktı değiştirilmiş satırı söylemiyor: %s", out)
	}
	if !strings.Contains(out, "1 event in the recording's seal, 1 row in the journal") {
		t.Errorf("çıktı sayıların TUTTUĞUNU göstermiyor; okuyan kişi eksik satır arar: %s", out)
	}
}

/*
 * Defteri tam olan oturumda çıktı, ÖZETİN DE karşılaştırıldığını
 * söylemeli. "OK" tek başına, yalnızca sayıya bakılmış bir kontrolle
 * ikisine birden bakılmış bir kontrolü aynı gösterir.
 */
func TestSessionVerifySaysTheDigestWasChecked(t *testing.T) {
	e := newEnv(t)
	const id = "22222222222222222222222222222222"
	kayitliOturum(t, e, id, true)

	ctx := context.Background()

	olay := sftpaudit.Event{Op: sftpaudit.OpOpendir, Path: "/tmp", OK: true}
	var seal sftpcast.Seal
	seal.Add(sftpcast.Line(olay))

	if err := e.db.MarkSFTPJournal(ctx, id, model.SFTPJournal{
		Measured: true, Events: 1, Digest: seal.Head(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.db.AddSessionFiles(ctx, id, []store.SessionFile{{
		At: time.Now(), Op: string(olay.Op), Path: olay.Path, OK: true, InRecording: true,
	}}); err != nil {
		t.Fatal(err)
	}

	out, err := e.run(t, newSessionCmd(), "verify", id)
	if err != nil {
		t.Fatalf("dokunulmamış defter düştü: %v\n%s", err, out)
	}
	if !strings.Contains(out, "JOURNAL  OK") {
		t.Errorf("çıktı defterin kontrol edildiğini söylemiyor: %s", out)
	}
	if !strings.Contains(out, "digest matches") {
		t.Errorf("çıktı özetin de tuttuğunu söylemiyor: %s", out)
	}
}
