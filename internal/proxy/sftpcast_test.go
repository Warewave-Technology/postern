package proxy

import (
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/record"
	"github.com/Warewave-Technology/postern/internal/sftpaudit"
)

// stderrCast, SFTP açıkken hedefin stderr'ini kayda verip sonucu döner.
func stderrCast(t *testing.T, chunks ...string) string {
	t.Helper()

	sink := &memCloser{}
	rec, err := record.NewWriter(sink, 80, 24, nil)
	if err != nil {
		t.Fatal(err)
	}

	b := &Broker{rec: rec}
	b.sftp.Store(sftpaudit.NewSession(func(sftpaudit.Event) {}))

	w := newCastStderr(b)
	for _, c := range chunks {
		if _, err := w.Write([]byte(c)); err != nil {
			t.Fatal(err)
		}
	}
	w.flush()

	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	return sink.String()
}

/*
 * ⚠️ SAHTE DENETİM SATIRI, KANAL TÜRÜ BELLİ OLMADAN DA YAZILAMAMALI.
 *
 * Atıf kapısı `b.sftp`ye bakıyordu ve o ancak oturumu başlatan istek
 * işlenince doluyor. Arada bir pencere vardı: stderr boru hattı Run ile
 * başlıyor, istemcinin `subsystem sftp`si ise sonra geliyor. O pencerede
 * hedefin yazdığı her şey kayda HAM giriyordu — yani uydurma bir denetim
 * satırı, yalnızca daha ERKEN göndererek hâlâ mümkündü. Kaçış dizisi
 * temizlemek bunu kapatmıyor: sahte satır zaten yazdırılabilir.
 *
 * Kabuk kaydında ham bayt DOĞRU (o dosyanın tamamı ham), o yüzden
 * "bilmiyorken temizle" de olmuyor. Karar verilene kadar BEKLETİLİYOR.
 */
func TestNothingReachesTheRecordingBeforeTheChannelIsDecided(t *testing.T) {
	sink := &memCloser{}
	rec, err := record.NewWriter(sink, 80, 24, nil)
	if err != nil {
		t.Fatal(err)
	}

	// ⚠️ Ne sftp kuruldu ne başlangıç kapısı açıldı: kanal türü BELİRSİZ.
	b := &Broker{rec: rec}
	w := newCastStderr(b)

	forged := "postern sftp: get /etc/shadow (1.2 KiB)\n"
	if _, err := w.Write([]byte(forged)); err != nil {
		t.Fatal(err)
	}

	if got := sink.String(); strings.Contains(got, "get /etc/shadow") {
		t.Fatalf("kanal türü belli değilken hedefin baytı kayda girdi:\n%s", got)
	}

	// Şimdi oturum SFTP oluyor: bekletilen satır ATIFLI çıkmalı.
	b.sftp.Store(sftpaudit.NewSession(func(sftpaudit.Event) {}))
	b.openStartGate()
	if _, err := w.Write([]byte("sonraki\n")); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	out := sink.String()
	if !strings.Contains(out, "target wrote: postern sftp: get /etc/shadow") {
		t.Errorf("bekletilen satır atfedilerek girmemiş:\n%s", out)
	}
	if !strings.Contains(out, "target wrote: sonraki") {
		t.Errorf("sonraki satır girmemiş:\n%s", out)
	}

	/*
	 * Ve hedef postern'in satır biçimini ele geçiremiyor: kayıt JSON
	 * satırlarından oluşuyor, yani bir çıktı parçasının başı ya tırnaktan
	 * ya da kaçırılmış bir satır sonundan sonra geliyor.
	 */
	for _, start := range []string{`"postern sftp: get`, `\r\npostern sftp: get`} {
		if strings.Contains(out, start) {
			t.Errorf("hedef, postern'in satır biçimini ele geçirdi:\n%s", out)
		}
	}
}

/*
 * ⚠️ HİÇ KARAR VERİLMEDEN KAPANAN OTURUMDA DA KAYBOLMUYOR. Hedef
 * stderr'e yazdı, istemci hiçbir program başlatmadı: bekletilenler
 * kapanışta atıflı yoldan çıkıyor — ve önek "sftp" demiyor, çünkü bu
 * kanal SFTP olmadı.
 */
func TestHeldStderrSurvivesASessionThatNeverStarted(t *testing.T) {
	sink := &memCloser{}
	rec, err := record.NewWriter(sink, 80, 24, nil)
	if err != nil {
		t.Fatal(err)
	}

	b := &Broker{rec: rec}
	w := newCastStderr(b)
	if _, err := w.Write([]byte("hedefin son sözü\n")); err != nil {
		t.Fatal(err)
	}
	w.flush()
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	out := sink.String()
	if !strings.Contains(out, "postern: target wrote: hedefin son sözü") {
		t.Errorf("bekletilen satır kapanışta kayboldu ya da yanlış etiketlendi:\n%s", out)
	}
	if strings.Contains(out, "postern sftp:") {
		t.Errorf("SFTP olmayan kanal kaydında 'sftp' etiketi var:\n%s", out)
	}
}

/*
 * ⚠️ SATIR HEDEFİN VERDİĞİ PARÇALARA GÖRE DEĞİL, SATIR SONUNA GÖRE
 * KESİLİYOR.
 *
 * Hedef metnini istediği yerden bölebiliyor ve bölünme yeri onun elinde.
 * Damgayı parça başına koysaydık, bir cümleyi ikiye bölmek onu iki
 * "target wrote:" satırına çevirirdi — ya da tersi: damgayı tek parçaya
 * koymak, hedefin araya kendi satır sonunu koymasıyla damgasız bir satır
 * üretmesine izin verirdi.
 */
func TestTargetStderrIsStampedPerLineNotPerWrite(t *testing.T) {
	out := stderrCast(t, "one line ", "split over three ", "writes\n")

	if n := strings.Count(out, "target wrote:"); n != 1 {
		t.Errorf("damga sayısı = %d, 1 bekleniyordu:\n%s", n, out)
	}
	if !strings.Contains(out, "target wrote: one line split over three writes") {
		t.Errorf("satır birleştirilmemiş:\n%s", out)
	}
}

/*
 * ⚠️ HEDEFİN stderr'İ DE İKİ YÖNLÜ DENETİMLERDEN ARINIYOR.
 *
 * İki ayrı düzeltmenin BULUŞTUĞU yer, ve buluşma sessizce bozulabilir:
 * biri castSafe'e U+202E'yi ekledi (dosya adları kayıtta yalan
 * söylüyordu), diğeri hedefin stderr'ini kayda castSafe üzerinden
 * sokmaya başladı. İkisi bugün örtüşüyor — ama stderr yolu bir gün
 * castSafe'i atlarsa, dosya adı tarafındaki test yine geçer ve bu yüzey
 * sessizce açılır.
 *
 * Kaçış dizisi ekranı boyuyor: gürültülü. U+202E satırı olduğu gibi
 * bırakıp BAŞKA okutuyor, ve bir denetim kaydında yanlış okunan bir
 * cevap, okunmayan cevaptan kötü.
 */
func TestTargetStderrDropsBidiOverridesToo(t *testing.T) {
	out := stderrCast(t, "fetched fatura\u202egnp.exe\n")

	if strings.ContainsRune(out, '\u202e') {
		t.Errorf("iki yönlü denetim kayda düştü:\n%s", out)
	}
	if !strings.Contains(out, "target wrote: fetched faturagnp.exe…") {
		t.Errorf("ad temizlenmiş hâliyle ve atıflı girmedi:\n%s", out)
	}
}

/*
 * ⚠️ HEDEFİN CRLF'İ ÇİFT SATIR BAŞI ÜRETMİYOR. Satırı postern kendi
 * "\r\n"siyle kapatıyor; hedefinkini de geçirmek, oynatıcıda boş satırlar
 * açardı — hedefin eline kaydın YERLEŞİMİNİ verirdi.
 */
func TestTargetStderrCRLFBecomesOneLineBreak(t *testing.T) {
	out := stderrCast(t, "a\r\nb\r\n")

	if n := strings.Count(out, "target wrote:"); n != 2 {
		t.Errorf("satır sayısı = %d, 2 bekleniyordu:\n%s", n, out)
	}
	if strings.Contains(out, `\r\r`) {
		t.Errorf("çift satır başı kayda düştü:\n%s", out)
	}
}

/*
 * ⚠️ SATIR SONU HİÇ GÖNDERMEYEN HEDEF, TAMPONU BÜYÜTEMİYOR.
 *
 * ÖLÇÜLEN ŞEY TAMPONUN KENDİSİ, kayda çıkan satır DEĞİL — çıktı zaten
 * castSafe'in 512'sine takılıyor ve o tavana bakan bir test, buradaki
 * tavan hiç olmasa da geçerdi. Sınırlanan şey süreçte duran bellek:
 * satır sonu göndermeyen bir hedef, gigabaytı burada biriktirebilirdi.
 *
 * Kırpmanın GÖRÜNÜR olması ayrı bir iddia ve o da ölçülüyor: sessizce
 * kısaltılmış bir satır, denetçiye hedefin o kadarını yazdığını
 * düşündürürdü.
 */
func TestTargetStderrLineIsBoundedAndSaysSo(t *testing.T) {
	sink := &memCloser{}
	rec, err := record.NewWriter(sink, 80, 24, nil)
	if err != nil {
		t.Fatal(err)
	}

	b := &Broker{rec: rec}
	b.sftp.Store(sftpaudit.NewSession(func(sftpaudit.Event) {}))
	w := newCastStderr(b)

	// Satır sonu hiç göndermeyen bir hedef.
	for range 10 {
		if _, err := w.Write([]byte(strings.Repeat("a", maxCastStderrLine))); err != nil {
			t.Fatal(err)
		}
	}

	if len(w.line) > maxCastStderrLine {
		t.Errorf("tampon sınırsız büyüdü: %d bayt", len(w.line))
	}

	w.flush()
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	if out := sink.String(); !strings.Contains(out, "…") {
		t.Errorf("kırpmanın izi kayıtta yok:\n%s", out)
	}
}

func ev(op sftpaudit.Op, path string, mod ...func(*sftpaudit.Event)) sftpaudit.Event {
	e := sftpaudit.Event{At: time.Unix(1757066400, 0), Op: op, Path: path, OK: true}
	for _, m := range mod {
		m(&e)
	}

	return e
}

/*
 * ⚠️ BU DOSYADAKİ EN ÖNEMLİ TEST.
 *
 * Kayda giren metin OYNATILDIĞINDA TERMİNALDE ÇALIŞIR. Dosya adını
 * hedefteki kullanıcı koyuyor; içine ESC dizisi koyan biri, kaydı izleyen
 * denetçinin ekranını boyayabilir, imleci oynatabilir, kendinden önceki
 * satırları SİLEBİLİR — yani kaydı yanıltıcı kılabilir. Bir denetim
 * kaydında bu, kaydın hiç olmamasından kötü.
 */
func TestControlBytesNeverReachTheRecording(t *testing.T) {
	nasty := []struct {
		name, path string
	}{
		{"ESC dizisi", "/tmp/\x1b[2J\x1b[Hsahte.txt"},
		{"satır başı", "/tmp/a\rpostern sftp: get /etc/shadow"},
		{"satır sonu", "/tmp/a\nb"},
		{"geri silme", "/tmp/gizli\x08\x08\x08\x08\x08masum"},
		// C1: UTF-8 çözümünden sonra tek baytlık ESC eşdeğeri.
		{"C1 CSI", "/tmp/[2Jsahte"},
		{"NUL", "/tmp/a\x00b"},
		{"DEL", "/tmp/a\x7fb"},
		// Bozuk UTF-8: hedefin dosya adı geçerli UTF-8 olmak zorunda değil.
		{"bozuk UTF-8", "/tmp/a\xffb"},
	}

	for _, c := range nasty {
		t.Run(c.name, func(t *testing.T) {
			line := castLine(ev(sftpaudit.OpOpendir, c.path))

			// Satır sonu YALNIZCA sonda olmalı.
			body := strings.TrimSuffix(line, "\r\n")
			for _, r := range body {
				if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
					t.Fatalf("kontrol baytı kayda girdi: %q içinde %U", line, r)
				}
			}
			if !strings.HasSuffix(line, "\r\n") {
				t.Errorf("satır sonu yok: %q", line)
			}
		})
	}
}

/*
 * TestBidiControlsNeverReachTheRecording — satırı BOYAMAYAN ama YALAN
 * SÖYLETEN karakterler.
 *
 * ⚠️ KAÇIŞ DİZİLERİNDEN FARKI, SATIRIN OLDUĞU GİBİ DURMASI. İki yönlü
 * yazı denetimleri ekranı yeniden yazmıyor; satırı BAŞKA okutuyorlar.
 * Hedefte "fatura<U+202E>gnp.exe" adında bir dosya açan biri, o dosyayı
 * alan oturumun kaydında "fatura exe.png" yazan bir satır bırakıyor:
 * denetçi bir resim indirildiğini sanıyor. Kayıt, "kim hangi dosyayı
 * aldı" sorusunun cevabı; o cevabın YANLIŞ OKUNMASI, kaydın okunmaz
 * olmasından kötü.
 *
 * Canlı denemede bulundu: ad, panelin ürettiği arşivde temizleniyordu
 * ama kayda olduğu gibi giriyordu.
 */
func TestBidiControlsNeverReachTheRecording(t *testing.T) {
	bidi := []struct {
		name, path string
	}{
		{"RLO", "/tmp/fatura\u202egnp.exe"},
		{"LRO", "/tmp/a\u202db"},
		{"PDF", "/tmp/a\u202cb"},
		{"LRM", "/tmp/a\u200eb"},
		{"RLM", "/tmp/a\u200fb"},
		{"izole", "/tmp/a\u2066b\u2069c"},
	}

	for _, c := range bidi {
		t.Run(c.name, func(t *testing.T) {
			line := castLine(ev(sftpaudit.OpOpendir, c.path))

			for _, r := range line {
				if r == 0x200e || r == 0x200f ||
					(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
					t.Fatalf("yön denetimi kayda girdi: %q içinde %U", line, r)
				}
			}
		})
	}
}

// Atılan bir şey olduğu KAYBOLMAMALI: temizlenmiş bir ad, temiz bir adla
// aynı görünürse denetçi yanlış dosyaya bakar.
func TestSanitisingIsVisible(t *testing.T) {
	dirty := castLine(ev(sftpaudit.OpOpendir, "/tmp/a\x1bb"))
	clean := castLine(ev(sftpaudit.OpOpendir, "/tmp/ab"))
	if dirty == clean {
		t.Fatalf("temizlenen ad, temiz adla aynı satırı üretti: %q", dirty)
	}
	if !strings.Contains(dirty, "…") {
		t.Errorf("atma işareti yok: %q", dirty)
	}
}

// Tümüyle atılmış bir alan BOŞ bırakılmamalı: boş yol "yol yoktu" demek.
func TestFullyStrippedPathStillShows(t *testing.T) {
	line := castLine(ev(sftpaudit.OpOpendir, "\x1b\x1b\x1b"))
	if !strings.Contains(line, "(unprintable)") {
		t.Errorf("tümüyle atılan yol görünmüyor: %q", line)
	}
}

// Alan uzunluğu sınırlı: gerekçe metni HEDEFTEN geliyor ve sınırı hedef
// koyuyor. Sınırsız bırakmak, tek isteğin kaydı şişirmesine izin verirdi.
func TestFieldsAreBounded(t *testing.T) {
	line := castLine(ev(sftpaudit.OpOpendir, "/"+strings.Repeat("a", 4000)))
	if len(line) > maxCastField+200 {
		t.Errorf("satır sınırı aşıyor: %d bayt", len(line))
	}
}

/*
 * Aktarımın YÖNÜ görünmeli. "transfer /x (1 MiB)" bir denetçinin ilk
 * sorduğu şeyi — dosya çıktı mı girdi mi — cevaplamıyor.
 */
func TestTransferDirectionIsVisible(t *testing.T) {
	get := castLine(ev(sftpaudit.OpTransfer, "/tmp/r.pdf", func(e *sftpaudit.Event) { e.Read = 1536 }))
	put := castLine(ev(sftpaudit.OpTransfer, "/tmp/y.tar", func(e *sftpaudit.Event) { e.Wrote = 2048 }))

	if !strings.Contains(get, "get ") || !strings.Contains(get, "1.5 KiB") {
		t.Errorf("indirme satırı: %q", get)
	}
	if !strings.Contains(put, "put ") || !strings.Contains(put, "2.0 KiB") {
		t.Errorf("yükleme satırı: %q", put)
	}
	if strings.Contains(get, "put") || strings.Contains(put, "get") {
		t.Errorf("yön karıştı: %q / %q", get, put)
	}
}

// Açılmış ama tek bayt taşınmamış dosya "get 0 B" DEMEMELİ: bir aktarım
// olduğunu düşündürürdü.
func TestOpenWithoutTransferIsNotCalledGet(t *testing.T) {
	line := castLine(ev(sftpaudit.OpTransfer, "/tmp/bos"))
	if strings.Contains(line, "get") || strings.Contains(line, "put") {
		t.Errorf("bayt taşımayan aktarım yön iddia ediyor: %q", line)
	}
	if !strings.Contains(line, "opened") {
		t.Errorf("beklenen 'opened': %q", line)
	}
}

/*
 * ⚠️ BAŞARISIZLIK GÖRÜNÜR OLMAK ZORUNDA. "Kimse denemedi" ile "denedi ve
 * reddedildi" ayrı bulgular; kayıt ikincisini göstermezse denetçi
 * ilkini varsayar.
 */
func TestRefusalsAndFailuresAreVisible(t *testing.T) {
	denied := castLine(ev("denied.opendir", "/etc", func(e *sftpaudit.Event) {
		e.OK = false
		e.Detail = "postern: path is not allowed by your role"
	}))
	if !strings.Contains(denied, "denied opendir") {
		t.Errorf("ret görünmüyor: %q", denied)
	}
	if !strings.Contains(denied, "not allowed by your role") {
		t.Errorf("gerekçe görünmüyor: %q", denied)
	}

	// Hedefin kendi reddi: "denied." öneki YOK ama OK=false.
	failed := castLine(ev(sftpaudit.OpOpen, "/root/x", func(e *sftpaudit.Event) {
		e.OK = false
		e.Detail = "Permission denied"
	}))
	if !strings.Contains(failed, "[failed]") {
		t.Errorf("hedefin reddi görünmüyor: %q", failed)
	}
}

func TestByteFormatting(t *testing.T) {
	for _, c := range []struct {
		n    int64
		want string
	}{{0, "0 B"}, {512, "512 B"}, {1024, "1.0 KiB"}, {1536, "1.5 KiB"},
		{1048576, "1.0 MiB"}, {1610612736, "1.5 GiB"}} {
		if got := castBytes(c.n); got != c.want {
			t.Errorf("castBytes(%d) = %q, %q bekleniyordu", c.n, got, c.want)
		}
	}
}
