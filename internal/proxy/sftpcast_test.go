package proxy

// Hedefin stderr'inin KAYDA giden kopyası (sftpcast.go, castStderr).
//
// ⚠️ SATIR BİÇİMİ internal/sftpcast'E TAŞINDI ama bu testler taşınmadı:
// ölçtükleri şey biçim değil, castStderr'in kapısı — kanalın türü, atıf
// ve bekletme. Hepsi Broker'a bağlı, yani proxy paketinde kalıyorlar.

import (
	"strings"
	"testing"

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
