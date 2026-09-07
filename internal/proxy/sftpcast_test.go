package proxy

import (
	"strings"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/sftpaudit"
)

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
