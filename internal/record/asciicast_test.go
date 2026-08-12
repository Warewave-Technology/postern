package record

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
)

// nopCloser, bellekteki tamponu io.WriteCloser gibi gösterir.
type nopCloser struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	closed bool
}

func (n *nopCloser) Write(p []byte) (int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.buf.Write(p)
}

func (n *nopCloser) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.closed = true
	return nil
}

func (n *nopCloser) String() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.buf.String()
}

// parseCast, üretilen dosyayı başlık + olaylar olarak ayrıştırır ve her
// satırın geçerli JSON olduğunu doğrular.
func parseCast(t *testing.T, raw string) (map[string]any, [][]any) {
	t.Helper()

	lines := strings.Split(strings.TrimRight(raw, "\n"), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatal("çıktı boş — başlık satırı yok")
	}

	var header map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &header); err != nil {
		t.Fatalf("başlık geçerli JSON değil: %v\nsatır: %s", err, lines[0])
	}

	var events [][]any
	for i, line := range lines[1:] {
		var ev []any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("olay satırı %d geçerli JSON değil: %v\nsatır: %s", i, err, line)
		}
		if len(ev) != 3 {
			t.Fatalf("olay satırı %d üç alan içermeli, %d içeriyor: %v", i, len(ev), ev)
		}
		events = append(events, ev)
	}
	return header, events
}

func eventData(t *testing.T, ev []any) (kind, data string) {
	t.Helper()
	k, ok := ev[1].(string)
	if !ok {
		t.Fatalf("olay tipi string olmalı: %v", ev[1])
	}
	d, ok := ev[2].(string)
	if !ok {
		t.Fatalf("olay verisi string olmalı: %v", ev[2])
	}
	return k, d
}

// Başlık: asciicast v2 şeması.
func TestWriterHeader(t *testing.T) {
	out := &nopCloser{}

	w, err := NewWriter(out, 120, 30, map[string]string{"TERM": "xterm-256color"})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	header, _ := parseCast(t, out.String())

	if v, _ := header["version"].(float64); v != 2 {
		t.Errorf("version = %v, beklenen 2", header["version"])
	}
	if v, _ := header["width"].(float64); v != 120 {
		t.Errorf("width = %v, beklenen 120", header["width"])
	}
	if v, _ := header["height"].(float64); v != 30 {
		t.Errorf("height = %v, beklenen 30", header["height"])
	}
	if ts, _ := header["timestamp"].(float64); ts <= 0 {
		t.Errorf("timestamp = %v, pozitif unix zamanı bekleniyordu", header["timestamp"])
	}
	env, ok := header["env"].(map[string]any)
	if !ok || env["TERM"] != "xterm-256color" {
		t.Errorf("env = %v, TERM taşımalı", header["env"])
	}
	if !out.closed {
		t.Error("Close alttaki writer'ı da kapatmalı")
	}
}

// Olay sırası korunmalı, tipler doğru olmalı, zaman monoton artmalı.
func TestWriterEventOrder(t *testing.T) {
	out := &nopCloser{}
	w, err := NewWriter(out, 80, 24, nil)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	if err := w.Output([]byte("birinci\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Input([]byte("ls\r")); err != nil {
		t.Fatal(err)
	}
	if err := w.Resize(120, 30); err != nil {
		t.Fatal(err)
	}
	if err := w.Output([]byte("ikinci\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	_, events := parseCast(t, out.String())
	if len(events) != 4 {
		t.Fatalf("olay sayısı = %d, beklenen 4", len(events))
	}

	want := []struct{ kind, data string }{
		{"o", "birinci\n"},
		{"i", "ls\r"},
		{"r", "120x30"},
		{"o", "ikinci\n"},
	}
	var last float64
	for i, ev := range events {
		kind, data := eventData(t, ev)
		if kind != want[i].kind || data != want[i].data {
			t.Errorf("olay %d = (%q,%q), beklenen (%q,%q)", i, kind, data, want[i].kind, want[i].data)
		}
		ts, _ := ev[0].(float64)
		if ts < last {
			t.Errorf("olay %d zamanı geriye gitti: %v < %v", i, ts, last)
		}
		last = ts
	}
}

// ⚠️ Çok baytlı karakter iki yazmaya bölünebilir — SSH paket sınırı karakter
// sınırına saygı duymaz. Kayıt bunu birleştirmezse Türkçe metin bozulur.
func TestWriterSplitMultibyte(t *testing.T) {
	out := &nopCloser{}
	w, err := NewWriter(out, 80, 24, nil)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	// "değişti" — 0xC4 0x9F = "ğ". İlk yazma "ğ"nin ortasında kesiliyor.
	full := []byte("değişti")
	cut := bytes.IndexByte(full, 0xC4) + 1 // 0xC4'ten hemen sonra

	if err := w.Output(full[:cut]); err != nil {
		t.Fatal(err)
	}
	if err := w.Output(full[cut:]); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	_, events := parseCast(t, out.String())

	var joined strings.Builder
	for _, ev := range events {
		_, data := eventData(t, ev)
		joined.WriteString(data)
	}
	if got := joined.String(); got != "değişti" {
		t.Fatalf("birleşik çıktı = %q, beklenen %q — çok baytlı karakter bölünmede bozuldu", got, "değişti")
	}
}

// Yarım kalan kuyruk sessizce düşürülmemeli: Close onu da yazmalı.
func TestWriterFlushesPendingOnClose(t *testing.T) {
	out := &nopCloser{}
	w, err := NewWriter(out, 80, 24, nil)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	if err := w.Output([]byte{0xC4}); err != nil { // yarım "ğ", devamı hiç gelmiyor
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	_, events := parseCast(t, out.String())
	if len(events) == 0 {
		t.Fatal("yarım kalan bayt sessizce düşürüldü — kayıt dürüst olmalı")
	}
}

// Eşzamanlı Output/Input satırları bozmamalı. `go test -race` ile koş.
func TestWriterConcurrentWrites(t *testing.T) {
	out := &nopCloser{}
	w, err := NewWriter(out, 80, 24, nil)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	const n = 200
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			if err := w.Output([]byte("cikti satiri\n")); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			if err := w.Input([]byte("girdi\r")); err != nil {
				t.Error(err)
				return
			}
		}
	}()

	wg.Wait()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// parseCast her satırı ayrı ayrı JSON olarak çözüyor: iç içe geçmiş bir
	// yazma varsa burada patlar.
	_, events := parseCast(t, out.String())
	if len(events) != 2*n {
		t.Fatalf("olay sayısı = %d, beklenen %d — satır kaybı veya karışması", len(events), 2*n)
	}
}

// Terminal çıktısı ESC, tırnak, ters bölü ve kontrol karakterleri taşır;
// escape işini json.Marshal yapmalı, elle string birleştirme değil.
func TestWriterEscapesControlBytes(t *testing.T) {
	out := &nopCloser{}
	w, err := NewWriter(out, 80, 24, nil)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	raw := "\x1b[?1034h\"tirnak\" ve \\ters\t\n"
	if err := w.Output([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	_, events := parseCast(t, out.String())
	if len(events) != 1 {
		t.Fatalf("olay sayısı = %d, beklenen 1", len(events))
	}
	if _, data := eventData(t, events[0]); data != raw {
		t.Fatalf("veri = %q, beklenen %q", data, raw)
	}
}

func TestSplitIncompleteUTF8(t *testing.T) {
	cases := []struct {
		name         string
		in           []byte
		wantComplete string
		wantTrailing []byte
	}{
		{
			name:         "saf ascii",
			in:           []byte("merhaba"),
			wantComplete: "merhaba",
		},
		{
			name:         "tam cok baytli",
			in:           []byte("değişti"),
			wantComplete: "değişti",
		},
		{
			name:         "sonda yarim iki baytli",
			in:           []byte{'d', 'e', 0xC4},
			wantComplete: "de",
			wantTrailing: []byte{0xC4},
		},
		{
			name:         "sonda yarim uc baytli",
			in:           []byte{'a', 0xE2, 0x82}, // "€" = E2 82 AC
			wantComplete: "a",
			wantTrailing: []byte{0xE2, 0x82},
		},
		{
			name:         "tamamen yarim",
			in:           []byte{0xC5},
			wantComplete: "",
			wantTrailing: []byte{0xC5},
		},
		{
			name:         "bos",
			in:           nil,
			wantComplete: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			complete, trailing := splitIncompleteUTF8(tc.in)
			if string(complete) != tc.wantComplete {
				t.Errorf("complete = %q, beklenen %q", complete, tc.wantComplete)
			}
			if !bytes.Equal(trailing, tc.wantTrailing) {
				t.Errorf("trailing = %v, beklenen %v", trailing, tc.wantTrailing)
			}
		})
	}
}

// ⚠️ Çağıranın tamponu YENİDEN KULLANILIR: io.Copy her turda aynı diziyi
// doldurur ve io.Writer sözleşmesi "Write, p'yi saklamamalıdır" der.
// Kaydedici yarım kalan kuyruğu saklıyorsa onu KOPYALAMAK zorundadır;
// aksi halde bir sonraki okuma o baytların üzerine yazar ve kayıt sessizce
// bozulur — üretimde teşhisi en zor hata sınıfı.
func TestWriterDoesNotRetainCallerBuffer(t *testing.T) {
	out := &nopCloser{}
	w, err := NewWriter(out, 80, 24, nil)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	full := []byte("değişti")
	cut := bytes.IndexByte(full, 0xC4) + 1 // "ğ"nin ortasında kes

	// Çağıran tek bir tamponu tekrar tekrar kullanıyor.
	buf := make([]byte, 32)

	n := copy(buf, full[:cut])
	if err := w.Output(buf[:n]); err != nil {
		t.Fatal(err)
	}

	// io.Copy bir sonraki okumadan önce tamponu ezer.
	for i := range buf {
		buf[i] = 'X'
	}

	n = copy(buf, full[cut:])
	if err := w.Output(buf[:n]); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	_, events := parseCast(t, out.String())
	var joined strings.Builder
	for _, ev := range events {
		_, data := eventData(t, ev)
		joined.WriteString(data)
	}
	if got := joined.String(); got != "değişti" {
		t.Fatalf("birleşik çıktı = %q, beklenen %q — kuyruk çağıranın tamponuna referansla saklanmış", got, "değişti")
	}
}

// failingCloser: başlık yazımı geçer, sonraki her yazma patlar (disk dolma
// senaryosu — dosya açıldı, oturum ortasında yer bitti).
type failingCloser struct {
	mu     sync.Mutex
	writes int
	closed bool
}

func (f *failingCloser) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes++
	if f.writes == 1 {
		return len(p), nil // başlık
	}
	return 0, errors.New("disk dolu")
}

func (f *failingCloser) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

// Kayıt arızası oturumu ÖLDÜRMEMELİ: adaptörlerin Write'ı her zaman
// (len(p), nil) döner. Ama arıza kaybolmamalı da — ilk hata Err() ile
// dışarı verilir (bufio.Scanner'daki kalıp).
//
// ⚠️ Adaptörler broker'ın iki ayrı goroutine'inden çağrılır; firstErr'e
// erişim kilit altında olmalı. Bu testi `-race` ile koş.
func TestWriterStreamsSurviveWriteErrors(t *testing.T) {
	w, err := NewWriter(&failingCloser{}, 80, 24, nil)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	out := w.OutputStream()
	in := w.InputStream()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			n, err := out.Write([]byte("cikti\n"))
			if err != nil || n != 6 {
				t.Errorf("OutputStream.Write = (%d,%v), beklenen (6,nil) — kayıt hatası oturumu öldürmemeli", n, err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			n, err := in.Write([]byte("girdi\n"))
			if err != nil || n != 6 {
				t.Errorf("InputStream.Write = (%d,%v), beklenen (6,nil)", n, err)
				return
			}
		}
	}()

	wg.Wait()

	if w.Err() == nil {
		t.Error("yazma hataları yutuldu ve Err() ile de bildirilmedi")
	}
}
