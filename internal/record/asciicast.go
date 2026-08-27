// Package record writes session streams in asciicast v2 format.
//
// Format — ilk satır başlık, sonrası olay satırları:
//
//	{"version":2,"width":80,"height":24,"timestamp":1723465329,"env":{"TERM":"xterm-256color"}}
//	[0.248848,"o","[?1034h"]
//	[2.143881,"i","ls\r"]
//	[3.002100,"r","120x30"]
//
// Kayıt için terminal emülasyonu GEREKMEZ (Ek C.7): bayt akışını
// olduğu gibi saklıyoruz, emülasyonu oynatıcı yapıyor.
//
// ⚠️ SADAKATİN SINIRI: asciicast v2 veriyi JSON DİZESİ olarak saklar ve
// JSON dizesi rastgele bayt tutamaz. encoding/json geçersiz her UTF-8
// baytını U+FFFD (replacement character) ile değiştirir. Yani hedefte
// `cat /bin/ls` çalıştıran bir oturum BİREBİR kaydedilmez.
//
// Bu formatın seçilmesinin bedeli ve bilerek kabul ediliyor: kayıtların
// amacı bir insanın oturumu izlemesi, ikili veriyi yeniden üretmek
// değil. Ama "ham baytları saklıyoruz" demek yanlış olurdu ve bir
// olay incelemesinde yanlış beklenti üretirdi.
// (Ölçüldü: TestWriterReplacesInvalidUTF8Bytes bu davranışı sabitliyor.)
package record

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
	"unicode/utf8"
)

// Writer serializes a session into asciicast v2.
//
// ⚠️ Eşzamanlılık: Output ve Input FARKLI goroutine'lerden gelir (broker'ın
// beş akışını hatırla). mu olmadan iki olay satırı iç içe geçer ve dosya
// bozulur.
//
// KİLİT DİSİPLİNİ — üç katman:
//
//	dış  (Output/Input/Resize/Close)  → mu'yu BURADA al
//	orta (writeStream/flush)          → mu tutuluyor varsayar
//	alt  (writeEvent)                 → mu tutuluyor varsayar
//
// sync.Mutex reentrant DEĞİLDİR: iç katmanlar kilit alsaydı Close→flush→
// writeEvent zinciri kendi kendini kilitlerdi. Tek giriş noktası dış katman
// olduğu için disiplin tek yerde toplanıyor.
type Writer struct {
	mu       sync.Mutex
	w        io.WriteCloser
	start    time.Time
	closed   bool
	firstErr error

	out stream // kind: "o"
	in  stream // kind: "i"
}

// stream, tek bir olay akışının durumu: tipi ve yarım kalan UTF-8 kuyruğu.
// İkisi her zaman birlikte yolculuk ettiği için tek yerde tutuluyor —
// böylece "çıktı olayını girdi tamponuyla yazma" hatası imkânsız hale gelir.
type stream struct {
	kind    string // "o" veya "i" — NewWriter'da bir kez set edilir
	pending []byte // yalnızca yarım kalan kuyruk, en fazla 3 bayt
}

type header struct {
	Version   int               `json:"version"`
	Width     int               `json:"width"`
	Height    int               `json:"height"`
	Timestamp int64             `json:"timestamp"`
	Env       map[string]string `json:"env,omitempty"`
}

type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// NewWriter writes the asciicast header to w and starts the clock.
func NewWriter(w io.WriteCloser, width, height int, env map[string]string) (*Writer, error) {
	t := time.Now()

	if width <= 0 {
		width = 80
	}

	if height <= 0 {
		height = 24
	}

	data, err := json.Marshal(header{Version: 2, Width: width, Height: height, Timestamp: t.Unix(), Env: env})
	if err != nil {
		return nil, fmt.Errorf("record.NewWriter: %w", err)
	}

	if w != nil {
		_, err = w.Write(append(data, '\n'))
		if err != nil {
			return nil, fmt.Errorf("record.NewWriter: %w", err)
		}
	}

	return &Writer{w: w, start: t, in: stream{kind: "i"}, out: stream{kind: "o"}}, nil
}

func (w *Writer) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.firstErr
}

// --- Dış katman: kilidi BUNLAR alır ---

// Output records target→user bytes as an "o" event.
func (w *Writer) Output(b []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}

	err := w.writeStream(&w.out, b)
	if err != nil {
		return fmt.Errorf("record.Output: %w", err)
	}

	return nil
}

// Input records user→target bytes as an "i" event.
//
// ⚠️ Girdi kaydı VARSAYILAN KAPALI olmalı (config record_input: false):
// kullanıcının yazdığı her şey girdidir — sudo parolası dahil. Bu metod
// yalnızca açıkça istendiğinde çağrılır; kararı çağıran verir.
func (w *Writer) Input(b []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}

	err := w.writeStream(&w.in, b)
	if err != nil {
		return fmt.Errorf("record.Input: %w", err)
	}

	return nil
}

// Resize records a terminal size change as an "r" event ("120x30").
func (w *Writer) Resize(cols, rows int) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}

	err := w.writeEvent("r", []byte(fmt.Sprintf("%dx%d", cols, rows)))
	if err != nil {
		return fmt.Errorf("record.Resize: %w", err)
	}

	return nil
}

// Close flushes any buffered bytes and closes the underlying writer.
func (w *Writer) Close() (err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}
	defer func() {
		w.closed = true
		closeErr := w.w.Close()

		if err == nil {
			err = closeErr
		}
	}()

	err = w.flush(&w.out)
	if err != nil {
		return fmt.Errorf("record.Close.output: %w", err)
	}

	err = w.flush(&w.in)
	if err != nil {
		return fmt.Errorf("record.Close.input: %w", err)
	}

	return nil
}

// OutputStream returns an io.Writer recording everything as "o" events.
func (w *Writer) OutputStream() io.Writer {
	return writerFunc(func(p []byte) (int, error) {
		err := w.Output(p)

		w.mu.Lock()
		defer w.mu.Unlock()

		if err != nil && w.firstErr == nil {
			w.firstErr = err
		}

		return len(p), nil
	})
}

// InputStream is the "i" counterpart of OutputStream.
func (w *Writer) InputStream() io.Writer {
	return writerFunc(func(p []byte) (int, error) {
		err := w.Input(p)

		w.mu.Lock()
		defer w.mu.Unlock()

		if err != nil && w.firstErr == nil {
			w.firstErr = err
		}

		return len(p), nil
	})
}

// --- Orta katman: tamponlama. mu TUTULUYOR OLMALI. ---

// writeStream buffers b on s, then emits the part that ends on a complete
// UTF-8 boundary.
func (w *Writer) writeStream(s *stream, b []byte) error {
	s.pending = append(s.pending, b...)

	complete, trailing := splitIncompleteUTF8(s.pending)
	defer func() { s.pending = trailing }()

	if len(complete) != 0 {
		err := w.writeEvent(s.kind, complete)
		if err != nil {
			return fmt.Errorf("record.writeStream: %w", err)
		}
	}

	return nil
}

// flush emits whatever is left in s.pending, unconditionally.
func (w *Writer) flush(s *stream) error {
	if len(s.pending) == 0 {
		return nil
	}

	err := w.writeEvent(s.kind, s.pending)
	if err != nil {
		return fmt.Errorf("record.flush: %w", err)
	}

	s.pending = nil
	return nil
}

// --- Alt katman: serileştirme + yazma. mu TUTULUYOR OLMALI. ---

// writeEvent appends one event line: [<göreli saniye>,"<kind>","<data>"].
func (w *Writer) writeEvent(kind string, data []byte) error {
	t := time.Since(w.start).Seconds()
	line, err := json.Marshal([]any{t, kind, string(data)})
	if err != nil {
		return fmt.Errorf("record.writeEvent: %w", err)
	}

	_, err = w.w.Write(append(line, '\n'))
	if err != nil {
		return fmt.Errorf("record.writeEvent: %w", err)
	}

	return nil
}

// splitIncompleteUTF8 splits b into the part that ends on a complete UTF-8
// boundary and a trailing partial rune (at most 3 bytes).
func splitIncompleteUTF8(b []byte) (complete, trailing []byte) {
	for index := len(b) - 1; index >= 0 && len(b)-index <= utf8.UTFMax; index-- {
		if utf8.RuneStart(b[index]) {
			if utf8.FullRune(b[index:]) {
				return b, nil
			}
			return b[:index], b[index:]
		}
	}

	return b, nil
}
