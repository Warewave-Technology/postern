package proxy

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// writeCloseRecorder, CloseWrite'ın gerçekten çağrıldığını kanıtlar.
type writeCloseRecorder struct {
	buf        bytes.Buffer
	closeWrite bool
	closeAll   bool
}

func (w *writeCloseRecorder) Write(p []byte) (int, error) { return w.buf.Write(p) }
func (w *writeCloseRecorder) CloseWrite() error           { w.closeWrite = true; return nil }
func (w *writeCloseRecorder) Close() error                { w.closeAll = true; return nil }

// singleWriter=true: dst'ye tek yazıcı var, EOF'ta yarı kapatma yapılmalı.
func TestPipeCopiesAndHalfCloses(t *testing.T) {
	const payload = "merhaba dunya\n"
	dst := &writeCloseRecorder{}

	n, err := pipe(dst, strings.NewReader(payload), true)
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("kopyalanan = %d bayt, beklenen %d", n, len(payload))
	}
	if got := dst.buf.String(); got != payload {
		t.Fatalf("içerik = %q, beklenen %q", got, payload)
	}
	if !dst.closeWrite {
		t.Error("EOF sonrası CloseWrite çağrılmalı (yarı kapalı bağlantı, Ek C.6)")
	}
	if dst.closeAll {
		t.Error("Close çağrılmamalı — ters yöndeki akışı keser")
	}
}

// singleWriter=false: dst'yi başka bir akış da paylaşıyor (down = stdout +
// stderr). Yeteneği olsa bile yarı kapatma YAPILMAMALI — kapatma kararı, o
// kanala yazan herkesin bittiğini bilen koordinatöre (Run) aittir.
func TestPipeSharedWriterSkipsHalfClose(t *testing.T) {
	dst := &writeCloseRecorder{}

	if _, err := pipe(dst, strings.NewReader("cikti\n"), false); err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if dst.buf.String() != "cikti\n" {
		t.Fatalf("içerik = %q", dst.buf.String())
	}
	if dst.closeWrite {
		t.Error("paylaşılan kanalda CloseWrite çağrılmamalı — diğer akış hâlâ yazıyor olabilir")
	}
	if dst.closeAll {
		t.Error("Close hiçbir durumda çağrılmamalı")
	}
}

// CloseWrite'ı olmayan bir hedefe yazarken panik/hata olmamalı.
func TestPipePlainWriter(t *testing.T) {
	var dst bytes.Buffer

	n, err := pipe(&dst, strings.NewReader("abc"), true)
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if n != 3 || dst.String() != "abc" {
		t.Fatalf("n=%d içerik=%q", n, dst.String())
	}
}

func TestIsBenignCloseErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, true},
		{"EOF", io.EOF, true},
		{"closed pipe", io.ErrClosedPipe, true},
		{"sarmalanmis EOF", errors.New("wrap: " + io.EOF.Error()), false}, // metin eşleşmesi YETMEZ
		{"gercek hata", errors.New("connection reset by peer"), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isBenignCloseErr(tc.err); got != tc.want {
				t.Fatalf("isBenignCloseErr(%v) = %v, beklenen %v", tc.err, got, tc.want)
			}
		})
	}
}

// errReader, io.Copy'ye belirli bir hatayı ürettirir.
type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// pipe'ın hata sözleşmesi: gerçek arıza yukarı bildirilir, normal kapanış
// gürültüsü yutulur. İkisini karıştırmak ya arızayı gizler ya da her
// sağlıklı oturum çıkışını hata gibi gösterir.
func TestPipeErrorContract(t *testing.T) {
	t.Run("gercek hata raporlanir", func(t *testing.T) {
		boom := errors.New("connection reset by peer")

		if _, err := pipe(&writeCloseRecorder{}, errReader{err: boom}, true); err == nil {
			t.Fatal("gerçek kopyalama hatası yutuldu")
		} else if !errors.Is(err, boom) {
			t.Fatalf("hata sarmalanmalı; gelen: %v", err)
		}
	})

	t.Run("zararsiz kapanis yutulur", func(t *testing.T) {
		if _, err := pipe(&writeCloseRecorder{}, errReader{err: io.ErrClosedPipe}, true); err != nil {
			t.Fatalf("normal kapanış hata sayılmamalı; gelen: %v", err)
		}
	})
}
