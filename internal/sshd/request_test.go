package sshd

import (
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Strateji: payload'ları ssh.Marshal ile üretiyoruz — yani gerçek wire
// formatı, elle byte dizmek yok. Parser doğruysa round-trip (Marshal →
// Parse) orijinali aynen geri vermeli. Bozuk payload'lar için ayrıca
// kısa/çöp girdi denenir.

func TestParsePty(t *testing.T) {
	want := PtyRequest{
		Term:    "xterm-256color",
		Columns: 80,
		Rows:    24,
		Width:   640,
		Height:  480,
		Modes:   "\x01\x00\x00\x00\x03\x00", // opaque; içeriği önemsiz, korunmalı
	}

	got, err := ParsePty(ssh.Marshal(want))
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if got != want {
		t.Fatalf("round-trip bozuldu:\n got  %+v\n want %+v", got, want)
	}
}

func TestParsePtyShort(t *testing.T) {
	// Sadece TERM string'i var, geri kalan alanlar yok → hata.
	short := ssh.Marshal(struct{ Term string }{Term: "xterm"})

	_, err := ParsePty(short)
	if err == nil {
		t.Fatal("kısa payload hata vermeli")
	}
	if !errors.Is(err, ErrShortPayload) {
		t.Fatalf("ErrShortPayload bekl: broker errors.Is'e bakacak; gelen: %v", err)
	}
}

func TestParseWindowChange(t *testing.T) {
	want := WindowChangeRequest{Columns: 120, Rows: 30, Width: 0, Height: 0}

	got, err := ParseWindowChange(ssh.Marshal(want))
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if got != want {
		t.Fatalf("round-trip bozuldu:\n got  %+v\n want %+v", got, want)
	}
}

func TestParseExec(t *testing.T) {
	want := ExecRequest{Command: "cat /etc/hostname"}

	got, err := ParseExec(ssh.Marshal(want))
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if got != want {
		t.Fatalf("round-trip bozuldu:\n got  %q\n want %q", got.Command, want.Command)
	}
}

// exec komutu boş olabilir ("ssh host ”") — bu geçerli, hata değil.
func TestParseExecEmpty(t *testing.T) {
	got, err := ParseExec(ssh.Marshal(ExecRequest{Command: ""}))
	if err != nil {
		t.Fatalf("boş komut geçerli olmalı; gelen hata: %v", err)
	}
	if got.Command != "" {
		t.Fatalf("Command boş olmalı; gelen: %q", got.Command)
	}
}
