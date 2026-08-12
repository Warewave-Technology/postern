package record

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreCreate(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")

	s, err := NewStore(root)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	f, path, err := s.Create("abc123")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer f.Close()

	if !strings.HasSuffix(path, "abc123.cast") {
		t.Errorf("yol = %q, <sessionID>.cast ile bitmeli", path)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("dosya oluşmamış: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("dosya izni = %04o, beklenen 0600 (kayıt oturum içeriğidir)", perm)
	}

	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("dizin izni = %04o, beklenen 0700", perm)
	}
}

// Aynı ID ikinci kez gelirse var olan kaydın üzerine YAZILMAMALI.
func TestStoreCreateRefusesOverwrite(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "recordings"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	f, _, err := s.Create("ayni-id")
	if err != nil {
		t.Fatalf("ilk Create: %v", err)
	}
	f.Close()

	if _, _, err := s.Create("ayni-id"); err == nil {
		t.Fatal("aynı ID ikinci kez kabul edildi — var olan kayıt ezilir")
	}
}

// sessionID dosya adına giriyor: yol kaçışı denemeleri reddedilmeli
// (plan Ek B: "Dosya yolları kullanıcı girdisinden türetilmiyor").
func TestStoreCreateRejectsUnsafeID(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "recordings"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	for _, id := range []string{
		"../kacis",
		"a/b",
		"",
		".",
		"bosluk var",
		"tirnak'lı",
	} {
		t.Run(id, func(t *testing.T) {
			if f, path, err := s.Create(id); err == nil {
				f.Close()
				t.Fatalf("güvensiz ID kabul edildi: %q → %q", id, path)
			}
		})
	}
}

func TestNewSessionID(t *testing.T) {
	seen := make(map[string]bool)

	for i := 0; i < 100; i++ {
		id, err := NewSessionID()
		if err != nil {
			t.Fatalf("NewSessionID: %v", err)
		}
		if len(id) < 16 {
			t.Fatalf("ID çok kısa: %q", id)
		}
		if strings.ContainsAny(id, "/\\. ") {
			t.Fatalf("ID dosya adında güvenli değil: %q", id)
		}
		if seen[id] {
			t.Fatalf("ID tekrar etti: %q", id)
		}
		seen[id] = true
	}
}
