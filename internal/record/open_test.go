package record

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Store.Open, kayıt kökünün DIŞINDAKİ hiçbir yolu açmamalı.
//
// Bu testin gerekçesi doğrudan tehdit modeli: recording_path bir
// veritabanı sütunu ve oraya yazabilen her yol, yetkili bir admin
// oturumu üzerinden keyfi dosya okumaya dönüşürdü. Bariz hedef CA özel
// anahtarı.
func TestOpenRefusesPathsOutsideRoot(t *testing.T) {
	root := t.TempDir()
	s, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}

	// Kökün DIŞINDA gerçek bir dosya: reddin "dosya yok"tan değil
	// kapsama kontrolünden geldiğini kanıtlamak için var olmalı.
	outside := filepath.Join(t.TempDir(), "ca_ed25519")
	if err := os.WriteFile(outside, []byte("SECRET KEY"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Kökün İÇİNDE geçerli bir kayıt: testin kontrol grubu.
	inside := filepath.Join(root, "2026-08-27", "abc123.cast")
	if err := os.MkdirAll(filepath.Dir(inside), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inside, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("kok icindeki kayit acilir", func(t *testing.T) {
		f, err := s.Open("abc123", inside)
		if err != nil {
			t.Fatalf("geçerli kayıt açılamadı: %v", err)
		}
		f.Close()
	})

	refused := map[string]string{
		"mutlak dis yol":      outside,
		"gorece disari cikis": filepath.Join(root, "..", filepath.Base(filepath.Dir(outside)), "ca_ed25519"),
		"kokun kendisi":       root,
		"etc shadow":          "/etc/shadow",
		"nokta nokta zinciri": filepath.Join(root, "..", "..", "..", "etc", "passwd"),
	}
	for name, p := range refused {
		t.Run(name, func(t *testing.T) {
			f, err := s.Open("abc123", p)
			if err == nil {
				f.Close()
				t.Fatalf("kök dışındaki yol açıldı: %s", p)
			}
			if !errors.Is(err, ErrOutsideRoot) {
				t.Errorf("hata = %v, ErrOutsideRoot bekleniyordu", err)
			}
		})
	}
}

// Geçersiz bir session id, yol ne olursa olsun reddedilmeli: iki kontrol
// birbirinin yedeği.
func TestOpenRejectsInvalidSessionID(t *testing.T) {
	root := t.TempDir()
	s, _ := NewStore(root)

	inside := filepath.Join(root, "x.cast")
	os.WriteFile(inside, []byte("{}\n"), 0o600)

	for _, id := range []string{"", "../../etc/passwd", "a/b", "a b", "a.b", "a;b"} {
		if f, err := s.Open(id, inside); err == nil {
			f.Close()
			t.Errorf("geçersiz session id kabul edildi: %q", id)
		}
	}
}

// Kaydı hiç olmayan oturum ErrNotRecorded vermeli — "dosya yok"tan
// ayrı bir durum, çünkü panelde farklı gösterilecek.
func TestOpenReportsMissingRecordingDistinctly(t *testing.T) {
	s, _ := NewStore(t.TempDir())

	_, err := s.Open("abc123", "")
	if !errors.Is(err, ErrNotRecorded) {
		t.Errorf("hata = %v, ErrNotRecorded bekleniyordu", err)
	}
}

// Göreli kök (testlerde ve bazı yapılandırmalarda oluyor) kapsama
// kontrolünü bozmamalı: filepath.Rel biri mutlak biri göreli olduğunda
// hata verir, o yüzden Open iki tarafı da mutlaklaştırıyor.
func TestOpenHandlesRelativeRoot(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(cwd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	s, err := NewStore("recordings")
	if err != nil {
		t.Fatal(err)
	}

	inside := filepath.Join(dir, "recordings", "abc123.cast")
	if err := os.WriteFile(inside, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if f, err := s.Open("abc123", inside); err != nil {
		t.Errorf("göreli kökle mutlak kayıt yolu açılamadı: %v", err)
	} else {
		f.Close()
	}

	outside := filepath.Join(dir, "elsewhere.cast")
	os.WriteFile(outside, []byte("x"), 0o600)
	if f, err := s.Open("abc123", outside); err == nil {
		f.Close()
		t.Error("göreli kökle kök dışı yol açıldı")
	} else if !strings.Contains(err.Error(), "outside") {
		t.Errorf("hata = %v, kapsama reddi bekleniyordu", err)
	}
}

// Kökün İÇİNE konmuş, dışarıyı gösteren bir sembolik bağ da
// reddedilmeli.
//
// Metinsel kapsama kontrolü bunu KAÇIRIRDI: yol kökün altında görünür
// ama açtığı dosya dışarıda. Saldırgan senaryosu dar (kayıt dizinine
// yazma erişimi gerekiyor) ama kapsama kontrolünün anlamı tam olarak
// budur.
func TestOpenRefusesSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	s, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}

	secret := filepath.Join(t.TempDir(), "ca_ed25519")
	if err := os.WriteFile(secret, []byte("SECRET KEY"), 0o600); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(root, "abc123.cast")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("sembolik bağ kurulamadı: %v", err)
	}

	f, err := s.Open("abc123", link)
	if err == nil {
		defer f.Close()
		data, _ := os.ReadFile(link)
		t.Fatalf("kökün içindeki bağ dışarıyı gösteriyordu ve açıldı; içerik: %q", data)
	}
	if !errors.Is(err, ErrOutsideRoot) {
		t.Errorf("hata = %v, ErrOutsideRoot bekleniyordu", err)
	}
}
