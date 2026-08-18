package ca

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestInit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca_ed25519")

	c, err := Init(path)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("anahtar dosyası oluşmamış: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("izin = %04o, beklenen 0600 — CA anahtarı bütün filoya erişim demektir", perm)
	}

	if c.PublicKey() == nil {
		t.Fatal("PublicKey nil")
	}
	if got := c.PublicKey().Type(); got != ssh.KeyAlgoED25519 {
		t.Errorf("anahtar tipi = %q, beklenen %q", got, ssh.KeyAlgoED25519)
	}

	line := c.AuthorizedKey()
	if !strings.HasPrefix(line, ssh.KeyAlgoED25519+" ") {
		t.Errorf("AuthorizedKey = %q, authorized_keys satırı olmalı", line)
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err != nil {
		t.Errorf("AuthorizedKey çözümlenemedi: %v", err)
	}
}

// ⚠️ Init idempotent DEĞİLDİR: var olan CA anahtarının üzerine yazmak,
// dağıtılmış bütün hedeflerdeki TrustedUserCAKeys satırını geçersiz kılar
// ve her hedefe elle gitmeyi gerektirir. Sessizce ezmektense patlasın.
func TestInitRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca_ed25519")

	first, err := Init(path)
	if err != nil {
		t.Fatalf("ilk Init: %v", err)
	}

	if _, err := Init(path); err == nil {
		t.Fatal("ikinci Init başarılı oldu — var olan CA anahtarı eziliyor")
	}

	// Dosya bozulmamış olmalı: eski anahtar hâlâ yüklenebiliyor.
	again, err := Load(path)
	if err != nil {
		t.Fatalf("başarısız Init sonrası Load: %v", err)
	}
	if !equalKeys(first.PublicKey(), again.PublicKey()) {
		t.Error("başarısız Init dosyayı değiştirmiş")
	}
}

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca_ed25519")

	created, err := Init(path)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !equalKeys(created.PublicKey(), loaded.PublicKey()) {
		t.Error("Load farklı bir anahtar döndürdü")
	}
}

// İzin kuralı bir DEĞER eşitliği değil, bir GÜVENLİK ÖZELLİĞİDİR: grubun ve
// diğerlerinin hiçbir erişimi olmamalı. Sahibin bitleri bizi ilgilendirmez —
// OpenSSH'ın kontrolü de budur (st_mode & 077).
//
// Bu anahtar her hedefe girebilen sertifikalar basar; sızması bütün filoya
// kök erişim vermekle eşdeğerdir (plan Ek B).
func TestLoadPermissionRule(t *testing.T) {
	cases := []struct {
		mode   os.FileMode
		accept bool
	}{
		{0o600, true},  // olağan
		{0o400, true},  // salt okunur — daha da sıkı, reddedilmemeli
		{0o700, true},  // çalıştırma biti anlamsız ama sahibe ait: kural ihlali yok
		{0o644, false}, // dünya okuyabiliyor
		{0o660, false}, // grup okuyabiliyor
		{0o604, false}, // yalnızca "diğerleri" biti bile yeter
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("%04o", tc.mode), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ca_ed25519")
			if _, err := Init(path); err != nil {
				t.Fatalf("Init: %v", err)
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}

			_, err := Load(path)
			if tc.accept && err != nil {
				t.Fatalf("%04o reddedildi ama grup/diğer erişimi yok: %v", tc.mode, err)
			}
			if !tc.accept && err == nil {
				t.Fatalf("%04o kabul edildi — grup ya da diğerleri okuyabiliyor", tc.mode)
			}
		})
	}
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()

	t.Run("olmayan dosya", func(t *testing.T) {
		path := filepath.Join(dir, "yok_boyle_dosya")
		if _, err := Load(path); err == nil {
			t.Fatal("hata bekleniyordu")
		} else if !strings.Contains(err.Error(), "yok_boyle_dosya") {
			t.Errorf("hata dosya yolunu söylemeli; gelen: %v", err)
		}
	})

	t.Run("bozuk anahtar", func(t *testing.T) {
		path := filepath.Join(dir, "bozuk")
		if err := os.WriteFile(path, []byte("bu bir anahtar degil"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatal("bozuk anahtar dosyası kabul edildi")
		}
	})
}

func equalKeys(a, b ssh.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	return string(a.Marshal()) == string(b.Marshal())
}
