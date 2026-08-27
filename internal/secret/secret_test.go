package secret

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSealUnsealRoundTrip(t *testing.T) {
	box, err := Init(filepath.Join(t.TempDir(), "secret.key"))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	const plain = "s3rvis-hesabı-parolası"

	sealed, err := box.Seal(plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if strings.Contains(sealed, plain) {
		t.Fatal("mühürlü değer düz metni içeriyor")
	}

	got, err := box.Unseal(sealed)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if got != plain {
		t.Errorf("Unseal = %q, beklenen %q", got, plain)
	}
}

// Aynı düz metin iki kez mühürlenince FARKLI çıktı vermeli: nonce taze
// olmazsa aynı parola aynı şifreli metni üretir ve "iki kullanıcının
// parolası aynı" bilgisi veritabanından okunabilir hale gelir.
func TestSealIsNotDeterministic(t *testing.T) {
	box, err := Init(filepath.Join(t.TempDir(), "secret.key"))
	if err != nil {
		t.Fatal(err)
	}

	a, err := box.Seal("aynı-parola")
	if err != nil {
		t.Fatal(err)
	}
	b, err := box.Seal("aynı-parola")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("iki mühürleme aynı çıktıyı verdi — nonce tekrar kullanılıyor")
	}
}

// GCM kimlik doğrulamalı: kurcalanmış değer sessizce yanlış düz metin
// üretmemeli.
func TestUnsealRejectsTamperedValue(t *testing.T) {
	box, err := Init(filepath.Join(t.TempDir(), "secret.key"))
	if err != nil {
		t.Fatal(err)
	}

	sealed, err := box.Seal("orijinal")
	if err != nil {
		t.Fatal(err)
	}

	// Son karakteri değiştir (base64 alfabesinde kal).
	tampered := sealed[:len(sealed)-1]
	if sealed[len(sealed)-1] == 'A' {
		tampered += "B"
	} else {
		tampered += "A"
	}

	if _, err := box.Unseal(tampered); !errors.Is(err, ErrNotSealed) {
		t.Fatalf("kurcalanmış değer için hata = %v, beklenen ErrNotSealed", err)
	}
	if _, err := box.Unseal("bu base64 bile degil!!"); !errors.Is(err, ErrNotSealed) {
		t.Fatal("bozuk girdi kabul edildi")
	}
}

// Başka anahtarla mühürlenmiş değer açılamamalı.
func TestUnsealRejectsForeignKey(t *testing.T) {
	dir := t.TempDir()
	a, err := Init(filepath.Join(dir, "a.key"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Init(filepath.Join(dir, "b.key"))
	if err != nil {
		t.Fatal(err)
	}

	sealed, err := a.Seal("gizli")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Unseal(sealed); !errors.Is(err, ErrNotSealed) {
		t.Fatalf("yabancı anahtarla açıldı: %v", err)
	}
}

func TestInitRefusesToOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	if _, err := Init(path); err != nil {
		t.Fatal(err)
	}
	// İkinci Init var olan anahtarı EZMEMELİ: ezerse o anahtarla
	// mühürlenmiş her sır kalıcı olarak okunamaz hale gelirdi.
	if _, err := Init(path); err == nil {
		t.Fatal("Init var olan anahtarın üstüne yazdı")
	}
}

func TestLoadRejectsLoosePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	if _, err := Init(path); err != nil {
		t.Fatal(err)
	}

	// Anahtarı herkesin okuyabileceği hale getir.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("herkesin okuyabildiği anahtar kabul edildi")
	}
	if !strings.Contains(err.Error(), "readable") {
		t.Errorf("hata sebebi söylemeli; gelen: %v", err)
	}

	// Doğru izinde açılmalı.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("0600 anahtar reddedildi: %v", err)
	}
}

// Init ile yazılan anahtar, Load ile açılıp AYNI sırları çözebilmeli:
// süreç yeniden başladığında sırlar okunabilir kalmalı.
func TestInitThenLoadCanUnseal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")

	first, err := Init(path)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := first.Seal("kalıcı-sır")
	if err != nil {
		t.Fatal(err)
	}

	second, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, err := second.Unseal(sealed)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if got != "kalıcı-sır" {
		t.Errorf("got %q", got)
	}
}
