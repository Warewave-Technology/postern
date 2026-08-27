package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Gerçek (parse edilebilir) test anahtarları. Private yarıları üretildikleri
// anda silindi; burada yalnızca public satırlar yaşıyor — sır değiller.
// Validate anahtar sözdizimini denetlediği için sahte string kullanılamaz.
const ()

// S1.1 test tablosu — postern-PLAN.md'deki 5 senaryo + olmayan config dosyası.
// Bu tablo Load/Validate implementasyonunun sözleşmesidir: hepsi yeşile
// dönünce S1.1'in test ayağı bitmiş demektir.
func TestLoad(t *testing.T) {
	cases := []struct {
		name        string
		file        string
		wantErr     bool
		errContains string // boşsa yalnızca err != nil kontrol edilir
	}{
		{
			name: "gecerli config yukleniyor",
			file: "testdata/valid.yaml",
		},
		{
			// Dosya adı bilinçli olarak "hostkey" (alt çizgisiz): Load hatayı
			// dosya yoluyla sarmaladığında "host_key" beklentisi yol üzerinden
			// yanlışlıkla geçmesin, gerçekten Validate'ten gelsin.
			name:        "host_key eksikse hata",
			file:        "testdata/missing_hostkey.yaml",
			wantErr:     true,
			errContains: "host_key",
		},
		{
			name:        "olmayan anahtar dosyasi hata",
			file:        "testdata/missing_host_key_file.yaml",
			wantErr:     true,
			errContains: "does_not_exist", // hata mesajı yolu söylemeli
		},
		{
			name:    "bozuk yaml hata",
			file:    "testdata/broken.yaml",
			wantErr: true,
		},
		{
			name:        "olmayan config dosyasi hata",
			file:        "testdata/boyle_bir_dosya_yok.yaml",
			wantErr:     true,
			errContains: "boyle_bir_dosya_yok.yaml",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(tc.file)

			if tc.wantErr {
				if err == nil {
					t.Fatal("hata bekleniyordu, nil geldi")
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("hata %q içermeli; gelen: %v", tc.errContains, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("beklenmeyen hata: %v", err)
			}
			if cfg == nil {
				t.Fatal("hata yokken cfg nil olmamalı")
			}
		})
	}
}

// Geçerli config'te alanların doğru geldiğini alan alan kontrol eder.
// testdata/valid.yaml'daki değerlere bağlıdır — orayı değiştirirsen
// burayı da güncelle.
// SÖZLEŞMENİN BEKÇİSİ: kimlik verisi config'e geri sızamaz.
//
// yaml.Strict() bilinmeyen alanları reddediyor; bu test, birinin YAML'a
// "users:" yazıp "neden girmiyor" diye saatler harcamasını, açılışta net
// bir hataya çevirir. Alanları şemaya geri ekleyen biri de önce bu testi
// silmek zorunda kalır — ki tam olarak istenen sürtünme bu.
func TestLoadRejectsIdentityData(t *testing.T) {
	for _, field := range []string{"targets", "roles", "users"} {
		t.Run(field, func(t *testing.T) {
			content := "listen:\n  addr: \":2222\"\n" + field + ": []\n"
			path := filepath.Join(t.TempDir(), "old.yaml")
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}

			_, err := Load(path)
			if err == nil {
				t.Fatalf("%q alanı kabul edildi — kimlik verisi config'e geri sızmış", field)
			}
			if !strings.Contains(err.Error(), field) {
				t.Errorf("hata suçlu alanı (%q) söylemeli; gelen: %v", field, err)
			}
		})
	}
}

func TestLoadValidFields(t *testing.T) {
	cfg, err := Load("testdata/valid.yaml")
	if err != nil {
		t.Fatalf("valid.yaml yüklenemedi: %v", err)
	}

	if got, want := cfg.Listen.Addr, ":2222"; got != want {
		t.Errorf("Listen.Addr = %q, beklenen %q", got, want)
	}
	if cfg.Recording.RecordInput {
		t.Error("Recording.RecordInput varsayılan false olmalı (şifre yazımı da girdidir)")
	}

	// Yol çözümleme sözleşmesi: Load göreli yolları config dosyasının
	// dizinine göre çözmüş olmalı. Çözülmüş yol, testin CWD'sinden
	// bakıldığında da var olmalı.
	if _, err := os.Stat(cfg.HostKey); err != nil {
		t.Errorf("HostKey yolu çözülmemiş görünüyor (%q): %v", cfg.HostKey, err)
	}
}

// validConfig, Validate'in dosya sistemine dokunan alanlarını gerçek
// testdata yollarıyla besleyen geçerli bir Config üretir (yollar test
// CWD'sine göre, Load'un çözümlemesinden geçmiş kabul edilir). Her subtest
// kendi kopyasını alıp tek bir şeyi bozar.
func validConfig() Config {
	return Config{
		Listen:   ListenConfig{Addr: ":2222"},
		HostKey:  "testdata/keys/host_ed25519",
		CA:       CAConfig{KeyFile: "testdata/keys/ca_ed25519"},
		Database: DatabaseConfig{Path: "testdata/postern.db"},
		// Dizinin var olması aranmıyor, dolu olması aranıyor: kayıt dizinini
		// Store ilk oturumda kendisi açar (S1.8).
		Recording: RecordingConfig{Dir: "testdata/recordings"},
	}
}

// Validate sözleşmesini Load'dan bağımsız, alan alan sabitler.
// Genel kural: hata mesajı SUÇLUYU söylemeli — alan adı, target adı ya da yol.
func TestValidate(t *testing.T) {
	cases := []struct {
		name        string
		mutate      func(*Config)
		wantErr     bool
		errContains string
	}{
		{
			name:   "gecerli config gecer",
			mutate: func(c *Config) {},
		},
		{
			// recording.dir boşken sunucu anlaşılmaz bir "mkdir :" hatasıyla
			// ölüyordu. Config katmanında yakalanırsa operatör hangi alanı
			// dolduracağını öğrenir.
			name:        "database.path bos hata",
			mutate:      func(c *Config) { c.Database.Path = "" },
			wantErr:     true,
			errContains: "database.path",
		},
		{
			name:        "recording.dir bos hata",
			mutate:      func(c *Config) { c.Recording.Dir = "" },
			wantErr:     true,
			errContains: "recording.dir",
		},
		{
			// OOB ya tam ya hiç: yarım yapılandırma sessizce "çalışıyor
			// görünür" (public key yolu işler, linkler asla üretilmez).
			name: "yarim oidc yapilandirmasi hata",
			mutate: func(c *Config) {
				c.OIDC.IssuerURL = "https://idp.example/realms/postern"
			},
			wantErr:     true,
			errContains: "http.addr",
		},
		{
			name: "tam oidc yapilandirmasi gecer",
			mutate: func(c *Config) {
				c.OIDC.IssuerURL = "https://idp.example/realms/postern"
				c.OIDC.ClientID = "postern"
				c.HTTP.Addr = ":8088"
				c.HTTP.ExternalURL = "https://bastion.example:8088"
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)
			err := cfg.Validate()

			if tc.wantErr {
				if err == nil {
					t.Fatal("hata bekleniyordu, nil geldi")
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("hata %q içermeli; gelen: %v", tc.errContains, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("beklenmeyen hata: %v", err)
			}
		})
	}
}

// Mutlak yollar çözümlemeden OLDUĞU GİBİ geçmeli.
func TestLoadAbsolutePaths(t *testing.T) {
	absHost, err := filepath.Abs("testdata/keys/host_ed25519")
	if err != nil {
		t.Fatal(err)
	}
	absCA, err := filepath.Abs("testdata/keys/ca_ed25519")
	if err != nil {
		t.Fatal(err)
	}

	absDB := filepath.Join(t.TempDir(), "postern.db")

	content := fmt.Sprintf(`listen:
  addr: ":2222"
host_key: %s
ca:
  key_file: %s
database:
  path: %s
recording:
  dir: recordings
`, absHost, absCA, absDB)

	cfgPath := filepath.Join(t.TempDir(), "abs.yaml")
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("mutlak yollu config yüklenemedi: %v", err)
	}
	if cfg.CA.KeyFile != absCA {
		t.Errorf("CA.KeyFile değişmiş: %q, beklenen %q", cfg.CA.KeyFile, absCA)
	}
	if cfg.Database.Path != absDB {
		t.Errorf("Database.Path değişmiş: %q, beklenen %q", cfg.Database.Path, absDB)
	}
	if cfg.HostKey != absHost {
		t.Errorf("HostKey değişmiş: %q, beklenen %q", cfg.HostKey, absHost)
	}
}

// terminal_enabled iki şarta bağlı: OIDC yapılandırması ve HTTPS.
// İkisi de "sonra hallederiz" diye atlanabilecek türden olduğu için
// açılışta reddediliyor.
func TestValidateTerminalGuards(t *testing.T) {
	withOIDC := func(c *Config) {
		c.OIDC.IssuerURL = "https://idp.example/realms/postern"
		c.OIDC.ClientID = "postern"
		c.HTTP.Addr = ":8088"
		c.HTTP.ExternalURL = "https://bastion.example:8088"
	}

	cases := []struct {
		name        string
		mutate      func(*Config)
		wantErr     bool
		errContains string
	}{
		{
			name:        "oidc'siz terminal reddedilir",
			mutate:      func(c *Config) { c.HTTP.TerminalEnabled = true },
			wantErr:     true,
			errContains: "terminal_enabled",
		},
		{
			name: "duz http uzerinde terminal reddedilir",
			mutate: func(c *Config) {
				withOIDC(c)
				c.HTTP.ExternalURL = "http://bastion.example:8088"
				c.HTTP.TerminalEnabled = true
			},
			wantErr:     true,
			errContains: "https",
		},
		{
			// Yerel geliştirme: loopback'te düz HTTP serbest.
			name: "loopback'te duz http gecer",
			mutate: func(c *Config) {
				withOIDC(c)
				c.HTTP.ExternalURL = "http://127.0.0.1:8088"
				c.HTTP.TerminalEnabled = true
			},
		},
		{
			name: "https ile terminal gecer",
			mutate: func(c *Config) {
				withOIDC(c)
				c.HTTP.TerminalEnabled = true
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)
			err := cfg.Validate()

			if tc.wantErr {
				if err == nil {
					t.Fatal("hata bekleniyordu, nil geldi")
				}
				if !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("hata %q içermeli; gelen: %v", tc.errContains, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("beklenmeyen hata: %v", err)
			}
		})
	}
}
