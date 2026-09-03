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

// S1.1 test tablosu — docs/history/postern-PLAN.md'deki 5 senaryo + olmayan config dosyası.
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
		Database: DatabaseConfig{DSN: "postgres://postern@localhost:5432/postern?sslmode=disable"},
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
			name:        "database.dsn bos hata",
			mutate:      func(c *Config) { c.Database.DSN = "" },
			wantErr:     true,
			errContains: "database.dsn",
		},
		{
			name:        "recording.dir bos hata",
			mutate:      func(c *Config) { c.Recording.Dir = "" },
			wantErr:     true,
			errContains: "recording.dir",
		},
		{
			// OIDC grubu kendi içinde ya tam ya hiç: yarım yapılandırma
			// sessizce "çalışıyor görünür" (public key yolu işler,
			// linkler asla üretilmez).
			name: "yarim oidc yapilandirmasi hata",
			mutate: func(c *Config) {
				c.OIDC.IssuerURL = "https://idp.example/realms/postern"
			},
			wantErr:     true,
			errContains: "oidc.client_id",
		},
		{
			// ⚠️ OIDC, HTTP yüzeyine muhtaç: /auth/callback o
			// dinleyicide karşılanıyor. Tersi DEĞİL — panel tek başına
			// ayakta durabilir, bir sonraki vaka onu sınıyor.
			name: "http'siz tam oidc hata",
			mutate: func(c *Config) {
				c.OIDC.IssuerURL = "https://idp.example/realms/postern"
				c.OIDC.ClientID = "postern"
				c.HTTP.Addr = ""
				c.HTTP.ExternalURL = ""
			},
			wantErr:     true,
			errContains: "callback has nowhere to land",
		},
		{
			// Ürünün asıl hedefi: dizini olan ama kimlik sağlayıcısı
			// OLMAYAN kurum paneli çalıştırabilmeli. Eskiden bu
			// yapılandırma reddediliyordu ve postern'in yönetilebilir
			// hâli bir Keycloak kurmaya bağlıydı.
			name: "oidc'siz panel gecerli",
			mutate: func(c *Config) {
				c.OIDC = OIDCConfig{}
				c.HTTP.Addr = "127.0.0.1:8088"
				c.HTTP.ExternalURL = "https://bastion.example"
			},
			wantErr: false,
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

	content := fmt.Sprintf(`listen:
  addr: ":2222"
host_key: %s
ca:
  key_file: %s
database:
  dsn: postgres://postern@localhost:5432/postern?sslmode=disable
recording:
  dir: recordings
`, absHost, absCA)

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

// writeConfigWithDSN, verilen dsn satırıyla geçerli bir config dosyası
// yazar ve yolunu döner. Anahtar dosyaları gerçek olmalı: Load
// varlıklarını sınıyor.
func writeConfigWithDSN(t *testing.T, dsn string) string {
	t.Helper()

	absHost, err := filepath.Abs("testdata/keys/host_ed25519")
	if err != nil {
		t.Fatal(err)
	}
	absCA, err := filepath.Abs("testdata/keys/ca_ed25519")
	if err != nil {
		t.Fatal(err)
	}

	content := fmt.Sprintf(`listen:
  addr: ":2222"
host_key: %s
ca:
  key_file: %s
database:
  dsn: %s
recording:
  dir: recordings
`, absHost, absCA, dsn)

	cfgPath := filepath.Join(t.TempDir(), "postern.yaml")
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

// database.dsn bir DOSYA YOLU DEĞİL: göreli görünse bile config
// dizinine göre çözülmemeli.
//
// Bu testin sebebi somut: SQLite döneminde bu alan gerçekten bir yoldu
// ve Load onu filepath.Join'liyordu. O davranış geride kalırsa
// "host=... user=..." biçimindeki bir bağlantı dizesi sessizce
// bozulurdu.
func TestLoadDoesNotResolveDSNAsPath(t *testing.T) {
	const raw = "host=db.local user=postern dbname=postern sslmode=verify-full"

	cfg, err := Load(writeConfigWithDSN(t, raw))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Database.DSN != raw {
		t.Errorf("DSN değişmiş: %q, beklenen %q", cfg.Database.DSN, raw)
	}
}

// POSTERN_DATABASE_DSN, config dosyasındaki değerin ÜSTÜNE yazar.
//
// Yön önemli: parolayı dosyada tutmamak istenen davranış olduğu için
// ortamdan gelen kazanmalı. Ters yönde çalışsaydı ortam değişkeni
// yalnızca alan boşken işe yarardı ve amacını kaçırırdı.
func TestDatabaseDSNEnvOverridesFile(t *testing.T) {
	cfgPath := writeConfigWithDSN(t,
		"postgres://dosyadan@localhost:5432/postern?sslmode=disable")

	const fromEnv = "postgres://ortamdan@db.local:5432/postern?sslmode=verify-full"
	t.Setenv(DatabaseDSNEnv, fromEnv)

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Database.DSN != fromEnv {
		t.Errorf("DSN = %q, ortamdan gelen %q bekleniyordu", cfg.Database.DSN, fromEnv)
	}
}

// Ortam değişkeni BOŞSA dosyadaki değer korunmalı: boş bir değişken
// "burayı sil" demek değil, "ayarlamadım" demek.
func TestEmptyDatabaseDSNEnvKeepsFileValue(t *testing.T) {
	const fromFile = "postgres://dosyadan@localhost:5432/postern?sslmode=disable"

	cfgPath := writeConfigWithDSN(t, fromFile)
	t.Setenv(DatabaseDSNEnv, "")

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Database.DSN != fromFile {
		t.Errorf("DSN = %q, dosyadaki %q korunmalıydı", cfg.Database.DSN, fromFile)
	}
}

// ⚠️ YAPILANDIRMA HATALARI SIR SIZDIRMAMALI.
//
// Ölçülmüş bir sızıntının regresyon testi: goccy/go-yaml ayrıştırma
// hatasına KAYNAK SATIRLARINI ekliyor ve config'in kaynak satırlarında
// veritabanı parolası ile OIDC istemci sırrı var. Bu hata açılışta
// stderr'e düşüyor — oradan journald'a, log toplayıcıya, CI çıktısına
// ve destek paketine.
func TestConfigErrorsDoNotEchoSecrets(t *testing.T) {
	const (
		dbPassword   = "SUPER-SECRET-PW"
		clientSecret = "OIDC-CLIENT-SECRET-XYZ"
	)

	content := `listen:
  addr: ":2222"
database:
  dsn: postgres://postern:` + dbPassword + `@db/postern?sslmode=disable
oidc:
  client_secret: ` + clientSecret + `
bozuk: [
`
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(p)
	if err == nil {
		t.Fatal("bozuk YAML kabul edildi")
	}

	for _, secret := range []string{dbPassword, clientSecret} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("SIR HATA METNİNDE SIZDI (%s):\n%v", secret, err)
		}
	}

	// Mesaj yine de teşhis edilebilir olmalı: dosya adı geçmeli.
	if !strings.Contains(err.Error(), "c.yaml") {
		t.Errorf("hata dosyayı adlandırmıyor: %v", err)
	}
}

// ⚠️ HTTPS kuralı TERMİNALE değil, WEB YÜZEYİNİN TAMAMINA bağlı olmalı.
//
// Kural eskiden yalnızca terminal_enabled iken uygulanıyordu. Ama
// terminal kapalıyken de aynı kaynaktan oturum çerezi, OIDC kod
// değişimi, admin API'si, denetim kaydı ve oturum kayıtlarının tamamı
// servis ediliyor. Terminalin kapalı olması bu yüzeyi güvenli yapmıyor,
// yalnızca bir parçasını kaldırıyor.
func TestPlainHTTPExternalURLIsRefusedEvenWithoutTerminal(t *testing.T) {
	base := func() Config {
		c := validConfig()
		c.OIDC = OIDCConfig{IssuerURL: "https://idp.local", ClientID: "postern"}
		c.HTTP = HTTPConfig{Addr: ":8088", ExternalURL: "http://bastion.local"}
		return c
	}

	t.Run("terminal KAPALI, duz http reddedilir", func(t *testing.T) {
		c := base()
		c.HTTP.TerminalEnabled = false
		if err := c.Validate(); err == nil {
			t.Error("terminal kapalıyken düz HTTP kabul edildi — oturum çerezi, " +
				"admin API'si ve kayıtlar ağda açık gider")
		}
	})

	t.Run("https kabul edilir", func(t *testing.T) {
		c := base()
		c.HTTP.ExternalURL = "https://bastion.local"
		if err := c.Validate(); err != nil {
			t.Errorf("https reddedildi: %v", err)
		}
	})

	// ⚠️ "127.1" gibi kısaltmalar BİLEREK loopback sayılmıyor:
	// net.ParseIP onları reddediyor ve bu kontrol düz HTTP'ye İZİN
	// VERDİĞİ için katı olmak doğru yön. Naif bir eşleşme, aynı
	// kısaltmaların SSRF filtrelerini atlatmasıyla aynı sınıf hatadır.
	t.Run("loopback gelistirme icin serbest", func(t *testing.T) {
		for _, u := range []string{"http://localhost:8088", "http://127.0.0.1:8088", "http://[::1]:8088"} {
			c := base()
			c.HTTP.ExternalURL = u
			if err := c.Validate(); err != nil {
				t.Errorf("loopback %q reddedildi: %v", u, err)
			}
		}
	})
}

// ⚠️ İKİ KAPI DA KAPALI OLAMAZ. public_key_login kapatılıp OIDC de
// yapılandırılmamışsa bastion açılır, dinler ve HİÇ KİMSEYİ içeri
// almaz — çalışır görünen ama kimsenin fark etmediği bir kilitlenme.
func TestPublicKeyOffWithoutBrowserLoginIsRefused(t *testing.T) {
	off := false

	c := validConfig()
	c.Auth = AuthConfig{PublicKeyLogin: &off}

	err := c.Validate()
	if err == nil {
		t.Fatal("iki kapı da kapalıyken yapılandırma kabul edildi")
	}
	// Mesaj SEBEBİ söylemeli: "invalid config" diyen bir hata,
	// operatöre neyi düzelteceğini söylemiyor.
	if !strings.Contains(err.Error(), "nobody could sign in") {
		t.Errorf("hata sebebi anlatmıyor: %v", err)
	}

	// Tarayıcı girişi varken AYNI ayar geçerli olmalı.
	c.HTTP = HTTPConfig{Addr: ":8088", ExternalURL: "https://postern.example"}
	c.OIDC = OIDCConfig{IssuerURL: "https://idp.example", ClientID: "postern"}
	if err := c.Validate(); err != nil {
		t.Errorf("OIDC varken reddedildi: %v", err)
	}
}

// Yazılmamış alan anahtar girişini KAPATMAMALI: mevcut kurulumlar
// yükseltmeden sonra dışarıda kalırdı.
func TestPublicKeyLoginDefaultsOn(t *testing.T) {
	if !(AuthConfig{}).PublicKeyLoginEnabled() {
		t.Error("varsayılan kapalı — mevcut kurulumları kilitler")
	}
	on, off := true, false
	if !(AuthConfig{PublicKeyLogin: &on}).PublicKeyLoginEnabled() {
		t.Error("true okunmadı")
	}
	if (AuthConfig{PublicKeyLogin: &off}).PublicKeyLoginEnabled() {
		t.Error("false okunmadı")
	}
}
