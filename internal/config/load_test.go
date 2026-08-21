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
const (
	testUserPubKey    = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOIPqmYrvP98V3v7Tyn71W5TL4eEQJlROZYGw0yFho9T yigit@warewave.io"
	testTargetHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIcLUQM0UcoZdJVh2EokribDvFZyyNyAVURM/LrCugFM"
)

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
			name:        "cakisan target adi hata",
			file:        "testdata/duplicate_target.yaml",
			wantErr:     true,
			errContains: "web01", // hata mesajı çakışan adı söylemeli
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
func TestLoadValidFields(t *testing.T) {
	cfg, err := Load("testdata/valid.yaml")
	if err != nil {
		t.Fatalf("valid.yaml yüklenemedi: %v", err)
	}

	if got, want := cfg.Listen.Addr, ":2222"; got != want {
		t.Errorf("Listen.Addr = %q, beklenen %q", got, want)
	}
	if got := len(cfg.Targets); got != 2 {
		t.Fatalf("len(Targets) = %d, beklenen 2", got)
	}
	if got, want := cfg.Targets[0].Name, "web01"; got != want {
		t.Errorf("Targets[0].Name = %q, beklenen %q", got, want)
	}
	if got, want := cfg.Targets[1].Name, "db01"; got != want {
		t.Errorf("Targets[1].Name = %q, beklenen %q", got, want)
	}
	if cfg.Recording.RecordInput {
		t.Error("Recording.RecordInput varsayılan false olmalı (şifre yazımı da girdidir)")
	}
	if got := len(cfg.Users); got != 1 {
		t.Fatalf("len(Users) = %d, beklenen 1", got)
	}
	if got := len(cfg.Users[0].PublicKeys); got == 0 {
		t.Error("Users[0].PublicKeys boş olmamalı")
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
		Listen:  ListenConfig{Addr: ":2222"},
		HostKey: "testdata/keys/host_ed25519",
		CA:      CAConfig{KeyFile: "testdata/keys/ca_ed25519"},
		// Dizinin var olması aranmıyor, dolu olması aranıyor: kayıt dizinini
		// Store ilk oturumda kendisi açar (S1.8).
		Recording: RecordingConfig{Dir: "testdata/recordings"},
		Targets: []TargetConfig{
			{Name: "web01", Host: "127.0.0.1", Port: 2201, HostKey: testTargetHostKey},
			{Name: "db01", Host: "127.0.0.1", Port: 2202, HostKey: testTargetHostKey},
		},
		Roles: []RoleConfig{
			{Name: "ops", Targets: []string{"web01", "db01"}},
		},
		Users: []UserConfig{
			{Name: "yigit", OSUser: "yigit", Roles: []string{"ops"}, PublicKeys: []string{testUserPubKey}},
		},
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
			name:        "port 0 gecersiz",
			mutate:      func(c *Config) { c.Targets[0].Port = 0 },
			wantErr:     true,
			errContains: "port",
		},
		{
			name:        "port 65536 gecersiz",
			mutate:      func(c *Config) { c.Targets[0].Port = 65536 },
			wantErr:     true,
			errContains: "port",
		},
		{
			name:        "eksik alan hatasi hangi target oldugunu soyler",
			mutate:      func(c *Config) { c.Targets[1].Host = "" },
			wantErr:     true,
			errContains: "db01",
		},
		{
			name: "cakisan user adi",
			mutate: func(c *Config) {
				c.Users = append(c.Users, UserConfig{Name: "yigit", OSUser: "yigit", PublicKeys: []string{"ssh-ed25519 AAAA-test2"}})
			},
			wantErr:     true,
			errContains: "yigit",
		},
		{
			name:        "public keysiz user",
			mutate:      func(c *Config) { c.Users[0].PublicKeys = nil },
			wantErr:     true,
			errContains: "yigit",
		},
		{
			// Bozuk anahtar auth anında değil, config yüklenirken yakalanmalı.
			// Hata suçluyu (kullanıcıyı) söylemeli.
			name:        "bozuk public key satiri hata",
			mutate:      func(c *Config) { c.Users[0].PublicKeys = []string{"bu bir ssh anahtari degil"} },
			wantErr:     true,
			errContains: "yigit",
		},
		{
			// ⚠️ Yazım hatası olan rol adı SESSİZCE atlanmamalı: kullanıcı
			// hiçbir hedefe giremez ve sebebini kimse anlamaz. Hata rol adını
			// söylemeli ki operatör hangi satırı düzelteceğini bilsin.
			name:        "tanimsiz rol adi hata",
			mutate:      func(c *Config) { c.Users[0].Roles = []string{"opss"} },
			wantErr:     true,
			errContains: "opss",
		},
		{
			// Aynı sebep: rol var olmayan bir hedefi listeliyorsa yetki
			// sessizce boşa düşer.
			name: "rol tanimsiz target'a referans veriyor",
			mutate: func(c *Config) {
				c.Roles[0].Targets = append(c.Roles[0].Targets, "boyle-bir-hedef-yok")
			},
			wantErr:     true,
			errContains: "boyle-bir-hedef-yok",
		},
		{
			name: "cakisan rol adi",
			mutate: func(c *Config) {
				c.Roles = append(c.Roles, RoleConfig{Name: "ops", Targets: []string{"web01"}})
			},
			wantErr:     true,
			errContains: "ops",
		},
		{
			// recording.dir boşken sunucu anlaşılmaz bir "mkdir :" hatasıyla
			// ölüyordu. Config katmanında yakalanırsa operatör hangi alanı
			// dolduracağını öğrenir.
			name:        "recording.dir bos hata",
			mutate:      func(c *Config) { c.Recording.Dir = "" },
			wantErr:     true,
			errContains: "recording.dir",
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

// Mutlak yollar çözümlemeden OLDUĞU GİBİ geçmeli; hiçbir target kaybolmamalı.
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
recording:
  dir: recordings
targets:
  - name: web01
    host: 127.0.0.1
    port: 2201
    host_key: "%s"
users:
  - name: yigit
    os_user: yigit
    public_keys:
      - "%s"
`, absHost, absCA, testTargetHostKey, testUserPubKey)

	cfgPath := filepath.Join(t.TempDir(), "abs.yaml")
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("mutlak yollu config yüklenemedi: %v", err)
	}
	if len(cfg.Targets) != 1 {
		t.Fatalf("len(Targets) = %d, beklenen 1 — target kaybolmuş", len(cfg.Targets))
	}
	if cfg.CA.KeyFile != absCA {
		t.Errorf("CA.KeyFile değişmiş: %q, beklenen %q", cfg.CA.KeyFile, absCA)
	}
	if cfg.HostKey != absHost {
		t.Errorf("HostKey değişmiş: %q, beklenen %q", cfg.HostKey, absHost)
	}
}
