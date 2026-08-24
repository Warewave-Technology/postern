// Package config defines postern's YAML configuration schema and loading.
//
// SÖZLEŞME (S3): config yalnızca ALTYAPI taşır — dinleme adresi, anahtar
// yolları, veritabanı ve kayıt dizini. Kimlik ve yetki verisi (kullanıcı,
// rol, hedef) burada YAŞAMAZ: tek kaynağı veritabanıdır ve yalnızca
// yetkili kanallardan (bastion hostundaki postern CLI; ileride OIDC'li
// API) değiştirilir. YAML'a kullanıcı yazmak diye bir şey yoktur.
package config

type Config struct {
	Listen    ListenConfig    `yaml:"listen"`
	HostKey   string          `yaml:"host_key"` // path to the bastion's own host private key
	CA        CAConfig        `yaml:"ca"`
	Database  DatabaseConfig  `yaml:"database"`
	Recording RecordingConfig `yaml:"recording"`
}

// CAConfig, sertifika otoritesi.
//
// key_file, `postern ca init` ile üretilen özel anahtar. serve her oturumda
// bununla sertifika kesecek; ca.Load izin kontrolünü kendisi yapıyor.
type CAConfig struct {
	KeyFile string `yaml:"key_file"`
}

// DatabaseConfig, kalıcı durumun tutulduğu SQLite dosyası.
//
// S3'ten itibaren kullanıcılar, roller, hedefler ve oturum denetim kaydı
// burada. Yönetimi paket doc'undaki sözleşmeye tabi: CLI ya da API,
// config değil.
type DatabaseConfig struct {
	// Path, veritabanı dosyası. Dizini yoksa store.Open oluşturur.
	//
	// ⚠️ host_key ve ca.key_file gibi, göreli yazıldığında CONFIG
	// DOSYASININ dizinine göre çözülür — süreci nereden başlattığına göre
	// başka bir veritabanı açılmasın diye.
	Path string `yaml:"path"`
}

type ListenConfig struct {
	Addr string `yaml:"addr"` // e.g. ":2222"
}

type RecordingConfig struct {
	Dir string `yaml:"dir"` // session recordings root

	// RecordInput defaults to false on purpose: keystrokes include
	// passwords. See postern-PLAN.md S1.7, design note 4.
	RecordInput bool `yaml:"record_input"`
}
