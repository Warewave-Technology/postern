// Package config defines postern's YAML configuration schema and loading.
//
// S1: targets and users are static config. S3 moves them to the database;
// only listen/host_key/recording stay in the file after that.
package config

type Config struct {
	Listen    ListenConfig    `yaml:"listen"`
	HostKey   string          `yaml:"host_key"` // path to the bastion's own host private key
	CA        CAConfig        `yaml:"ca"`
	Recording RecordingConfig `yaml:"recording"`
	Targets   []TargetConfig  `yaml:"targets"`
	Roles     []RoleConfig    `yaml:"roles"`
	Users     []UserConfig    `yaml:"users"`
}

// CAConfig, sertifika otoritesi.
//
// key_file, `postern ca init` ile üretilen özel anahtar. serve her oturumda
// bununla sertifika kesecek; ca.Load izin kontrolünü kendisi yapıyor.
type CAConfig struct {
	KeyFile string `yaml:"key_file"`
}

// RoleConfig, bir hedef kümesine erişim yetkisi.
//
// S3'te roles + role_targets tablolarına taşınacak; şimdilik config'de.
// Kullanıcılar rollere ADIYLA referans verir, böylece hedef listesi tek
// yerde durur.
type RoleConfig struct {
	Name    string   `yaml:"name"`
	Targets []string `yaml:"targets"`
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

// TargetConfig, bağlanılacak makine.
//
// Hedefteki HESAP burada yok ve olmamalı: sertifika modelinde hangi hesapla
// açılacağı kişiye göre değişir (users[].os_user) ve kararı policy verir.
// Statik anahtar da yok — erişimi veren şey oturum başına kesilen sertifika.
type TargetConfig struct {
	Name    string `yaml:"name"`
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"`
	HostKey string `yaml:"host_key"` // target's expected host public key, OpenSSH format
}

type UserConfig struct {
	Name string `yaml:"name"`

	// OSUser, kişinin hedeflerdeki hesabı — sertifikanın principal'ı olacak
	// değer. Kişiye özel, paylaşılmaz: driver 1'in özü bu alan.
	OSUser string `yaml:"os_user"`

	// Roles, kişinin sahip olduğu rol ADLARI (roles listesine referans).
	Roles []string `yaml:"roles"`

	PublicKeys []string `yaml:"public_keys"` // authorized keys, OpenSSH format
}
