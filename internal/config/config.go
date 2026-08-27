// Package config defines postern's YAML configuration schema and loading.
//
// SÖZLEŞME (S3): config yalnızca ALTYAPI taşır — dinleme adresi, anahtar
// yolları, veritabanı ve kayıt dizini. Kimlik ve yetki verisi (kullanıcı,
// rol, hedef) burada YAŞAMAZ: tek kaynağı veritabanıdır ve yalnızca
// yetkili kanallardan (bastion hostundaki postern CLI; ileride OIDC'li
// API) değiştirilir. YAML'a kullanıcı yazmak diye bir şey yoktur.
package config

type Config struct {
	Listen   ListenConfig   `yaml:"listen"`
	HostKey  string         `yaml:"host_key"` // path to the bastion's own host private key
	CA       CAConfig       `yaml:"ca"`
	Database DatabaseConfig `yaml:"database"`
	Session  SessionConfig  `yaml:"session"`

	// SecretKeyFile, veritabanındaki şifreli ayarları açan ana anahtar
	// (`postern secret init` üretir). Boş bırakılabilir: o zaman şifreli
	// ayar okunamaz/yazılamaz ama bastion'ın geri kalanı çalışır.
	//
	// ⚠️ Bu dosya veritabanıyla AYNI yerde durmamalı: ikisi birlikte
	// sızarsa şifrelemenin tek faydası (yedek/kopya senaryosu) kaybolur.
	SecretKeyFile string          `yaml:"secret_key_file"`
	Recording     RecordingConfig `yaml:"recording"`

	// HTTP ve OIDC birlikte OOB girişini açar (S3.3). İkisi de boş
	// bırakılabilir: o zaman bastion yalnızca public key kabul eder —
	// mevcut kurulumlar hiçbir şey değiştirmeden çalışmaya devam eder.
	HTTP HTTPConfig `yaml:"http"`
	OIDC OIDCConfig `yaml:"oidc"`
}

// HTTPConfig, tarayıcıya bakan uçların dinleyicisi.
type HTTPConfig struct {
	// Addr, dinlenecek adres (":8088" gibi).
	Addr string `yaml:"addr"`

	// ExternalURL, KULLANICININ tarayıcısından erişilen kök
	// ("https://bastion.warewave.io:8088" gibi). Login linkleri ve OIDC
	// redirect_url bununla kurulur — Addr'dan türetilemez: bastion NAT/
	// proxy arkasında olabilir, ":8088" dış dünyada bir anlam taşımaz.
	ExternalURL string `yaml:"external_url"`

	// TerminalEnabled, tarayıcıdaki web terminalini açar. VARSAYILAN
	// KAPALI ve bu bilinçli bir güvenlik kararı: web terminali, SPA'daki
	// herhangi bir XSS'i hedef makinede komut çalıştırma yetkisine
	// çevirir. Bugün aynı XSS yalnızca API'yi kullanabilir — sınırlı bir
	// zarar. Terminale ihtiyacı olmayan kurulum o yüzeyi hiç taşımasın;
	// kod var diye kapı açık olmak zorunda değil.
	//
	// Açan kurulum için şartlar: HTTPS (external_url https), sıkı CSP
	// (securityHeaders zaten kuruyor) ve WS upgrade'inde Origin kontrolü.
	TerminalEnabled bool `yaml:"terminal_enabled"`
}

// OIDCConfig, kimlik sağlayıcısı. auth.OIDCConfig'e birebir taşınır.
type OIDCConfig struct {
	IssuerURL string `yaml:"issuer_url"`
	ClientID  string `yaml:"client_id"`

	// ClientSecret public client'ta boş — PKCE onun yerini tutuyor.
	ClientSecret string `yaml:"client_secret"`
}

// CAConfig, sertifika otoritesi.
//
// key_file, `postern ca init` ile üretilen özel anahtar. serve her oturumda
// bununla sertifika kesecek; ca.Load izin kontrolünü kendisi yapıyor.
type CAConfig struct {
	KeyFile string `yaml:"key_file"`
}

// DatabaseConfig, kalıcı durumun tutulduğu PostgreSQL bağlantısı.
//
// S3'ten itibaren kullanıcılar, roller, hedefler ve oturum denetim kaydı
// burada. Yönetimi paket doc'undaki sözleşmeye tabi: CLI ya da API,
// config değil.
type DatabaseConfig struct {
	// DSN, PostgreSQL bağlantı dizesi. İki biçim de kabul edilir:
	//
	//	postgres://postern:parola@db.local:5432/postern?sslmode=verify-full
	//	host=db.local user=postern dbname=postern sslmode=verify-full
	//
	// sslmode yazılmamışsa store.Open "verify-full" varsayar. libpq'nun
	// varsayılanı olan "prefer" TLS kurulamazsa düz metne SESSİZCE
	// düşer; bir bastion'ın kimlik verisi için bu kabul edilemez.
	//
	// ⚠️ Bu dize PAROLA taşır. Config dosyasına yazmak yerine
	// POSTERN_DATABASE_DSN ortam değişkenini kullanmak tercih edilir —
	// dolu olduğunda buradaki değerin yerine geçer. Şemadaki diğer
	// sırların aksine bu, veritabanının KENDİSİNE ulaşmak için gerekli
	// olduğundan settings tablosuna konulamıyor.
	DSN string `yaml:"dsn"`
}

type ListenConfig struct {
	Addr string `yaml:"addr"` // e.g. ":2222"
}

// SessionConfig, oturum kanalının davranış sınırları.
type SessionConfig struct {
	// AcceptEnv, kullanıcıdan hedefe geçmesine izin verilen ortam
	// değişkeni adları. Sondaki * joker: "LC_*" tüm LC_ ile
	// başlayanları kapsar.
	//
	// Yazılmazsa varsayılan LANG ve LC_* (OpenSSH'ın yaygın AcceptEnv
	// yapılandırmasıyla aynı). BOŞ LİSTE yazmak "hiçbiri" demek —
	// "yazmamak" ile "boş yazmak" farklı şeyler.
	//
	// ⚠️ Buraya PATH, LD_PRELOAD, BASH_ENV gibi bir ad eklemek hedefte
	// NE ÇALIŞACAĞINI kullanıcının eline verir. Whitelist'in var olma
	// sebebi tam olarak bu.
	AcceptEnv []string `yaml:"accept_env"`
}

type RecordingConfig struct {
	Dir string `yaml:"dir"` // session recordings root

	// RecordInput defaults to false on purpose: keystrokes include
	// passwords. See postern-PLAN.md S1.7, design note 4.
	RecordInput bool `yaml:"record_input"`
}
