// Package config defines postern's YAML configuration schema and loading.
//
// S1: targets and users are static config. S3 moves them to the database;
// only listen/host_key/recording stay in the file after that.
package config

type Config struct {
	Listen    ListenConfig    `yaml:"listen"`
	HostKey   string          `yaml:"host_key"` // path to the bastion's own host private key
	Recording RecordingConfig `yaml:"recording"`
	Targets   []TargetConfig  `yaml:"targets"`
	Users     []UserConfig    `yaml:"users"`
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

type TargetConfig struct {
	Name    string `yaml:"name"`
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"`
	User    string `yaml:"user"`     // OS user on the target (S1 only; certs replace this in S2)
	KeyFile string `yaml:"key_file"` // private key used to reach the target (S1 only)
	HostKey string `yaml:"host_key"` // target's expected host public key, OpenSSH format
}

type UserConfig struct {
	Name       string   `yaml:"name"`
	PublicKeys []string `yaml:"public_keys"` // authorized keys, OpenSSH format
}
