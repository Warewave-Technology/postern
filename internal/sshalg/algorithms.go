// Package sshalg holds the SSH transport algorithms postern accepts.
//
// Ayrı paket olmasının sebebi yapısal: aynı listeler hem GELEN
// (internal/sshd) hem GİDEN (internal/upstream) yönde kullanılıyor ve
// sshd zaten upstream'e bağımlı — listeleri ikisinden birine koymak
// içe aktarma döngüsü yaratırdı. İkiye kopyalamak ise iki yönün
// sessizce ayrışmasına açık kapı bırakırdı.
package sshalg

// SSH taşıma algoritmaları.
//
// ⚠️ NEDEN AÇIKÇA YAZILIYOR: x/crypto'nun varsayılanları UYUMLULUK
// için seçilmiş ve SHA-1 taşıyor — ölçüldü:
//
//	KEX : ... diffie-hellman-group14-sha1
//	MAC : ... hmac-sha1, hmac-sha1-96
//
// Bir bastion'ın taşıma katmanı, geride kalmış istemcilere uyum
// sağlamak için değil, arkasındaki her makineye giden trafiği korumak
// için ayarlanır. Listeler varsayılanın SHA-1'siz hâli: modern
// istemcilerin hepsi kalanları konuşuyor.
//
// Listeler HER İKİ YÖNDE de uygulanıyor: iki yönden birini sıkı,
// diğerini gevşek bırakmak zinciri zayıf halkası kadar yapardı.

// KeyExchanges, kabul edilen anahtar değişimi algoritmaları.
var KeyExchanges = []string{
	"mlkem768x25519-sha256",
	"curve25519-sha256",
	"curve25519-sha256@libssh.org",
	"ecdh-sha2-nistp256",
	"ecdh-sha2-nistp384",
	"ecdh-sha2-nistp521",
	"diffie-hellman-group14-sha256",
}

// Ciphers, kabul edilen şifreler. Hepsi AEAD ya da CTR;
// varsayılanla aynı (orada zaten zayıf şifre yok).
var Ciphers = []string{
	"aes128-gcm@openssh.com",
	"aes256-gcm@openssh.com",
	"chacha20-poly1305@openssh.com",
	"aes128-ctr",
	"aes192-ctr",
	"aes256-ctr",
}

// MACs, kabul edilen mesaj doğrulama algoritmaları.
//
// ETM (encrypt-then-MAC) varyantları önce: doğru sıra o.
var MACs = []string{
	"hmac-sha2-256-etm@openssh.com",
	"hmac-sha2-512-etm@openssh.com",
	"hmac-sha2-256",
	"hmac-sha2-512",
}
