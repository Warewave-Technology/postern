package proxy

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Oturum kanalı üzerindeki request'lerin süzgeci.
//
// NEDEN VAR: bu süzgeç yazılana kadar broker her request'i hedefe OLDUĞU
// GİBİ geçiriyordu. Ölçüldü, tahmin değil — `subsystem sftp` uçtan uca
// çalışıyordu ve dosya transferi asciicast dosyasına HAM İKİLİ PROTOKOL
// olarak düşüyordu: oynatınca anlamsız, "kim hangi dosyayı aldı" sorusuna
// cevapsız, üstelik 1 GB'lık bir indirme 1 GB'lık bir "terminal kaydı"
// üretiyordu. Denetim iddiası olan bir bastion'da sessizce çalışan
// denetlenemez bir kanal, olmayan bir özellikten kötüdür.
//
// KURAL: varsayılan reddet. Bilinmeyen bir request tipi geçmez. SSH'a
// yarın eklenen bir uzantı, biz karar verene kadar bu köprüden geçemez.

// direction, request'in hangi yöne aktığını söyler.
//
// Yön ayrımı şart: aynı request tipi bir yönde meşru, diğerinde
// anlamsızdır. exit-status hedeften gelir; pty-req kullanıcıdan.
type direction int

const (
	// fromClient: kullanıcı → hedef. Saldırı yüzeyi asıl burası.
	fromClient direction = iota
	// fromTarget: hedef → kullanıcı.
	fromTarget
)

func (d direction) String() string {
	if d == fromClient {
		return "client->target"
	}
	return "target->client"
}

// clientRequests, kullanıcıdan hedefe geçmesine izin verilen tipler.
//
// Listede OLMAYANLAR ve neden:
//
//	subsystem                   → sftp/scp denetlenemiyor (bkz. dosya başı).
//	                              SFTP relay planda ayrı bir iş; dosya
//	                              seviyesinde denetimle geldiğinde açılacak.
//	x11-req                     → X11 yönlendirme bastion'ı atlayan ikinci
//	                              bir kanal açar.
//	auth-agent-req@openssh.com  → agent yönlendirme, kullanıcının özel
//	                              anahtarını hedefin erişimine sunar. Hedef
//	                              ele geçtiyse anahtar da ele geçer.
var clientRequests = map[string]bool{
	"pty-req":       true,
	"shell":         true,
	"exec":          true,
	"window-change": true,
	"signal":        true,
	// env AYRICA süzülür: tip serbest, AD whitelist'e tabi.
	"env": true,
	// OpenSSH uzantıları: yarım kapanma bildirimi ve boşta yoklama.
	// İkisi de veri taşımaz.
	"eow@openssh.com":       true,
	"keepalive@openssh.com": true,
}

// targetRequests, hedeften kullanıcıya geçmesine izin verilen tipler.
//
// Hedef bu kanalda çok az şey söyler (RFC 4254 §6.8, §6.10). Liste dar
// tutuluyor: hedef ele geçmiş olabilir ve kullanıcının istemcisini
// sürmesi için bir sebep yok.
var targetRequests = map[string]bool{
	"exit-status":           true,
	"exit-signal":           true,
	"xon-xoff":              true,
	"eow@openssh.com":       true,
	"keepalive@openssh.com": true,
}

// defaultAcceptEnv, env whitelist'inin varsayılanı.
//
// OpenSSH'ın yaygın AcceptEnv yapılandırmasıyla aynı: yerel ayar
// değişkenleri geçer, çalıştırılacak kodu etkileyenler geçmez.
// LD_PRELOAD, PATH, BASH_ENV, PERL5LIB gibi değişkenler hedefte NE
// ÇALIŞACAĞINI değiştirir; bir bastion'ın taşımaması gereken tam olarak
// bunlardır.
var defaultAcceptEnv = []string{"LANG", "LC_*"}

// RequestPolicy, oturum kanalı request'lerinin geçiş kuralları.
type RequestPolicy struct {
	// AcceptEnv, geçmesine izin verilen ortam değişkeni adları.
	// Sondaki * joker: "LC_*" tüm LC_ ile başlayanları kapsar.
	//
	// nil = varsayılan (defaultAcceptEnv). BOŞ DİLİM = hiçbiri; ikisi
	// farklı şeyler ve YAML bu ikisini ayırt edebiliyor.
	AcceptEnv []string
}

// acceptEnv, etkin whitelist'i döner.
func (p RequestPolicy) acceptEnv() []string {
	if p.AcceptEnv == nil {
		return defaultAcceptEnv
	}
	return p.AcceptEnv
}

// allow, request'in geçip geçemeyeceğini ve geçemiyorsa sebebini döner.
//
// Sebep metni kullanıcıya DEĞİL log'a gider: reddin gerekçesi operatörün
// işine yarar, saldırganın keşfine değil.
func (p RequestPolicy) allow(dir direction, req *ssh.Request) (bool, string) {
	if dir == fromTarget {
		if targetRequests[req.Type] {
			return true, ""
		}
		return false, "target may not send this request type"
	}

	if !clientRequests[req.Type] {
		if req.Type == "subsystem" {
			// Adı log'a yazmak teşhisi kolaylaştırıyor: "sftp mi denendi,
			// başka bir şey mi" sorusu operatörün ilk sorusu olacak.
			return false, fmt.Sprintf("subsystem %q is not relayed (no per-file audit yet)", subsystemName(req.Payload))
		}
		return false, "request type is not allowed"
	}

	if req.Type == "env" {
		name, ok := envName(req.Payload)
		if !ok {
			return false, "malformed env request"
		}
		if !envAllowed(name, p.acceptEnv()) {
			return false, fmt.Sprintf("env %q is not in accept_env", name)
		}
	}

	return true, ""
}

// envAllowed, adın whitelist'e uyup uymadığını söyler.
func envAllowed(name string, patterns []string) bool {
	for _, pattern := range patterns {
		if prefix, found := strings.CutSuffix(pattern, "*"); found {
			if strings.HasPrefix(name, prefix) {
				return true
			}
			continue
		}
		if name == pattern {
			return true
		}
	}
	return false
}

// envName, "env" request payload'ından değişken ADINI çıkarır.
//
// Payload: string name, string value (RFC 4254 §6.4). Yalnız ad
// okunuyor — DEĞER OKUNMUYOR ve loglanmıyor: ortam değişkenlerinde sır
// taşınması yaygın ve bu köprünün işi onları toplamak değil.
func envName(payload []byte) (string, bool) {
	name, _, ok := parseString(payload)
	return name, ok
}

// subsystemName, "subsystem" request payload'ından adı çıkarır.
func subsystemName(payload []byte) string {
	name, _, ok := parseString(payload)
	if !ok {
		return "<malformed>"
	}
	return name
}

// parseString, SSH tel biçimindeki bir string'i okur: 4 baytlık uzunluk,
// ardından o kadar bayt. Kalanı ikinci dönüş değeriyle verir.
//
// Elle yazılıyor çünkü ssh.Unmarshal bir struct ister ve buradaki iki
// kullanım tek alanlık. Uzunluk kontrolü ÖNCE yapılıyor: uydurma bir
// uzunluk okuyan kod dilim sınırının dışına taşar.
func parseString(payload []byte) (string, []byte, bool) {
	if len(payload) < 4 {
		return "", nil, false
	}
	n := uint32(payload[0])<<24 | uint32(payload[1])<<16 |
		uint32(payload[2])<<8 | uint32(payload[3])

	// Karşılaştırmanın iki tarafı da genişletiliyor: n uint32, len(body)
	// negatif olamayan bir int. n'i int'e daraltmak 32-bit platformda
	// taşardı; uint64 ikisini de kayıpsız alıyor.
	body := payload[4:]
	if uint64(n) > uint64(len(body)) {
		return "", nil, false
	}
	return string(body[:n]), body[n:], true
}
