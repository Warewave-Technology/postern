// Package sshalg holds the SSH transport algorithms postern accepts.
//
// Ayrı paket olmasının sebebi yapısal: aynı listeler hem GELEN
// (internal/sshd) hem GİDEN (internal/upstream) yönde kullanılıyor ve
// sshd zaten upstream'e bağımlı — listeleri ikisinden birine koymak
// içe aktarma döngüsü yaratırdı. İkiye kopyalamak ise iki yönün
// sessizce ayrışmasına açık kapı bırakırdı.
package sshalg

import (
	"strings"

	"golang.org/x/crypto/ssh"
)

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

/*
 * PublicKeyAuths, GELEN kimlik doğrulamasında kabul edilen İSTEMCİ imza
 * algoritmaları (ssh.ServerConfig.PublicKeyAuthAlgorithms).
 *
 * ⚠️ TAŞIMADAN AYRI BİR PAZARLIK — ve ayarlanmadığı için kaçmıştı.
 * Yukarıdaki listeler taşıma katmanını ayarlıyor; kimlik kanıtının
 * imzası (SSH_MSG_USERAUTH_REQUEST) ayrı pazarlanıyor ve boş
 * bırakılınca x/crypto kendi varsayılanına düşüyor. O varsayılan
 * ssh-rsa (SHA-1) ve ssh-dss taşıyor.
 *
 * ÖLÇÜLDÜ, gerçek bastion'a karşı: liste yokken ssh-rsa (SHA-1) ile de
 * ssh-dss ile de kimlik doğrulandı (err=<nil>). Yani taşımada SHA-1'i
 * reddeden sunucu, kapıda kabul ediyordu.
 *
 * ⚠️ RSA ANAHTARLAR KAYBOLMUYOR: aynı anahtar rsa-sha2-256/512 ile
 * imzalanıyor ve geçiyor (ölçüldü). Tamamen düşen tek tür ssh-dss —
 * DSA'nın SHA-2 varyantı yok.
 *
 * Sertifika türleri BİLEREK yok: x/crypto sertifikayı ALTTAKİ imza
 * algoritmasıyla karşılaştırıyor, listeye *-cert-v01@openssh.com
 * koymak NewServerConn'u hataya düşürürdü.
 *
 * ⚠️ ELLE YAZILDI, ssh.SupportedAlgorithms()'den türetilmedi — bugün
 * birebir aynı olsalar bile. Bu dosyanın varlık sebebi kabul edilen
 * kümenin denetlenebilir bir yerde YAZILI olması; bağımlılığın bir
 * sürümde listeye bir şey eklemesi, buradaki kararı sessizce
 * değiştirmemeli.
 */
var PublicKeyAuths = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoSKED25519,
	ssh.KeyAlgoSKECDSA256,
	ssh.KeyAlgoECDSA256,
	ssh.KeyAlgoECDSA384,
	ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA256,
	ssh.KeyAlgoRSASHA512,
}

/*
 * UnusableKeyType, bu türde bir anahtarın postern'de HİÇBİR işe
 * yaramayacağını söyler — yarayacaksa boş dize döner.
 *
 * ⚠️ NEDEN VAR: PublicKeyAuths ssh-dss'i kapıda reddediyor ve
 * HostKeyAlgorithms zaten hiç sunmuyor. Kontrol olmasaydı bir DSA
 * anahtarı sorunsuzca EKLENEBİLİYOR, sonra hiçbir koşulda kimlik
 * doğrulayamıyordu — bu depodaki tekrar eden sınıfın kullanıcıya bakan
 * hâli: kabul edilen ve hiç çalışamayan bir kayıt. Sahibi de anahtarını
 * suçlamak yerine bastion'ı arızalı sanardı.
 *
 * ⚠️ ssh-rsa BURADA YOK, ve olmaması bilinçli: anahtarın TEL FORMATI
 * ssh-rsa olsa da imzası rsa-sha2-256/512 olabiliyor (RFC 8332). RSA
 * anahtarları çalışmaya devam ediyor; düşen tek tür DSA, çünkü onun
 * bir SHA-2 varyantı yok.
 */
func UnusableKeyType(keyType string) string {
	if keyType == ssh.InsecureKeyAlgoDSA {
		return "DSA keys are not accepted: the algorithm has no SHA-2 " +
			"variant, so this key could never authenticate"
	}
	return ""
}

/*
 * HostKeyAlgorithms, hedefin host key'ini TARARKEN istediğimiz türler,
 * TERCİH SIRASINDA.
 *
 * ⚠️ SIRA ÖNEMLİ ve liste kısıtlanmak ZORUNDA. Kısıtlamayınca sunucunun
 * keyfi tercihi geliyordu: ölçüldü, OpenSSH 9.7 taramaya
 * ecdsa-sha2-nistp256 döndü. Pinlenen tür sonradan postern'in pazarlık
 * edeceği tür olduğu için (bkz. upstream.hostKeyCallback, algoları
 * pinlenmiş anahtardan türetiyor), taramanın "sunucu ne derse" değil
 * "elimizdekilerin en iyisi" seçmesi gerekiyor.
 *
 * ed25519 önce: küçük, hızlı, eğri seçimi tartışmasız. Sonra RSA'nın
 * SHA-2 varyantları. NIST eğrileri en sonda — destekleniyor, çünkü
 * yalnızca onu sunan hedefler var ve o hedefi kaydedememek onu
 * korumasız bırakmak olurdu.
 */
var HostKeyAlgorithms = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoRSASHA512,
	ssh.KeyAlgoRSASHA256,
	ssh.KeyAlgoECDSA256,
	ssh.KeyAlgoECDSA384,
	ssh.KeyAlgoECDSA521,
}

/*
 * HostKeyAlgorithmsFor, PİNLENMİŞ bir anahtarın türünden o anahtarla
 * müzakere edilebilecek imza algoritmalarını üretir — TERCİH SIRASINDA.
 *
 * ⚠️ ANAHTARIN TEL FORMATI, MÜZAKERE ADI DEĞİL. RSA'da ikisi ayrışıyor:
 * anahtar tel üzerinde her zaman "ssh-rsa" diye duruyor (RFC 8332 imza
 * algoritmasını değiştirdi, anahtar formatını değil) ama imza
 * algoritması rsa-sha2-512 / rsa-sha2-256 olabiliyor.
 *
 * ÖLÇÜLEN ARIZA: pin'in tel formatı doğrudan müzakere listesi olarak
 * kullanılıyordu ve RSA host key'i pinlenmiş HER hedef erişilemez
 * oluyordu — OpenSSH 8.8 ssh-rsa'yı varsayılanda kapattı:
 *
 *     ssh: no common algorithm for host key;
 *     we offered: ["ssh-rsa"], peer offered: ["rsa-sha2-256" "rsa-sha2-512"]
 *
 * Aynı kusur eski bir hedefte SESSİZ kalıyordu: el sıkışma tamamlanıyor
 * ama SHA-1 ile (ölçüldü: müzakere edilen host key algoritması
 * "ssh-rsa"). Operatörün pin'i "rsa-sha2-512 AAAA..." diye yazıp
 * kaçması da mümkün değil — ParseAuthorizedKey onu reddediyor.
 *
 * ⚠️ ssh-rsa (SHA-1) listeye KASTEN GERİ KONMUYOR. RFC 8332 öncesi bir
 * hedef (OpenSSH < 7.2) bu akışa zaten giremiyor: tarama da aynı
 * listeyi sunuyor ve orada da ssh-rsa yok. Kaybedilen tek şey ELLE
 * pinlenmiş böyle bir hedef, ve onu SHA-1'de tutmak, SHA-1'i her
 * yerden çıkarmış bir taşıma katmanının tek istisnası olurdu.
 *
 * Pin'in ANLAMI değişmiyor: tel formatı aynı kaldığı için doğrulama
 * hâlâ birebir aynı anahtar blob'unu karşılaştırıyor.
 *
 * ⚠️ BOŞ LİSTE DÖNMEK TEHLİKELİ, o yüzden bilinmeyen tür kendi adına
 * düşüyor: x/crypto boş ClientConfig.HostKeyAlgorithms'i "varsayılanı
 * kullan" diye okuyor ve o varsayılan ssh-rsa ile ssh-dss içeriyor —
 * yani sessizce AÇILIRDI.
 */
func HostKeyAlgorithmsFor(keyType string) []string {
	switch keyType {
	case ssh.KeyAlgoRSA:
		// Sıra HostKeyAlgorithms ile aynı: tarama neyi tercih
		// ediyorsa bağlantı da onu tercih etmeli.
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	default:
		return []string{keyType}
	}
}

/*
 * HostKeyFile, bir anahtar türünün hedefteki DOSYA ADI.
 *
 * ⚠️ Tür adından türetilemiyor. İlk hâlde "ssh-" öneki kırpılıyordu ve
 * ecdsa-sha2-nistp256 için "ssh_host_ecdsa-sha2-nistp256_key.pub" gibi
 * var olmayan bir yol üretiyordu — operatöre verilen doğrulama komutu
 * çalışmıyordu, yani onaylaması istenen şeyi karşılaştıramıyordu.
 */
func HostKeyFile(keyType string) string {
	switch {
	case keyType == ssh.KeyAlgoED25519:
		return "/etc/ssh/ssh_host_ed25519_key.pub"
	case strings.HasPrefix(keyType, "ecdsa-"):
		return "/etc/ssh/ssh_host_ecdsa_key.pub"
	case keyType == ssh.KeyAlgoRSA || strings.HasPrefix(keyType, "rsa-sha2-"):
		return "/etc/ssh/ssh_host_rsa_key.pub"
	default:
		// Bilinmeyen tür: yol UYDURULMUYOR. Yanlış bir dosya adı,
		// operatörü "dosya yok" hatasıyla uğraştırıp doğrulamadan
		// vazgeçirir.
		return ""
	}
}
