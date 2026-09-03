package upstream

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/sshalg"
)

/*
 * Bağlantının NEDEN kurulamadığı.
 *
 * ⚠️ NEDEN AYRIŞTIRILIYOR: üçü de "bağlanamadım" ama operatörün yapması
 * gereken şey üçünde de farklı — biri ağ/firewall, biri hedefin
 * kimliğinin değişmesi (ya da araya girme), biri hedefin bu bastion'ın
 * CA'sına güvenmemesi. Hepsini tek bir "session unavailable" altında
 * toplamak, kullanıcıya hiçbir şey söylemeyen bir ekran bırakıyordu:
 * ÖLÇÜLDÜ — panelde kabuk düğmesine basınca tek görünen şey
 * "[disconnected]" idi, sebep yalnızca sunucu günlüğünde duruyordu.
 */
var (
	// ErrUnreachable: TCP bağlantısı hiç kurulamadı.
	ErrUnreachable = errors.New("upstream: target unreachable")

	// ErrHostKeyMismatch: hedef, sabitlenmişten BAŞKA bir anahtar sundu.
	// Bu bir yapılandırma sorunu olabilir de olmayabilir de — postern
	// bu ikisini ayırt edemez ve etmemeli.
	ErrHostKeyMismatch = errors.New("upstream: host key mismatch")

	// ErrRefused: taşıma kuruldu, hedef sertifikamızı kabul etmedi.
	// Neredeyse her zaman tek bir şey demek: hedef bu bastion'ın CA'sına
	// güvenmiyor (TrustedUserCAKeys) ya da kullanıcı hedefte yok.
	ErrRefused = errors.New("upstream: target refused our certificate")

	/*
	 * ErrHandshake: TCP kuruldu ama el sıkışma KİMLİK DOĞRULAMAYA
	 * GELMEDEN bitti.
	 *
	 * ⚠️ REDDEDİLMİŞ DEĞİLİZ — hedef sertifikamızı görmedi bile.
	 * Algoritma uyuşmazlığı, susan bir hedef, SSH konuşmayan bir port:
	 * üçü de burada. Operatörün yapması gereken şey ErrRefused'dakiyle
	 * hiç ilgisi olmayan bir şey, o yüzden ayrı bir sınıf.
	 */
	ErrHandshake = errors.New("upstream: ssh handshake did not complete")
)

/*
 * classifyHandshake, el sıkışma hatasını sınıflandırır.
 *
 * ⚠️ HOST ANAHTARI HATASI KENDİ SENTINEL'İMİZDEN geliyor (aşağıdaki
 * pinnedHostKey), kütüphanenin metninden değil: bir bağımlılığın hata
 * dizgisini ayrıştırmak, o dizgi değiştiği gün sessizce yanlış sınıfa
 * düşmek demektir.
 *
 * ⚠️ HER HATA "REDDEDİLDİ" DEĞİL — ve öyle sayılıyordu.
 *
 * Buradan çıkan her şey ErrRefused oluyordu ve kullanıcı panelde tek
 * bir cümle görüyordu: "hedef bu bastion'ın sertifikasını reddetti —
 * CA'ya güvenmesi gerekiyor". ÖLÇÜLDÜ, sekiz arıza biçiminden ALTISI
 * yanlış sınıflanıyordu: KEX uyuşmazlığı, şifre uyuşmazlığı, susan
 * hedef, SSH konuşmayan port, el sıkışma ortasında donan hedef. Gerçek
 * OpenSSH'e karşı da doğrulandı (KexAlgorithms daraltılmış bir sshd).
 *
 * Bedeli operatörün saatleri: yanlış cümle onu hedefteki
 * TrustedUserCAKeys'e bakmaya gönderiyor, oysa sorun ağda ya da
 * hedefin algoritma yapılandırmasında.
 *
 * ⚠️ SİNYAL, HOST ANAHTARININ SUNULUP SUNULMADIĞI. Metin ayrıştırmak
 * yerine olayın kendisine bakıyoruz: host key callback çağrıldıysa
 * taşıma kurulmuş ve hedef bizi görmüş demektir; çağrılmadıysa
 * kimliğimiz hiç konuşulmamıştır. Zaman aşımı ayrıca kontrol ediliyor
 * çünkü o, callback'ten SONRA da olabiliyor ve yine bir ret değil.
 */
func classifyHandshake(err error, offered bool) error {
	if errors.Is(err, ErrHostKeyMismatch) {
		return err
	}
	if !offered || errors.Is(err, os.ErrDeadlineExceeded) {
		return fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	return fmt.Errorf("%w: %w", ErrRefused, err)
}

/*
 * sawHostKey, host key callback'i sarıp "hedef anahtarını sundu"
 * bilgisini kaydeder.
 *
 * ⚠️ SARMALAYICI, DÖNÜŞ DEĞERİ DEĞİL: hostKeyCallback'in imzasını
 * büyütmek ya da struct'a çevirmek, bu bilgiyi hiç kullanmayan
 * testleri de değiştirmeyi gerektirirdi.
 */
func sawHostKey(cb ssh.HostKeyCallback, offered *atomic.Bool) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		offered.Store(true)
		return cb(hostname, remote, key)
	}
}

// classifyDial, TCP katmanı hatasını sınıflandırır.
func classifyDial(err error) error {
	var ne net.Error
	if errors.As(err, &ne) || errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	// Bilinmeyen bir TCP hatası da erişilemezliktir: bu noktaya kadar
	// hedefle hiç konuşmadık.
	return fmt.Errorf("%w: %w", ErrUnreachable, err)
}

// hostKeyCallback returns a callback accepting EXACTLY the host key given
// in the config (authorized-keys single-line format: "ssh-ed25519 AAAA...").
func hostKeyCallback(expected string) (ssh.HostKeyCallback, []string, error) {
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(expected))
	if err != nil {
		return nil, nil, fmt.Errorf("upstream.hostKeyCallback: %w", err)
	}

	// ⚠️ TÜRÜN KENDİSİ DEĞİL, O TÜRLE MÜZAKERE EDİLEBİLECEK
	// ALGORİTMALAR. RSA'da ikisi ayrı ve doğrudan tür verildiğinde
	// OpenSSH 8.8+ her hedef erişilemez oluyordu (bkz.
	// sshalg.HostKeyAlgorithmsFor).
	return pinnedHostKey(publicKey), sshalg.HostKeyAlgorithmsFor(publicKey.Type()), nil
}

/*
 * pinnedHostKey, ssh.FixedHostKey'in ayırt edilebilir hata dönen hâli.
 *
 * ⚠️ NEDEN SARMALIYORUZ: FixedHostKey uyuşmazlıkta düz bir hata
 * döndürüyor ve çağıran onu ancak metnine bakarak tanıyabilir. Kendi
 * sentinel'imizi koymak, "hedefin kimliği değişti" ile "hedef bizi
 * kabul etmedi" ayrımını kütüphanenin hata metnine bağlı olmaktan
 * çıkarıyor — ve bu iki durum operatöre bambaşka şeyler söylüyor.
 */
func pinnedHostKey(expected ssh.PublicKey) ssh.HostKeyCallback {
	inner := ssh.FixedHostKey(expected)
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if err := inner(hostname, remote, key); err != nil {
			return fmt.Errorf("%w: %w", ErrHostKeyMismatch, err)
		}
		return nil
	}
}
