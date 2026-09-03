package upstream

import (
	"errors"
	"fmt"
	"net"

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
)

// classifyHandshake, el sıkışma hatasını sınıflandırır.
//
// ⚠️ HOST ANAHTARI HATASI KENDİ SENTINEL'İMİZDEN geliyor (aşağıdaki
// pinnedHostKey), kütüphanenin metninden değil: bir bağımlılığın hata
// dizgisini ayrıştırmak, o dizgi değiştiği gün sessizce yanlış sınıfa
// düşmek demektir.
func classifyHandshake(err error) error {
	if errors.Is(err, ErrHostKeyMismatch) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrRefused, err)
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
