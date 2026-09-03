package upstream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/sshalg"
)

// scanTimeout, host key taraması için üst sınır.
//
// dialTimeout'tan kısa: burada bir oturum kurulmuyor, yalnızca anahtar
// değişimine kadar gidiliyor. Panelde bir düğmenin arkasında bekleyen
// bir operatör var.
const scanTimeout = 8 * time.Second

// errGotHostKey, el sıkışmayı anahtar alındıktan SONRA durdurmak için.
//
// Sentinel: HostKeyCallback'ten hata dönmek el sıkışmayı iptal ediyor ve
// istediğimiz tam olarak bu — kimlik doğrulamaya hiç geçilmiyor, hedefe
// hiçbir şey kanıtlanmıyor, hiçbir kanal açılmıyor.
var errGotHostKey = errors.New("host key captured")

/*
 * ScanHostKey, hedefin SUNDUĞU host key'i getirir.
 *
 * ⚠️ BU BİR DOĞRULAMA DEĞİL, BİR SORU. Dönen anahtar "doğru" anahtar
 * değil; o adreste o anda cevap veren makinenin sunduğu anahtar. Ağ
 * yolunda duran biri kendi anahtarını sunabilir ve buradan onu alırız.
 *
 * Yine de yapıştırmalı akıştan daha kötü DEĞİL: operatör de
 * `ssh-keyscan`i kendi makinesinden, çoğu zaman aynı ağ üzerinden
 * çalıştırıp yapıştırıyordu. Kazanılan şey yazım hatasının ve "şimdilik
 * boş bırakayım" cazibesinin ortadan kalkması; kaybedilen bir şey yok.
 * Güvenlik, çağıranın parmak izini operatöre AÇIKÇA gösterip onay
 * istemesinden geliyor — bkz. httpapi.adminScanTarget.
 */
func ScanHostKey(ctx context.Context, host string, port int) (ssh.PublicKey, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	ctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	var d net.Dialer
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("upstream.ScanHostKey: %w", err)
	}
	defer nc.Close()

	stop := context.AfterFunc(ctx, func() { nc.Close() })
	defer stop()

	var got ssh.PublicKey
	cfg := &ssh.ClientConfig{
		// Kullanıcı adı ve kimlik YOK: el sıkışma anahtar değişiminden
		// sonra kasten kesiliyor, kimlik doğrulamaya hiç sıra gelmiyor.
		User: "postern-scan",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got = key
			return errGotHostKey
		},

		// ⚠️ HostKeyAlgorithms KISITLI ve sıralı (sshalg).
		//
		// İlk hâlde kısıtlanmamıştı, gerekçesi "sunucunun tercihini
		// görelim"di. Ölçünce yanlış olduğu çıktı: OpenSSH 9.7
		// ecdsa-sha2-nistp256 döndürdü, oysa hedefin ed25519 anahtarı
		// da vardı ve pinlenmesi gereken oydu. Pinlenen tür, postern'in
		// sonradan pazarlık edeceği tür (hostKeyCallback algoları
		// pinlenmiş anahtardan türetiyor) — yani tarama "sunucu ne
		// derse" değil "elimizdekilerin en iyisi" seçmeli.
		HostKeyAlgorithms: sshalg.HostKeyAlgorithms,

		// Taşıma algoritmaları bağlanırkenkilerle AYNI: burada görülüp
		// pinlenen anahtar, sonradan bağlanamadığımız bir algoritmaya
		// aitse işe yaramaz.
		Config: ssh.Config{
			KeyExchanges: sshalg.KeyExchanges,
			Ciphers:      sshalg.Ciphers,
			MACs:         sshalg.MACs,
		},
		Timeout: scanTimeout,
	}

	_, _, _, err = ssh.NewClientConn(nc, addr, cfg)
	if got != nil {
		// Beklenen yol: anahtarı aldık ve el sıkışmayı biz kestik.
		return got, nil
	}
	if err != nil {
		return nil, fmt.Errorf("upstream.ScanHostKey: %w", err)
	}
	// Buraya düşmek "el sıkışma başarılı ama callback hiç çağrılmadı"
	// demek; olmaması gereken bir durum ve sessiz geçilmemeli.
	return nil, fmt.Errorf("upstream.ScanHostKey: target presented no host key")
}
