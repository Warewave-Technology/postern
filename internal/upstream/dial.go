// Package upstream implements the outbound (client-side) half of the
// bastion: dialing targets and opening channels on their behalf.
package upstream

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"github.com/warewave/postern/internal/sshalg"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/ca"
	"github.com/warewave/postern/internal/model"
)

// Conn is an established SSH connection to a target.
type Conn struct {
	client    *ssh.Client
	target    model.Target
	connectMS int
}

// Facts, EL SIKIŞMADAN öğrenilenleri döner.
//
// ⚠️ KAPSAM KASITLI OLARAK DAR. Buradan çıkan her şey sunucunun
// bağlantı kurarken kendiliğinden söylediği: afişi, anlaştığımız host
// key türü, bir de ne kadar sürdüğü. Hedefte `uname` ya da
// `/etc/os-release` okumak çok daha fazlasını verirdi — ve postern'in
// güven modelini bozardı: kullanıcının oturumu dışında hedefte iş
// çalıştırmıyoruz. Bir bastion'ın envanter aracına dönüşmesi, denetim
// altındaki her makinede sessizce komut çalıştırması demek.
func (c *Conn) Facts() model.TargetFacts {
	if c == nil || c.client == nil {
		return model.TargetFacts{}
	}
	f := model.TargetFacts{
		// Afiş sunucu girdisi: uzunluğu sınırlanıyor, aksi hâlde
		// düşmanca bir hedef tabloya ve panele istediği kadar metin
		// yazdırabilirdi.
		ServerVersion: truncate(string(c.client.ServerVersion()), 128),
		ConnectMS:     c.connectMS,
	}
	if pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(c.target.HostKey)); err == nil {
		f.HostKeyType = pub.Type()
	}
	return f
}

// truncate, sunucudan gelen metni sınırlar.
func truncate(s string, n int) string {
	// Kontrol karakterleri afişten temizleniyor: terminal kaçış dizisi
	// taşıyan bir afiş, onu gösteren her yerde ekranı ele geçirebilirdi.
	clean := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(clean) > n {
		return clean[:n] + "…"
	}
	return clean
}

// Client exposes the underlying SSH client
func (c *Conn) Client() *ssh.Client { return c.client }

// Close closes the connection to the target.
func (c *Conn) Close() error {
	if c != nil && c.client != nil {
		return c.client.Close()
	}

	return nil
}

const certValidFor = 5 * time.Minute

type Identity struct {
	PosternUser string

	OSUser string
}

// DialWithCert connects to t using a freshly minted, short-lived certificate
// instead of a static key.
func DialWithCert(ctx context.Context, t model.Target, identity Identity, authority *ca.CA) (*Conn, error) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("upstream.DialWithCert: %w", err)
	}

	ephemeralSigner, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("upstream.DialWithCert: %w", err)
	}

	cert, err := authority.Sign(ca.CertRequest{
		PublicKey:  ephemeralSigner.PublicKey(),
		KeyID:      identity.PosternUser,
		Principals: []string{identity.OSUser},
		ValidFor:   certValidFor,
		Extensions: nil,
	})
	if err != nil {
		return nil, fmt.Errorf("upstream.DialWithCert: %w", err)
	}

	signer, err := ssh.NewCertSigner(cert, ephemeralSigner)
	if err != nil {
		return nil, fmt.Errorf("upstream.DialWithCert: %w", err)
	}

	conn, err := dialer(ctx, t, identity.OSUser, signer)
	if err != nil {
		return nil, fmt.Errorf("upstream.DialWithCert: %w", err)
	}

	return conn, nil
}

// dialer, hedefe bağlanmanın ortak yolu. Kullanıcı adı PARAMETRE: sertifika
// modelinde hangi hesapla açılacağı config'in değil, oturumun kararıdır
// (policy.Authorize üretir) ve sertifikanın principal'ıyla aynı olmak
// zorundadır.
func dialer(ctx context.Context, t model.Target, user string, signer ssh.Signer) (*Conn, error) {
	cb, algos, err := hostKeyCallback(t.HostKey)
	if err != nil {
		return nil, fmt.Errorf("target %s: %w", t.Name, err)
	}

	// offered, hedefin host anahtarını sunduğunu işaretler —
	// sınıflandırmanın sinyali (bkz. classifyHandshake).
	var offered atomic.Bool

	ccfg := &ssh.ClientConfig{
		User:              user,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback:   sawHostKey(cb, &offered),
		HostKeyAlgorithms: algos,

		// Taşıma algoritmaları GELEN yönle aynı: x/crypto'nun
		// varsayılanları SHA-1 taşıyor ve iki yönden birini sıkı,
		// diğerini gevşek bırakmak zinciri zayıf halkası kadar yapardı.
		// Liste internal/sshd'de, gerekçesiyle birlikte.
		Config: ssh.Config{
			KeyExchanges: sshalg.KeyExchanges,
			Ciphers:      sshalg.Ciphers,
			MACs:         sshalg.MACs,
		},

		// ⚠️ YALNIZCA TCP BAĞLANMASINI SINIRLIYOR, EL SIKIŞMAYI DEĞİL —
		// ve burada TCP'yi biz açtığımız için pratikte hiç kullanılmıyor.
		// x/crypto bu alanı sadece ssh.Dial'ın içindeki bağlanmada
		// okuyor; ssh.NewClientConn ona hiç bakmıyor. El sıkışmanın
		// sınırı aşağıda, soketin kendi süresiyle konuyor.
		Timeout: dialTimeout,
	}

	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))

	var d net.Dialer
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("target %s: %w", t.Name, classifyDial(err))
	}

	stop := context.AfterFunc(ctx, func() { nc.Close() })
	defer stop()

	/*
	 * ⚠️ EL SIKIŞMANIN ÜST SINIRI SOKETİN KENDİ SÜRESİYLE KONUYOR.
	 *
	 * ÖLÇÜLEN ARIZA: ccfg.Timeout bunu yapıyor sanılıyordu, yapmıyor —
	 * x/crypto o alanı yalnızca ssh.Dial'ın içindeki TCP bağlanmasında
	 * okuyor ve biz TCP'yi kendimiz açıp NewClientConn'a veriyoruz.
	 * Yani el sıkışmanın hiçbir sınırı yoktu.
	 *
	 * Bedeli kimliği doğrulanmış bir kullanıcının elindeydi: TCP'yi
	 * kabul edip sonra susan bir hedef (çökmüş sshd, karadelik yapan
	 * bir ara cihaz, ya da kasten sessiz bir makine) oturum
	 * goroutine'ini, soketi ve kanal yerini süresiz tutuyordu. Kanal
	 * başına bir kez tekrarlanabiliyor. Diğer sınırların hiçbiri
	 * yetişmiyor: gelen bağlantının el sıkışma süresi çoktan
	 * kaldırılmış, idle/lifetime koruyucuları ise Session.Run'a kadar
	 * kurulmuyor.
	 *
	 * ⚠️ SINIR YALNIZCA EL SIKIŞMAYI KAPSIYOR — ÖLÇÜLDÜ.
	 *
	 * El sıkışmayı bitirip sonra susan bir hedef aynı zararı bir
	 * protokol adımı sonra üretiyor: Conn.OpenSession → OpenChannel
	 * ne context alıyor ne de süresi var, ve süre burada zaten
	 * kaldırılmış oluyor. İstemci gittiğinde bağlantı context'i iptal
	 * ediliyor ama aşağıdaki AfterFunc başarı yolunda söküldüğü için
	 * hedef soketini kapatan bir şey kalmıyor. Bu satırın kapattığı
	 * şey el sıkışma; kanal açılışı hâlâ açık bir sınır.
	 */
	if err := nc.SetDeadline(time.Now().Add(dialTimeout)); err != nil {
		nc.Close()
		return nil, fmt.Errorf("target %s: %w", t.Name, err)
	}

	start := time.Now()
	c, chans, reqs, err := ssh.NewClientConn(nc, addr, ccfg)
	if err != nil {
		nc.Close()
		// Sınıflandırma burada. `offered`, hedefin host anahtarını
		// sunup sunmadığını söylüyor: sunmadıysa kimliğimiz hiç
		// konuşulmamış, yani bu bir RET DEĞİL (hostkey.go).
		return nil, fmt.Errorf("target %s: %w", t.Name,
			classifyHandshake(err, offered.Load()))
	}

	/*
	 * ⚠️ SÜRE HEMEN KALDIRILIYOR — YOKSA OTURUMUN KENDİSİ ÖLÜR.
	 *
	 * Soket süresi tek seferlik değil, KALICI: kaldırılmasaydı
	 * kullanıcının kabuğu, el sıkışma bittikten dialTimeout saniye
	 * sonra sessizce kopardı. Yani asılı hedefi kesen düzeltme, çalışan
	 * her oturuma yirmi saniyelik bir ömür koyardı.
	 */
	if err := nc.SetDeadline(time.Time{}); err != nil {
		nc.Close()
		return nil, fmt.Errorf("target %s: %w", t.Name, err)
	}

	client := ssh.NewClient(c, chans, reqs)

	return &Conn{
		client: client, target: t,
		connectMS: int(time.Since(start).Milliseconds()),
	}, nil
}

// dialTimeout, hedefe bağlanma ve el sıkışma için üst sınır.
//
// ⚠️ Bu YOKKEN asılı ya da düşmanca bir hedef, oturum goroutine'ini
// süresiz tutabiliyordu: ssh.NewClientConn sunucu bağlamı altında
// çalışıyor ve session.idle_timeout henüz devrede değil (oturum daha
// kurulmadı). Yani "hedef cevap vermiyor" durumu sessizce kaynak
// tutmaya dönüşüyordu.
//
// 20 saniye: yavaş bir ağdaki meşru bir hedefe yetecek kadar uzun,
// asılı kalanı tutmayacak kadar kısa.
//
// ⚠️ const DEĞİL var: testin sınırı gerçekten uyguladığımızı ölçebilmesi
// için kısaltılabilmesi gerekiyor. Yirmi saniye bekleyen bir test ya
// yazılmaz ya da atlanır — ve o sınır tam olarak yazılmadığı için
// kaçmıştı.
var dialTimeout = 20 * time.Second
