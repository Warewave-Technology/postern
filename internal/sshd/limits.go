package sshd

import (
	"log/slog"
	"net"
	"sync"
	"time"
)

// Bağlantı sınırları.
//
// NEDEN: bu dosya yazılana kadar dinleyicide HİÇBİR sınır yoktu. Accept
// döngüsü sonsuza kadar kabul ediyor, her bağlantı için goroutine
// açıyordu; handshake'in süresi sınırsızdı. SSH sürüm satırı x/crypto'da
// BAYT BAYT okunuyor, yani saatte bir bayt gönderen bir istemci bir
// goroutine'i ve bir dosya tanıtıcısını süresiz tutabiliyordu — ve bunun
// için kimliğini doğrulaması gerekmiyordu.
//
// NE YAPMAZ: bunlar dağıtık bir saldırıyı DURDURMAZ. IP başına sınır bir
// botnet'e karşı işe yaramaz, küresel sınır da o noktada meşru
// kullanıcıyı reddetmeye başlar. Yaptıkları şey kesintiyi BOZULMAYA
// çevirmek: bastion ölmek yerine yük atar.

// connLimiter, eşzamanlı bağlantıları küresel ve IP başına sınırlar.
//
// Elle yazıldı, golang.org/x/sync/semaphore ile değil: semafor küresel
// sınırı verir ama IP başına haritayı vermez, yani mutex'i yine yazmak
// gerekirdi — ve dolaylı bir bağımlılığı yarım bir özellik için doğrudan
// bağımlılığa terfi ettirmek gerekirdi.
type connLimiter struct {
	maxTotal int
	maxPerIP int

	mu    sync.Mutex
	total int
	perIP map[string]int
}

func newConnLimiter(maxTotal, maxPerIP int) *connLimiter {
	return &connLimiter{
		maxTotal: maxTotal,
		maxPerIP: maxPerIP,
		perIP:    map[string]int{},
	}
}

// acquire, bir yer ayırır. reason boş dönerse yer alındı ve release
// ÇAĞRILMALI; doluysa reason sebebi söyler ve release nil'dir.
//
// Sıfır ya da negatif sınır "sınırsız" demek: yapılandırma yazılmamışsa
// çağıran varsayılanı koyar, -1 yazılmışsa operatör bilerek sınırsız
// istemiştir.
func (l *connLimiter) acquire(ip string) (release func(), reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.maxTotal > 0 && l.total >= l.maxTotal {
		return nil, "global"
	}
	if l.maxPerIP > 0 && l.perIP[ip] >= l.maxPerIP {
		return nil, "per-ip"
	}

	l.total++
	l.perIP[ip]++

	var once sync.Once
	return func() {
		// Once: release'in iki kez çağrılması sayacı bozar ve bastion
		// zamanla kendini kilitler. Çağıranın defer'ine güvenmek yerine
		// burada garanti altına alıyoruz.
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()

			l.total--
			l.perIP[ip]--
			if l.perIP[ip] <= 0 {
				// Sıfırlanan anahtarı SİLMEK şart: yalnızca büyüyen bir
				// harita, sınırlayıcının önlemesi gereken bellek
				// sızıntısının ta kendisi olurdu.
				delete(l.perIP, ip)
			}
		})
	}, ""
}

// stats, testler için: kaç bağlantı ve kaç ayrı IP kayıtlı.
func (l *connLimiter) stats() (total, ips int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total, len(l.perIP)
}

// remoteIP, bağlantının kaynak IP'sini döner.
//
// ⚠️ L4 yük dengeleyici ya da TCP vekil arkasında bu adres DENGELEYİCİNİN
// adresidir; o kurulumda max_conns_per_ip herkesi tek bir sayaca toplar.
// postern'de PROXY protokolü desteği yok, dolayısıyla böyle bir dağıtımda
// bu sınır kapatılmalı (-1). Reddetme logu IP'yi ve sayacı yazıyor ki
// sebep tek grep uzakta olsun.
func remoteIP(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		// Ayrıştırılamayan adresi olduğu gibi kullan: sayacın yanlış
		// gruplaması, sayamamaktan iyidir.
		return addr.String()
	}
	return host
}

// deadlineSetter, net.Conn'un yalnız ihtiyaç duyulan yüzü.
//
// Ayrı arayüz olması test içindir: OOB süre uzatma politikası canlı bir
// kimlik sağlayıcı olmadan sınanabilsin diye.
type deadlineSetter interface {
	SetDeadline(t time.Time) error
}

// oobDeadlineSlack, tarayıcı onayı beklenirken verilen ek süre.
//
// oobTimeout'a EKLENİR: challenge gidiş-dönüşü ve onay sonrası kimlik
// sorgusu (auth.go'daki 10 sn'lik sorgu) handshake süresinin içinde
// kalıyor.
const oobDeadlineSlack = 20 * time.Second

// extendDeadline, handshake süresini OOB onayını kapsayacak kadar uzatır.
//
// NEDEN AYRI BİR ADIM: düz bir handshake zaman aşımını oobTimeout kadar
// uzun yapmak, adını sanını bilmediğimiz her tarayıcıya bedava iki
// dakikalık goroutine vermek olurdu — sınırlamaya çalıştığımız şeyin ta
// kendisi. Süreyi YALNIZCA istemci keyboard-interactive'i seçtikten ve
// kendisine giriş bağlantısı gönderildikten sonra uzatıyoruz; ucuz yol
// ucuz kalıyor.
//
// SetDeadline'ı burada çağırmak güvenli: x/crypto'nun okuma goroutine'i
// başka bir yerde Read içinde bloke olsa bile net.Conn son tarihleri
// eşzamanlı çağrıya açıktır ve bloke çağrıyı da etkiler.
func extendDeadline(c deadlineSetter, d time.Duration, logger *slog.Logger) {
	if err := c.SetDeadline(time.Now().Add(d)); err != nil && logger != nil {
		logger.Debug("could not extend handshake deadline", "error", err)
	}
}
