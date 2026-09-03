package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

/*
 * Parola tahminine karşı artan gecikme.
 *
 * ⚠️ BU DOSYA, PAROLALARLA BİRLİKTE GELDİ — SONRADAN DEĞİL.
 *
 * locallogin.go'nun başındaki not, hız sınırının GÜVENLİK için değil
 * YÜK için olduğunu söylüyor ve o gerekçe 128 bitlik makine üretimi bir
 * sır içindi: 2^128'i kimse denemiyor. Kullanıcı parolası o öncülü
 * ortadan kaldırıyor. Ölçüldü: bu makinede bir argon2 doğrulaması
 * ~14ms, dört eşzamanlı yuvayla saniyede ~228 deneme. Günde ~19 milyon.
 * İnsanların gerçekten seçtiği parolalar bu hızda ayakta kalmaz.
 *
 * ⚠️ ANAHTAR (HESAP, KAYNAK ADRES) ÇİFTİ — YALNIZCA HESAP DEĞİL.
 *
 * Bu, bu dosyadaki TEK ÖNEMLİ KARAR ve bir saldırıyı ölçtükten sonra
 * böyle yazıldı. Yalnızca hesaba göre saymak, kimliği doğrulanmamış bir
 * yabancıya kurulumun tek yöneticisini panelden dışarıda tutan bir düğme
 * verirdi: yanlış parolayla üst üste denersin, hesap gecikmeye girer,
 * gerçek yönetici giremez. Üstelik hedefin adını tahmin etmek bile
 * gerekmiyor — `postern admin bootstrap` varsayılan olarak "admin"
 * açıyor. Bu, localcred.go:30'daki "kilitleme YOK" kuralının aynı
 * kapıdan geri gelmesi olurdu.
 *
 * Çift anahtar bunu kökten çözüyor: saldırgan yalnızca KENDİ adresini
 * yavaşlatabiliyor. Yönetici kendi adresinden hiçbir gecikme görmüyor.
 * Bedeli, dağıtık bir saldırının her adres için ilk denemeleri bedavaya
 * alması; üstündeki iki kat (adres başına dakikalık kota ve dört argon2
 * yuvası) o tavanı zaten bağlıyor.
 *
 * ⚠️ GECİKME UYKU DEĞİL, ANINDA 429.
 *
 * Beklemek, argon2 yuvasını tutarak beklemek demekti: dört istek bütün
 * kapıyı kapatırdı. Ret hemen dönüyor, yuva hiç alınmıyor.
 *
 * ⚠️ HESAP ADI HAM SAKLANMIYOR.
 *
 * locallogin.go:183'teki kuralın aynısı: operatör er ya da geç sırrı
 * kullanıcı adı kutusuna yapıştırıyor. Orada bunun kalıcı bir tabloya
 * düz metin yazılmasını engelliyoruz; burada bellekte tutulan anahtar da
 * özetleniyor, çünkü aynı değer.
 *
 * BELLEKTE, veritabanında değil: kimliği doğrulanmamış bir isteği bir
 * yazma işlemine çevirmek, 022'de bilinçle reddedilen büyütmenin ta
 * kendisi. Bedeli iki örnek çalıştıran kurulumda sayacın bölünmesi ve
 * yeniden başlatmada sıfırlanması — kabul edilen bir bedel, çünkü bu
 * katman tek savunma değil.
 */

// backoffSteps, ardışık başarısızlık sayısına karşılık gelen bekleme.
//
// İlk üç deneme BEDAVA: parolasını yanlış yazan insan, üç denemede
// bulur ve gecikmeyle karşılaşmaz. Sonrası hızla açılıyor — onuncu
// denemede beş dakika, yani saatte 12 deneme. Bir sözlük saldırısı bu
// hızda anlamını yitiriyor.
var backoffSteps = []time.Duration{
	0, 0, 0,
	2 * time.Second,
	5 * time.Second,
	15 * time.Second,
	30 * time.Second,
	time.Minute,
	2 * time.Minute,
	5 * time.Minute,
}

// backoffForget, dokunulmayan bir kaydın unutulma süresi. Sayaç
// süresiz büyümüyor: dün üç kez yanlış yazan kişi bugün cezalı değil.
const backoffForget = time.Hour

type backoffEntry struct {
	fails int
	// until: bu ana kadar deneme kabul edilmiyor.
	until time.Time
	// touched: tembel temizlik için.
	touched time.Time
}

// guessBackoff, (hesap, adres) çifti başına ardışık başarısızlıklar.
type guessBackoff struct {
	mu  sync.Mutex
	m   map[string]*backoffEntry
	now func() time.Time
}

func newGuessBackoff() *guessBackoff {
	return &guessBackoff{m: map[string]*backoffEntry{}, now: time.Now}
}

/*
 * backoffKey, hesap adı ve kaynak adresten özet üretir.
 *
 * ⚠️ AD KÜÇÜK HARFE KATLANIYOR — VE BUNUN OLMADIĞI HÂLİ ÖLÇÜLDÜ.
 *
 * Hesap her yerde harf duyarsız çözülüyor: users.username 019'dan beri
 * harf duyarsız tekil, sorgular ciEq (lower() = lower()) kullanıyor,
 * dizinler de uid/sAMAccountName'i caseIgnoreMatch ile eşliyor. Ham
 * adı anahtarlamak, TEK bir hesaba adın yazım sayısı kadar ayrı kova
 * veriyordu — sekiz harfli bir ad için 256 tane.
 *
 * Ölçüm (yerel kapı, aynı sahte saat, 100 istek): sabit yazımla 10
 * deneme parola kontrolüne ulaşıyor, 90'ı gecikmeye takılıyor; yazımı
 * döndürünce 100'ü de ulaşıyor, 0'ı takılıyor. Dizin kapısında sabit
 * yazımla 4 bind dizine gidiyor, döndürülmüş yazımla 10 — yani hem
 * saatte 600 tahmin geri geliyor hem de postern yeniden uzaktan hesap
 * kilitleme kolu oluyor. İkisi de tam olarak bu dosyanın kapattığını
 * söylediği zararlar.
 *
 * Adres KATLANMIYOR: o zaten normalize bir IP metni, ve (hesap, adres)
 * çiftinin ikinci yarısı olarak kalması "kilitleme düğmesi yok"
 * özelliğini koruyor.
 */
func backoffKey(username, client string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(username) + "\x00" + client))
	return hex.EncodeToString(sum[:16])
}

/*
 * retryAfter, bu çiftin beklemesi gereken süre. Sıfırsa deneme kabul.
 *
 * ⚠️ HESABIN VAR OLUP OLMADIĞINA BAKMIYOR. Bakmak, "bu ad gecikmeye
 * girdi" bilgisini bir hesap varlığı sızıntısına çevirirdi — decoy
 * doğrulayıcının (locallogin.go) kapatmak için var olduğu kanalın
 * aynısı, başka bir kapıdan.
 */
func (b *guessBackoff) retryAfter(key string) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()

	e, ok := b.m[key]
	if !ok {
		return 0
	}
	now := b.now()
	if d := e.until.Sub(now); d > 0 {
		return d
	}
	return 0
}

// fail, başarısız bir denemeyi kaydeder ve bir sonraki izni erteler.
func (b *guessBackoff) fail(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	b.sweep(now)

	e, ok := b.m[key]
	if !ok {
		e = &backoffEntry{}
		b.m[key] = e
	}
	e.fails++
	e.touched = now

	step := e.fails - 1
	if step >= len(backoffSteps) {
		step = len(backoffSteps) - 1
	}
	e.until = now.Add(backoffSteps[step])
}

/*
 * succeed, sayacı sıfırlar.
 *
 * ⚠️ DOĞRU PAROLA HİÇBİR ZAMAN GECİKMEYLE KARŞILAŞMASIN. Gecikme,
 * bilmeyenleri yavaşlatmak için; bilen kişiyi cezalandırmaya başladığı
 * an bir kilitlemeye dönüşür.
 */
func (b *guessBackoff) succeed(key string) {
	b.mu.Lock()
	delete(b.m, key)
	b.mu.Unlock()
}

// sweep, unutulacak kayıtları atar. Ayrı bir goroutine yok: temizlik,
// zaten kilit altında olduğumuz anda yapılıyor.
func (b *guessBackoff) sweep(now time.Time) {
	for k, e := range b.m {
		if now.Sub(e.touched) > backoffForget {
			delete(b.m, k)
		}
	}
}
