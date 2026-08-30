package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
)

const (
	alphabet   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	codeLength = 8
)

var (
	// ErrLoginDenied: giriş denemesi onaylanmadan yakıldı — yanlış
	// güvenlik kodu, süre aşımı ya da tekrar kullanım girişimi.
	ErrLoginDenied = errors.New("auth: login denied")

	// ErrUnknownAttempt: bu state'e ait bekleyen bir deneme yok (hiç
	// olmadı, süresi doldu ya da çoktan sonuçlandı).
	ErrUnknownAttempt = errors.New("auth: unknown login attempt")

	// ErrNotReady: kod girildi ama tarayıcı tarafı henüz tamamlanmadı.
	// Denemeyi YAKMAZ — kullanıcı tekrar deneyebilir.
	ErrNotReady = errors.New("auth: browser sign-in is not finished yet")

	// ErrTooManyPending: aynı anda çok fazla giriş onay bekliyor.
	//
	// Kuyruğa almak yerine REDDETMEK, varsayılan-reddet kuralının
	// gereği: kuyruğa alınan bir deneme, tutulan bir goroutine demek —
	// yani tam olarak paylaştırmaya çalıştığımız kaynak.
	ErrTooManyPending = errors.New("auth: too many pending logins")
)

// Logins, bekleyen OOB giriş denemelerinin kaydı.
//
// İki dünyayı buluşturur: SSH tarafı bir Attempt başlatıp Wait ile bekler;
// HTTP tarafı (tarayıcı callback'i) Lookup → [Exchange] → Park → Confirm
// zinciriyle kimliği teslim eder. Exchange'in kendisi BURADA DEĞİL: bu tip
// yalnızca eşzamanlılık ve yaşam döngüsü bilir, ağ bilmez — birim testleri
// de bu sayede IdP'siz koşar.
//
// YAŞAM DÖNGÜSÜ — her deneme bu çizgide tek yönlü ilerler:
//
//	Start ──► bekliyor ──Park──► kimlik parkta ──Confirm──► teslim ✓
//	             │                    │
//	          (timeout/Drop)      (yanlış kod / ikinci Park)
//	             ▼                    ▼
//	           yandı ✗              yandı ✗
//
// Yanan deneme geri dönmez: aynı state ile ikinci bir şans yok. Tekrar
// oynatmanın (replay) panzehiri sürecin kendisini tek kullanımlık yapmak.
type Logins struct {
	/*
	 * ⚠️ İSTEMCİ DEĞİL, TUTUCU. Ayarlar çalışırken değişebiliyor ve
	 * sabit bir işaretçi tutmak, değiştirilmiş bir sağlayıcıdan sonra
	 * ESKİSİYLE giriş yapılmasına yol açardı — iptal ettiğini sanan
	 * operatörün göremeyeceği bir yerden.
	 */
	oidc *OIDCHolder

	mu      sync.Mutex
	byState map[string]*Attempt // canlı denemeler; anahtar = state

	// maxPending, byState'in üst sınırı. 0 = sınırsız.
	maxPending int
}

// Attempt, tek bir OOB giriş denemesinin SSH tarafındaki ucu.
type Attempt struct {
	// URL, kullanıcının tarayıcıda açacağı adres (AuthRequest.URL).
	URL string

	// UserCode, TARAYICIDA gösterilen ve TERMİNALE yazılan doğrulama kodu.
	//
	// ⚠️ YÖN ÖNEMLİ ve bir güvenlik açığının düzeltilmesidir. Eskiden
	// ters yöndeydi: kod terminale basılıyor, tarayıcıya yazılıyordu.
	// O düzenin savunduğunu sandığı saldırı şuydu — saldırgan kendi
	// giriş linkini kurbana yollar, kurban tamamlar, saldırganın
	// bekleyen SSH oturumu kurbanın kimliğiyle açılır. Ama kod bunu
	// ENGELLEMİYORDU: terminali gören zaten SALDIRGANIN KENDİSİ, yani
	// kodu da o biliyordu ve linkle birlikte kurbana yolluyordu.
	// (Ölçüldü: TestAttackOOBDeviceCodePhishing saldırıyı uçtan uca
	// gerçekleştiriyordu.)
	//
	// Ters yönde saldırganın kodu YOK: kod yalnızca kurbanın tarayıcı
	// ekranında beliriyor. Saldırının işlemesi için kurbanın kodu
	// okuyup saldırgana GÖNDERMESİ gerekiyor — tek tıklık bir onay
	// yerine, insanların alarma geçtiği bir istek. Microsoft'un push
	// bildirimlerine "numara eşleştirme" eklemesinin sebebiyle aynı.
	UserCode string

	// SourceAddr, SSH bağlantısının geldiği adres. Tarayıcıda
	// GÖSTERİLİYOR: kurbanın "bunu ben başlatmadım" diyebilmesinin tek
	// somut dayanağı bu.
	SourceAddr string

	state  string      // haritadaki anahtarım — Drop bunsuz beni bulamaz
	req    AuthRequest // Lookup bunu verecek (Exchange'e lazım)
	logins *Logins     // Wait'in defer'lı Drop'u için geri işaretçi

	parked *Identity       // Park koydu, Confirm teslim edecek
	done   bool            // uç duruma vardı mı (teslim YA DA yanma)
	result chan waitResult // Wait'in dinlediği TEK kanal, tamponu 1
}

type waitResult struct {
	id  Identity
	err error
}

func NewLogins(o *OIDCHolder) *Logins {
	return &Logins{oidc: o, byState: make(map[string]*Attempt)}
}

// SetMaxPending, aynı anda onay bekleyebilecek giriş sayısını sınırlar.
// 0 = sınırsız. Dinlemeye başlamadan ÖNCE çağrılmalı.
//
// Sınırın BURADA olması gerekiyor, sshd'de değil: bekleyen girişleri
// tutan harita bu nesnenin içinde ve HTTP kapısı (Lookup/Park/Confirm)
// aynı haritayı okuyor. sshd'de uygulanan bir sınır, iki yazardan
// yalnızca birini sınırlardı.
func (l *Logins) SetMaxPending(n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.maxPending = n
}

// Start, yeni bir tarayıcı giriş denemesi açar.
//
// sourceAddr, SSH bağlantısının kaynak adresi; onay sayfasında
// gösteriliyor.
func (l *Logins) Start(sourceAddr string) (*Attempt, error) {
	// Sınır kontrolü İLK: kotayı aşan bir denemede OIDC durumu üretmenin
	// ve kod hesaplamanın anlamı yok.
	//
	// ⚠️ KOTA HEM KÜRESEL HEM KAYNAK BAŞINA.
	//
	// Küresel kota tek başına bir DoS aracıydı: GET tarafı kimlik
	// doğrulaması gerektirmiyor ve tek bir saldırgan, bağlantı
	// sınırının izin verdiği kadar (varsayılan IP başına 8) deneme
	// açarak dört kaynaktan 32'lik kotayı doldurup TARAYICI GİRİŞİNİ
	// HERKESE kapatabiliyordu.
	//
	// Kaynak başına pay, o saldırıyı saldırganın kendi payıyla
	// sınırlıyor: meşru kullanıcılar başka adreslerden gelmeye devam
	// ediyor.
	l.mu.Lock()
	over := l.maxPending > 0 && len(l.byState) >= l.maxPending
	perSource := 0
	if !over && l.maxPending > 0 {
		for _, a := range l.byState {
			if a.SourceAddr != "" && sameHost(a.SourceAddr, sourceAddr) {
				perSource++
			}
		}
		if perSource >= perSourceQuota(l.maxPending) {
			over = true
		}
	}
	l.mu.Unlock()

	if over {
		return nil, ErrTooManyPending
	}

	code, err := newCode()
	if err != nil {
		return nil, fmt.Errorf("auth.pending.Start: %w", err)
	}

	/*
	 * ⚠️ İSTEMCİ VE KUŞAK TEK OKUMADA. Ayrı okunsalardı, aradaki
	 * değişiklik akışı yanlış kuşakla damgalar ve tamamlanma kontrolü
	 * boşa çıkardı.
	 */
	client, gen := l.oidc.Current()
	if client == nil {
		return nil, fmt.Errorf("auth.Start: no identity provider is configured")
	}

	req, err := client.Begin()
	if err != nil {
		return nil, fmt.Errorf("auth.pending.Start: %w", err)
	}
	// Akış BU kuşakla damgalanıyor; tamamlanma anında karşılaştırılacak.
	req.Gen = gen

	a := &Attempt{
		URL:        req.URL,
		UserCode:   code,
		SourceAddr: sourceAddr,
		state:      req.State, // haritanın anahtarı — URL'den sökmek yok, elimizde zaten
		req:        req,
		logins:     l,
		result:     make(chan waitResult, 1), // ⚠️ tamponu 1 — unutulursa her şey kilitlenir
	}

	l.mu.Lock()
	// Kotayı kilit ALTINDA bir kez daha kontrol et: yukarıdaki kontrol
	// ile buraya gelene kadar başka goroutine'ler eklemiş olabilir.
	// Kontrolsüz bırakmak, sınırın eşzamanlı yükte tam olarak
	// ihtiyaç duyulduğu anda kayması demek olurdu.
	if l.maxPending > 0 && len(l.byState) >= l.maxPending {
		l.mu.Unlock()
		return nil, ErrTooManyPending
	}
	l.byState[a.state] = a
	l.mu.Unlock()

	return a, nil
}

// perSourceQuota, tek bir kaynağın alabileceği en fazla bekleyen giriş.
//
// Küresel kotanın dörtte biri, en az bir: bir saldırgan kotanın
// tamamını tutamaz, tek kullanıcılı küçük kurulumlar da çalışmaya
// devam eder.
func perSourceQuota(max int) int {
	if q := max / 4; q > 0 {
		return q
	}
	return 1
}

// sameHost, iki adresin AYNI KAYNAKTAN gelip gelmediğini söyler.
//
// Port yok sayılıyor: her bağlantının portu farklı, karşılaştırmaya
// katmak kaynak başına kotayı tamamen etkisiz kılardı.
func sameHost(a, b string) bool {
	ha, _, err := net.SplitHostPort(a)
	if err != nil {
		ha = a
	}
	hb, _, err := net.SplitHostPort(b)
	if err != nil {
		hb = b
	}
	return ha == hb
}

func (l *Logins) Lookup(state string) (AuthRequest, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	a, ok := l.byState[state]
	if ok {
		return a.req, true
	}

	return AuthRequest{}, false
}

func (l *Logins) Park(state string, id Identity) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	a, ok := l.byState[state]
	if !ok {
		return ErrUnknownAttempt
	}

	if a.parked != nil {
		l.finish(a, waitResult{err: ErrLoginDenied})
		return ErrUnknownAttempt
	}

	a.parked = &id

	return nil
}

// Confirm, terminalden gelen kodu doğrular ve kimliği teslim eder.
//
// ⚠️ ÇAĞIRAN ARTIK SSH TARAFI. Eskiden tarayıcı çağırıyordu; yön
// değişikliğinin gerekçesi UserCode'un doküman yorumunda.
func (l *Logins) Confirm(state, userCode string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	a, ok := l.byState[state]
	if !ok {
		return ErrUnknownAttempt
	}

	// Tarayıcı henüz giriş yapmadıysa bu bir HATA DEĞİL, sıra sorunu:
	// kullanıcı kodu göremeden yazmış olamaz, ama boş ENTER'a basmış
	// olabilir. Denemeyi YAKMIYORUZ — yakmak, kullanıcıyı baştan
	// başlamaya zorlardı.
	if a.parked == nil {
		return ErrNotReady
	}

	if subtle.ConstantTimeCompare([]byte(userCode), []byte(a.UserCode)) != 1 {
		// Yanlış kod denemeyi YAKAR: kaba kuvvet denemesi tek atışlık
		// olmalı.
		l.finish(a, waitResult{err: ErrLoginDenied})
		return ErrLoginDenied
	}

	l.finish(a, waitResult{id: *a.parked})

	return nil
}

// Parked, tarayıcının girişi tamamlayıp kimliği park edip etmediğini
// söyler.
func (l *Logins) Parked(state string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	a, ok := l.byState[state]
	return ok && a.parked != nil
}

// Challenge, tarayıcıda gösterilecek kodu ve SSH kaynağını döner.
//
// Kod yalnızca kimlik PARK EDİLDİKTEN sonra veriliyor: aksi hâlde
// state'i bilen herkes (yani denemeyi başlatan saldırgan) kodu
// doğrudan çekebilirdi ve yön değişikliği hiçbir işe yaramazdı.
func (l *Logins) Challenge(state string) (code, sourceAddr string, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	a, found := l.byState[state]
	if !found || a.parked == nil || a.done {
		return "", "", false
	}
	return a.UserCode, a.SourceAddr, true
}

// State, denemenin anahtarı. SSH tarafı Confirm'e vermek için istiyor;
// alanın kendisi dışa kapalı kalıyor ki kimse haritayı elle
// kurcalamasın.
func (a *Attempt) State() string { return a.state }

func (a *Attempt) Wait(ctx context.Context) (Identity, error) {
	defer a.logins.Drop(a)

	select {
	case r := <-a.result:
		return r.id, r.err

	case <-ctx.Done():
		return Identity{}, ctx.Err()
	}
}

/*
 * DropState, state ile bilinen bir denemeyi düşürür.
 *
 * ⚠️ VAR OLMA SEBEBİ: callback tarafında elde *Attempt yok, yalnızca
 * state var. Denemeyi düşürmeden dönmek, SSH tarafındaki kullanıcıyı
 * zaman aşımına kadar (varsayılan dakikalar) hiçbir şey söylemeden
 * bekletirdi — oysa cevabı zaten biliyoruz.
 *
 * Bilinmeyen state sessizce yok sayılıyor: zaten bitmiş bir denemeyi
 * ikinci kez düşürmek bir hata değil.
 */
func (l *Logins) DropState(state string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if a, ok := l.byState[state]; ok {
		l.finish(a, waitResult{err: ErrLoginDenied})
	}
}

func (l *Logins) Drop(a *Attempt) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.finish(a, waitResult{err: ErrLoginDenied})
}

func (l *Logins) finish(a *Attempt, res waitResult) {
	if a.done {
		return
	}
	a.done = true
	delete(l.byState, a.state)
	a.result <- res // tampon 1 + tek gönderim garantisi: asla bloklanmaz
}

func newCode() (string, error) {
	var builder strings.Builder

	maxRange := big.NewInt(int64(len(alphabet)))
	for i := 0; i < codeLength; i++ {
		// Yarıda tire: telefon ekranından okunup elle yazılacak bir değer
		// için dörtlü gruplar tek blok 8 karakterden belirgin şekilde az
		// hata üretir. Confirm karşılaştırması tireyi de içerir — form
		// alanındaki placeholder aynı biçimi gösteriyor.
		if i == codeLength/2 {
			builder.WriteByte('-')
		}
		idx, err := rand.Int(rand.Reader, maxRange)
		if err != nil {
			return "", err
		}

		builder.WriteByte(alphabet[idx.Int64()])
	}

	return builder.String(), nil
}
