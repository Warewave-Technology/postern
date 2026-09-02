package proxy

import (
	"context"
	"errors"
	"sync"
)

/*
 * Canlı oturum defteri: "şu an gerçekten akan" oturumlar.
 *
 * ⚠️ NEDEN VERİTABANI YETMİYOR. sessions tablosunda ended_at NULL olması
 * "bitişini kaydetmedik" demek, "şu anda çalışıyor" demek DEĞİL. postern
 * SIGKILL alırsa o satır sonsuza dek NULL kalıyor (ölçüldü: süreci
 * öldürüp yeniden başlattıktan sonra satır hâlâ açık). Kesme düğmesini
 * o satıra bağlasaydık, panel var olmayan bir oturumu kesmeyi teklif
 * eder ve "kesildi" derdi. Gerçek yalnızca süreçte biliniyor; defter o.
 *
 * ⚠️ TEK SÜREÇLİK ve bu bilinçli. 1.0 tek düğüm. İki örnek çalıştıran
 * kurulumda bir örnek diğerinin oturumunu kesemez — bu yüzden API
 * "kesildi" ile "burada çalışmıyor"u AYRI cevaplar olarak veriyor;
 * ikisini birleştirmek, operatöre yapılmamış bir işi yapılmış
 * göstermenin ta kendisi olurdu.
 */

// ErrTerminated: oturumu bir yönetici kesti. bound()'un ürettiği
// ErrIdleTimeout / ErrMaxLifetime ile aynı raftadır: Run bunu
// context.Cause'dan okuyup denetim satırına "closed_by" olarak yazıyor.
var ErrTerminated = errors.New("proxy: session terminated by an administrator")

/*
 * ErrShuttingDown: bastion kapanıyor ve bekleme süresi doldu.
 *
 * ⚠️ ErrTerminated'DAN AYRI TUTULUYOR. İkisi de oturumu kapatıyor ama
 * denetim kaydına ve kullanıcıya bambaşka şeyler söylüyorlar: biri "bir
 * yönetici seni kesti", öbürü "makine yeniden başlıyor". Aynı sebebi
 * kullansaydık, bir dağıtım gecesi denetim defteri kimsenin yapmadığı
 * yüzlerce kesme ile dolardı.
 */
var ErrShuttingDown = errors.New("proxy: the bastion is shutting down")

/*
 * terminatedError, kesmeyi YAPANI taşıyan sebep.
 *
 * ⚠️ AKTÖR ALAN OLARAK TAŞINIYOR, METİNDEN KAZINMIYOR. İlk hâl sebebi
 * fmt.Errorf("%w: %s") ile kuruyor ve okurken son ": "den bölüyordu;
 * içinde ": " geçen bir kullanıcı adı SESSİZCE kırpılır ve hem log
 * alanına hem panelin canlı akışına yanlış bir ad düşerdi. Denetimde
 * "kim" sorusunun cevabı, ayrıştırma kazasına açık olmamalı.
 */
type terminatedError struct{ by string }

func (e *terminatedError) Error() string {
	return ErrTerminated.Error() + ": " + e.by
}

// Unwrap: errors.Is(cause, ErrTerminated) çalışmaya devam etsin.
func (e *terminatedError) Unwrap() error { return ErrTerminated }

// Live, akan oturumların id -> iptal eşlemesi.
type Live struct {
	mu sync.Mutex
	m  map[string]context.CancelCauseFunc
}

// NewLive, boş bir defter kurar.
func NewLive() *Live { return &Live{m: map[string]context.CancelCauseFunc{}} }

// add, oturumu deftere yazar. Run çağırıyor.
func (l *Live) add(id string, cancel context.CancelCauseFunc) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.m[id] = cancel
}

// remove, oturumu defterden düşürür.
//
// ⚠️ Run'ın HER çıkış yolundan çağrılmalı (defer). Düşmeyen bir kayıt,
// bitmiş bir oturumu kesilebilir göstermeye devam ederdi: yönetici
// "kes"e basar, cevap başarılı döner ve hiçbir şey olmaz.
func (l *Live) remove(id string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.m, id)
}

// Running, oturumun bu süreçte akıp akmadığını söyler.
func (l *Live) Running(id string) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.m[id]
	return ok
}

// RunningIDs, bu süreçte akan oturumların kimlikleri.
//
// Panel, veritabanındaki "açık" satırları bununla süzüyor: açık ama
// akmayan satır, çökmeden kalmış bir izdir ve "çalışıyor" diye
// gösterilmemeli.
func (l *Live) RunningIDs() map[string]bool {
	out := map[string]bool{}
	if l == nil {
		return out
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for id := range l.m {
		out[id] = true
	}
	return out
}

/*
 * Terminate, oturumu keser ve KESTİĞİNİ bildirir.
 *
 * Dönen false "böyle akan bir oturum yok" demek — çağıran bunu
 * "kesildi" diye çevirmemeli. Bu ayrım, bu dosyanın var olma sebebi.
 *
 * ⚠️ SEBEP KİMİ İÇERİYOR. context.Cause zincirinden okunan metin
 * doğrudan denetim satırına ve kullanıcıya giden cümleye dönüşüyor;
 * "kesildi" ile "yönetici admin kesti" arasındaki fark, olay sonrası
 * kaydı okuyan için işin tamamı. errors.Is(ErrTerminated) yine
 * çalışıyor, çünkü sarmalıyoruz.
 */
func (l *Live) Terminate(id, by string) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	cancel, ok := l.m[id]
	l.mu.Unlock()
	if !ok {
		return false
	}

	// ⚠️ Kilit DIŞINDA iptal ediliyor. Kendini kilitleme riski YOK —
	// remove, Run'ın kendi goroutine'inde çalışıyor — ama cancel bizim
	// sahibi olmadığımız bir bağlam ağacında yabancı kod çalıştırıyor:
	// AfterFunc'lar, watcher'lar. Onları defterin kilidini tutarken
	// tetiklemek, bu kilidi hiç tanımadığımız çağrı yollarına açardı.
	cancel(&terminatedError{by: by})
	return true
}

/*
 * TerminatedBy, kesme sebebinden KİMİN kestiğini çıkarır.
 *
 * ⚠️ errors.As, metin bölme DEĞİL. Aktör tipli hatanın alanında
 * duruyor; sebebi Error() metninden geri kazımak, içinde ": " geçen bir
 * adı sessizce kırpardı.
 */
func TerminatedBy(cause error) (string, bool) {
	var te *terminatedError
	if errors.As(cause, &te) {
		return te.by, true
	}
	return "", errors.Is(cause, ErrTerminated)
}

/*
 * TerminateAll, akan bütün oturumları verilen sebeple keser ve kaç
 * tanesini kestiğini döner.
 *
 * ⚠️ KAPANIŞIN SON ADIMI. Bekleme süresi dolduğunda çağrılıyor:
 * oturumları öylece bırakıp süreçten çıkmak, kaydı yarım ve arşiv
 * kuyruğuna hiç girmemiş hâlde bırakmak demekti. Buradan geçen her
 * oturum normal kapanış yolunu yürüyor — kullanıcı sebebini görüyor,
 * kayıt kapanıyor, Close arşivi kuyruğa yazıyor.
 *
 * ⚠️ KOPYA ÜZERİNDE GEZİLİYOR. cancel çağrıları Run'ın kendi
 * goroutine'lerini uyandırıyor ve onlar remove'a giriyor; defterin
 * kilidini tutarken iptal etmek kilitlenme demekti (Terminate'teki
 * notun aynısı).
 */
func (l *Live) TerminateAll(cause error) int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	cancels := make([]context.CancelCauseFunc, 0, len(l.m))
	for _, c := range l.m {
		cancels = append(cancels, c)
	}
	l.mu.Unlock()

	for _, c := range cancels {
		c(cause)
	}
	return len(cancels)
}
