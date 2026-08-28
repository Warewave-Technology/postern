// Package events, bastion içinde olup biteni canlı izlemek isteyen
// abonelere dağıtır.
//
// KAPSAM: yalnızca BU süreçte olan olaylar. CLI'dan yapılan yönetim
// işlemleri başka bir süreçte çalışıyor ve buradan geçmiyor — onların
// yeri admin_log tablosu. Panel ikisini birden gösteriyor ve hangisinin
// nereden geldiğini söylüyor; "canlı akış her şeyi gösteriyor" sanmak,
// göstermediğini fark etmemek demek olurdu.
package events

import (
	"sync"
	"time"
)

// Kind, olay türü. Panelde süzme ve simge seçimi buna bakıyor.
type Kind string

const (
	SessionStarted Kind = "session.started"
	SessionEnded   Kind = "session.ended"
	AuthDenied     Kind = "auth.denied"
	AuthOK         Kind = "auth.ok"
)

// Event, tek bir olay.
//
// ⚠️ İÇİNDE SIR YOK ve olmamalı: bu yapı doğrudan tarayıcıya JSON olarak
// akıyor. Sertifika, token, parola ya da doğrulama kodu buraya konursa
// panelde oturum açmış her yöneticinin ekranına düşer.
type Event struct {
	At     time.Time `json:"at"`
	Kind   Kind      `json:"kind"`
	User   string    `json:"user,omitempty"`
	Target string    `json:"target,omitempty"`
	Source string    `json:"source,omitempty"` // istemcinin adresi
	Detail string    `json:"detail,omitempty"`
}

// Publisher, üretici tarafın gördüğü yüz.
//
// proxy ve sshd bu arayüzü alıyor, *Bus'ı değil: nil bir Publisher
// yerine no-op geçebilmek ve testte yayınları toplayabilmek için.
type Publisher interface {
	Publish(Event)
}

// Nop, olay yayını kapalıyken kullanılan Publisher.
type Nop struct{}

func (Nop) Publish(Event) {}

// Bus, abonelere dağıtan veriyolu.
type Bus struct {
	mu     sync.Mutex
	subs   map[int]*sub
	nextID int
	// dropped, yavaş abone yüzünden atılan olay sayısı. Panelde
	// gösteriliyor: eksik bir akışa "tam" diye bakmak, olmamış saymaktır.
	dropped uint64

	// maxSubs, aynı anda dinleyebilecek abone sayısı. Her abone bir
	// goroutine ve bir tampon tutuyor; sınırsız bırakmak, açık bırakılmış
	// sekmelerle belleği büyütmenin yolu olurdu.
	maxSubs int
	// buffer, abone başına tampon derinliği.
	buffer int
}

type sub struct {
	ch chan Event
}

// New, veriyolunu kurar. Sıfır/negatif değerler makul varsayılana düşer.
func New(maxSubs, buffer int) *Bus {
	if maxSubs <= 0 {
		maxSubs = 32
	}
	if buffer <= 0 {
		buffer = 256
	}
	return &Bus{subs: map[int]*sub{}, maxSubs: maxSubs, buffer: buffer}
}

// Publish, olayı bütün abonelere dağıtır.
//
// ⚠️ ASLA BLOKLAMAZ. Çağıranlar bir SSH oturumunun açılış/kapanış
// yolunda: burada beklemek, tarayıcısını açık unutmuş bir yöneticinin
// yavaş bağlantısının bir SSH oturumunu kilitlemesi demek olurdu.
// İzleme aracı, izlediği şeyi durduramaz. Tamponu dolmuş aboneye olay
// DÜŞÜRÜLÜR ve sayaç artar; abone bunu panelde görür.
func (b *Bus) Publish(e Event) {
	if e.At.IsZero() {
		e.At = time.Now()
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	for _, s := range b.subs {
		select {
		case s.ch <- e:
		default:
			b.dropped++
		}
	}
}

// Subscribe, yeni bir abone açar. İkinci dönen değer aboneliği kapatır
// ve birden çok kez çağrılabilir.
//
// Kapasite dolmuşsa ok=false döner: sessizce boş bir kanal vermek,
// panelin "bağlıyım ama hiç olay gelmiyor" demesine yol açardı.
func (b *Bus) Subscribe() (ch <-chan Event, cancel func(), ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.subs) >= b.maxSubs {
		return nil, func() {}, false
	}

	id := b.nextID
	b.nextID++
	s := &sub{ch: make(chan Event, b.buffer)}
	b.subs[id] = s

	var once sync.Once
	return s.ch, func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			if cur, exists := b.subs[id]; exists && cur == s {
				delete(b.subs, id)
				// Kanalı KAPATMIYORUZ: Publish kilidi bıraktıktan sonra
				// hâlâ yazıyor olabilirdi ve kapalı kanala yazmak panik.
				// Aboneliği haritadan düşürmek, bir daha yazılmaması için
				// yeterli; okuyan taraf kendi context'iyle çıkıyor.
			}
		})
	}, true
}

// Stats, panelde gösterilen sayaçlar.
type Stats struct {
	Subscribers int    `json:"subscribers"`
	Dropped     uint64 `json:"dropped"`
}

func (b *Bus) Stats() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return Stats{Subscribers: len(b.subs), Dropped: b.dropped}
}
