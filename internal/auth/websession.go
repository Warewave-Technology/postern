package auth

import (
	"errors"
	"sync"
	"time"
)

// ErrNoSession: token tanınmıyor — hiç olmadı, süresi doldu ya da çıkış
// yapıldı. Üçü de dışarıya aynı görünür: "giriş yap".
var ErrNoSession = errors.New("auth: no such web session")

// webSessionTTL, tarayıcı oturumunun ömrü. Kayan pencere DEĞİL, mutlak:
// süre girişte damgalanır, aktivite uzatmaz. Bir bastion oturumunun
// "sonsuza kadar açık sekme" ile ölümsüzleşmemesi kayan pencereden daha
// değerli; 12 saat de bir mesai gününü rahat karşılar.
const webSessionTTL = 12 * time.Hour

// webSession, tek bir tarayıcı oturumu.
//
// Kullanıcının ADI saklanır, model.User'ın kendisi değil: oturum 12 saat
// yaşıyor ve bu sürede admin bayrağı ya da roller değişebilir. Kaydı
// burada dondurmak, yetki değişikliğini oturum bitene kadar görünmez
// yapardı. Adı saklayıp her istekte store'dan okumak yetkiyi anında
// geçerli kılar — middleware zaten her istekte çalışıyor.
type webSession struct {
	username  string
	expiresAt time.Time
}

// WebSessions, tarayıcı oturumlarının bellek içi kaydı.
//
// BELLEKTE olması bilinçli: bastion yeniden başlarsa herkes yeniden giriş
// yapar. Bu bir kayıp değil, özellik — süreç yenilendiğinde eski token
// evreni de yenilenir ve DB'de temizlenecek oturum çöpü birikmez.
type WebSessions struct {
	// now, testlerin zamanı oynatabilmesi için alan olarak duruyor;
	// time.Sleep ile 12 saat beklenmez.
	now func() time.Time

	mu      sync.Mutex
	byToken map[string]webSession
}

// NewWebSessions, boş bir kayıt döner.
func NewWebSessions() *WebSessions {
	return &WebSessions{
		now:     time.Now,
		byToken: make(map[string]webSession),
	}
}

// Create, kullanıcı için yeni bir oturum açar ve token'ı döner.
//
// Token cookie'de yaşayacak ve oturumun KENDİSİ o: 32 bayt crypto/rand,
// tahmin edilebilirse oturum çalınır.
func (w *WebSessions) Create(username string) (string, error) {
	token, err := newID()
	if err != nil {
		return "", err
	}

	w.mu.Lock()
	w.byToken[token] = webSession{
		username:  username,
		expiresAt: w.now().Add(webSessionTTL),
	}
	w.mu.Unlock()

	return token, nil
}

// Resolve, token'ı kullanıcı ADINA çevirir. Tanınmayan ya da süresi
// dolmuş token için ErrNoSession.
//
// Karşılaştırma map anahtarıyla; sabit-zaman gerekmez — token rastgele
// 43 karakter, map lookup'ının zamanlaması içerik sızdırmaz (güvenlik
// kodundaki durum farklıydı: orada iki KISA, tahmin edilebilir değer
// yan yana geliyordu).
func (w *WebSessions) Resolve(token string) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	sess, ok := w.byToken[token]
	if !ok {
		return "", ErrNoSession
	}

	// Tembel temizlik: dokunulmayan çöp zararsızdır, dokunulan çöp
	// kendini temizler. Ayrı bir süpürücü goroutine'e gerek yok.
	if !w.now().Before(sess.expiresAt) {
		delete(w.byToken, token)
		return "", ErrNoSession
	}

	return sess.username, nil
}

// Destroy, oturumu düşürür (logout). Olmayan token için sessiz no-op:
// çifte logout bir hata değil.
func (w *WebSessions) Destroy(token string) {
	w.mu.Lock()
	delete(w.byToken, token)
	w.mu.Unlock()
}
