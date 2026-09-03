package auth

import (
	"errors"
	"strings"
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
	username string

	/*
	 * accountID, oturumun bağlı olduğu hesabın KİMLİĞİ (users.id).
	 *
	 * ⚠️ ADA DEĞİL KİMLİĞE BAĞLI. Kullanıcı adı yeniden kullanılabiliyor
	 * (purge onu serbest bırakıyor) ama kimlik kalıcı. Oturum yalnızca
	 * ada bağlı olsaydı, adı devralan yeni kişiye çözülürdü — ölçülen
	 * sızıntı buydu. Her istekte bu kimliğin hâlâ silinmemiş olduğu
	 * doğrulanıyor (accountStillOpen).
	 */
	accountID string

	expiresAt time.Time

	/*
	 * createdAt, oturumun AÇILDIĞI an.
	 *
	 * ⚠️ expiresAt'ten çıkarılabilir görünüyor ama çıkarılmamalı: TTL
	 * yapılandırmayla değişebilir ve o an "bu oturum ne kadar taze"
	 * sorusunun cevabı sessizce kayar. Tazelik bir güvenlik kararının
	 * girdisi (bkz. TOTP kaydı: 12 saatlik bir oturumu çalan biri
	 * ikinci faktör bağlayamamalı), o yüzden türetilmiş değil ölçülmüş
	 * bir değer.
	 */
	createdAt time.Time

	/*
	 * viaLocal: bu belirteci YEREL PAROLA KAPISI üretti.
	 *
	 * ⚠️ BU BİR YETKİ DEĞİL, BİR KÖKEN — ve fark, yukarıdaki kuralın
	 * çiğnenip çiğnenmediğini belirliyor. Yetki (kişi yönetici mi,
	 * parolasını değiştirmek zorunda mı) DEĞİŞEBİLİR, o yüzden her
	 * istekte store'dan okunuyor. Köken değişmez: bu belirteç hangi
	 * kapıdan çıktıysa ondan çıkmıştır.
	 *
	 * Neden gerekli: "parolanı değiştirmeden hiçbir şey yapamazsın"
	 * kısıtı HESABA değil, O PAROLAYA ait. Hesaba bağlansaydı, dizinden
	 * ya da kimlik sağlayıcıdan giren biri — hiç kullanmadığı, belki
	 * varlığından haberi olmadığı eski bir yerel parola yüzünden — bir
	 * parola değiştirme ekranına hapsolurdu.
	 */
	viaLocal bool
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
func (w *WebSessions) Create(username, accountID string) (string, error) {
	return w.create(username, accountID, false)
}

// CreateLocal, YEREL PAROLA KAPISINDAN açılan oturum. Ayrı bir isim,
// çünkü köken çağrı yerinde görünmeli: bayrağı unutan bir kapı,
// zorunlu parola değişikliğini sessizce atlatırdı.
func (w *WebSessions) CreateLocal(username, accountID string) (string, error) {
	return w.create(username, accountID, true)
}

func (w *WebSessions) create(username, accountID string, viaLocal bool) (string, error) {
	token, err := newID()
	if err != nil {
		return "", err
	}

	w.mu.Lock()
	now := w.now()
	w.byToken[token] = webSession{
		username:  username,
		accountID: accountID,
		createdAt: now,
		expiresAt: now.Add(webSessionTTL),
		viaLocal:  viaLocal,
	}
	w.mu.Unlock()

	return token, nil
}

/*
 * DestroyUser, bir kullanıcının BÜTÜN oturumlarını düşürür.
 *
 * ⚠️ PAROLA DEĞİŞİKLİĞİNİN AMACI BU. Parolasının ele geçtiğini düşünen
 * kişi onu değiştirir; eski parolayla açılmış oturumlar ayakta kalırsa
 * değiştirmek hiçbir işe yaramaz — saldırgan zaten içeride ve 12 saat
 * daha içeride kalır. Kimlik bilgisi iptal edildiğinde de aynısı
 * geçerli.
 *
 * Dönen sayı düşen oturum sayısı: denetim kaydına yazılıyor, çünkü
 * "kaç oturum kapandı" operatörün soracağı ilk soru.
 *
 * ⚠️ EŞLEŞME HARF DUYARSIZ — VERİTABANI DA ÖYLE.
 *
 * ÖLÇÜLEN ARIZA: burada tam eşleşme aranıyordu, oysa store kullanıcı
 * adını harf duyarsız çözüyor (dialect.go: users.username). Yani
 * `DELETE /api/admin/users/YIGIT` satırı gerçekten siliyor ama
 * "yigit" ile açılmış oturumlar ayakta kalıyordu; aynı ad yeniden
 * yaratıldığında o oturum YENİ kişiye çözülüyordu — üretildi.
 *
 * Fazladan bir hesabı düşürme riski yok: iki hesap yalnızca harf
 * yazımıyla ayrışamıyor, çünkü benzersizlik kısıtı da aynı harf
 * duyarsızlığı kullanıyor. İki kapı aynı adı aynı şekilde çözmezse,
 * arada geçen her şey sessizce kaçıyor.
 */
func (w *WebSessions) DestroyUser(username string) int {
	w.mu.Lock()
	defer w.mu.Unlock()

	n := 0
	for token, sess := range w.byToken {
		if strings.EqualFold(sess.username, username) {
			delete(w.byToken, token)
			n++
		}
	}
	return n
}

/*
 * DestroyAccount, verilen HESAP KİMLİĞİNE bağlı oturumları düşürür.
 *
 * ⚠️ NEDEN AD DEĞİL KİMLİK — VE ADLA DÜŞÜRÜLDÜĞÜ HÂLİN BEDELİ.
 *
 * accountStillOpen bir oturumu KİMLİĞE bakarak reddediyor ama sonra
 * ADLA düşürüyordu. Ad serbest bırakıldıktan sonra iki taraf aynı şeyi
 * göstermiyor: ayrılan kişinin uyuyan sekmesinden gelen bir istek
 * reddediliyor (doğru), ama düşürme, adı DEVRALAN yeni kişinin canlı
 * oturumunu da siliyordu — yeni çalışan iş ortasında, mesajsız, denetim
 * defterinde açıklaması olmayan bir şekilde dışarı atılıyordu. Log
 * satırı da hesabı "gitti" diye yazıyordu: eski satır için doğru, az
 * önce öldürdüğü oturum için yanlış.
 *
 * DestroyUser diğer çağıranlarında (purge, silme, parola değişikliği)
 * DOĞRU kalıyor: orada özne gerçekten ADIN kendisi.
 */
func (w *WebSessions) DestroyAccount(accountID string) int {
	w.mu.Lock()
	defer w.mu.Unlock()

	if accountID == "" {
		return 0
	}
	n := 0
	for token, sess := range w.byToken {
		if sess.accountID == accountID {
			delete(w.byToken, token)
			n++
		}
	}
	return n
}

/*
 * ResolveSessionFull, belirteci çözer: ad, oturumun bağlı olduğu hesap
 * KİMLİĞİ, ve belirteci yerel parola kapısının üretip üretmediği.
 * Tanınmayan ya da süresi dolmuş belirteç için ErrNoSession.
 *
 * Karşılaştırma map anahtarıyla; sabit-zaman gerekmez — belirteç
 * rastgele 43 karakter, map lookup'ının zamanlaması içerik sızdırmaz
 * (güvenlik kodundaki durum farklıydı: orada iki KISA, tahmin
 * edilebilir değer yan yana geliyordu).
 *
 * ⚠️ TEK AÇIK ÇÖZÜCÜ BU. Yanında Resolve (yalnızca ad) ve
 * ResolveSession (ad + köken) duruyordu; oturum ara katmanı buraya
 * geçtiğinden beri ikisinin de test dışında çağıranı kalmamıştı.
 * Yazılıp çağrılmayan kod bu depoda bir kusur, ve bir oturum
 * çözücüsünde ayrıca tehlikeli: hesap kimliğini DÖNDÜRMEYEN bir
 * sarmalayıcı, bir sonraki çağıranı ada bakmaya davet ediyor — adın
 * güvenli bir tutamak olmadığını bu dosyanın kendisi anlatırken.
 */
func (w *WebSessions) ResolveSessionFull(token string) (username, accountID string, viaLocal bool, err error) {
	return w.resolve(token)
}

func (w *WebSessions) resolve(token string) (username, accountID string, viaLocal bool, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	sess, ok := w.byToken[token]
	if !ok {
		return "", "", false, ErrNoSession
	}

	// Tembel temizlik: dokunulmayan çöp zararsızdır, dokunulan çöp
	// kendini temizler. Ayrı bir süpürücü goroutine'e gerek yok.
	if !w.now().Before(sess.expiresAt) {
		delete(w.byToken, token)
		return "", "", false, ErrNoSession
	}

	return sess.username, sess.accountID, sess.viaLocal, nil
}

/*
 * Age, oturumun ne kadar önce açıldığını döner.
 *
 * ⚠️ NEDEN VAR: bir oturumun VAR OLMASI ile kişinin AZ ÖNCE kimliğini
 * kanıtlamış olması aynı şey değil. 12 saat yaşayan bir belirteci
 * çalan biri, hesabın sahibi kadar "giriş yapmış" görünüyor. İkinci
 * faktör bağlamak gibi kalıcı sonuçlu adımlar taze bir kanıt istiyor
 * ve tazeliğin ölçüsü burası.
 *
 * Oturum yoksa hata döner — "bilinmiyor"u "çok taze" diye okutmamak
 * için.
 */
func (w *WebSessions) Age(token string) (time.Duration, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	sess, ok := w.byToken[token]
	if !ok {
		return 0, ErrNoSession
	}
	if !w.now().Before(sess.expiresAt) {
		delete(w.byToken, token)
		return 0, ErrNoSession
	}
	return w.now().Sub(sess.createdAt), nil
}

// Destroy, oturumu düşürür (logout). Olmayan token için sessiz no-op:
// çifte logout bir hata değil.
func (w *WebSessions) Destroy(token string) {
	w.mu.Lock()
	delete(w.byToken, token)
	w.mu.Unlock()
}
