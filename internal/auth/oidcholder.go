package auth

// Çalışırken değiştirilebilen kimlik sağlayıcısı.

import "sync"

/*
 * OIDCHolder, kimlik sağlayıcı istemcisini ÇALIŞIRKEN değiştirilebilir
 * kılar.
 *
 * ⚠️ NEDEN GEREKLİ: OIDC ayarları config dosyasından veritabanına
 * taşındı ve panelden düzenleniyor. Süreci yeniden başlatmadan
 * uygulanamasalardı, ürünün "kurulumdan sonra sunucuya hiç girme"
 * hedefi sihirbazın tam ortasında kırılırdı.
 *
 * ⚠️ İKİ AYRI DURUM, VE KARIŞTIRILAMAZLAR:
 *
 *   configured — bir yapılandırma VAR (ayar satırı ya da config dosyası)
 *   live       — o yapılandırmadan ÇALIŞAN bir istemci kurulabildi
 *
 * Sağlayıcı ulaşılamazken configured true, live false olur. Bu ayrım
 * arayüzün "OIDC seçilemiyor" derken sebebini söyleyebilmesinin tek
 * yolu: "hiç ayarlanmamış" ile "ayarlı ama şu an cevap vermiyor" aynı
 * ekranı hak etmiyor.
 */
type OIDCHolder struct {
	mu         sync.RWMutex
	cur        *OIDC
	gen        uint64
	configured bool
}

func NewOIDCHolder() *OIDCHolder { return &OIDCHolder{} }

/*
 * Current, ŞU ANKİ istemciyi ve KUŞAK numarasını birlikte döner.
 *
 * ⚠️ İKİSİ BİRLİKTE DÖNMEK ZORUNDA ve çağıran ikinci kez OKUMAMALI.
 * Bir giriş akışı A sağlayıcısında başlayıp B'de tamamlanırsa, A'nın
 * ürettiği code B'nin token ucuna gönderilir — yani code ve istemci
 * sırrı, operatörün az önce yazdığı yeni adrese sızar. Kuşak numarası
 * bu akışı reddetmek için var; ayrı ayrı okunan bir istemci/kuşak
 * çifti o korumayı boşa çıkarırdı.
 */
func (h *OIDCHolder) Current() (*OIDC, uint64) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.cur, h.gen
}

// Live, çalışan bir istemci var mı.
func (h *OIDCHolder) Live() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.cur != nil
}

// Configured, bir yapılandırma var mı — istemci kurulamamış olsa bile.
func (h *OIDCHolder) Configured() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.configured
}

// SetConfigured, yapılandırmanın VARLIĞINI işaretler.
func (h *OIDCHolder) SetConfigured(on bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.configured = on
}

// Install, yeni istemciyi yürürlüğe koyar ve kuşağı ilerletir.
func (h *OIDCHolder) Install(o *OIDC) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cur = o
	h.gen++
	h.configured = true
}

/*
 * Clear, çalışan istemciyi DÜŞÜRÜR — yapılandırmanın varlığına
 * dokunmadan.
 *
 * ⚠️ AYARLAR YAZILDIĞI ANDA, HERHANGİ BİR AĞ ÇAĞRISINDAN ÖNCE
 * çağrılmalı. Yeni sağlayıcı kurulamazsa sonuç "eski istemci hâlâ
 * ayakta" değil, "yapılandırma değişti, henüz çalışmıyor" olmalı:
 * yoksa operatör istemci sırrını değiştirdikten sonra ESKİ sırla
 * girişlerin sürdüğünü görür ve iptal ettiğini sanır.
 */
func (h *OIDCHolder) Clear() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cur = nil
	h.gen++
}
