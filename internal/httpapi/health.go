package httpapi

import (
	"context"
	"net/http"
	"sync"
	"time"
)

/*
 * Sağlık uçları.
 *
 * ⚠️ İKİYE BÖLÜNDÜ VE SEBEBİ GÜVENLİK. Tek bir "/healthz veritabanını
 * yoklasın" ucu, kimlik istemeyen bir yolu doğrudan veritabanına
 * bağlamak olurdu: saniyede binlerce istek atan biri, hiçbir kimlik
 * göstermeden bastion'ın veritabanını meşgul edebilirdi.
 *
 *   /healthz — SÜREÇ AYAKTA MI. Hiçbir şeye dokunmuyor.
 *   /readyz  — İŞ GÖREBİLİR Mİ. Veritabanına bakıyor, ama sonucu
 *              kısa süre önbelleklenerek: istek hızı ne olursa olsun
 *              veritabanına giden yük sabit kalıyor.
 *
 * ⚠️ KİMLİK İSTEMİYORLAR ve bu bilinçli: bir sağlık kontrolünün amacı
 * tam olarak kimlik bilgisi olmadan sorulabilmesi. Bedeli sızdırdıkları
 * bilgi ve o da kasten sıfıra yakın — sürüm yok, ana makine adı yok,
 * yapılandırma yok. /readyz'in söylediği tek şey "şu an iş göremiyorum".
 *
 * ⚠️ KURULUM DURUMUNA BAKMIYORLAR. Kurulmamış bir bastion da AYAKTA;
 * ilk açılışta 503 dönmek, sistemd'nin ve vekilin daha kimse
 * kurulumu bitirmeden servisi ölü sanmasına yol açardı.
 */

// readyTTL, hazırlık sonucunun önbellek süresi.
//
// ⚠️ ÖNBELLEK GÜVENLİK İÇİN, HIZ İÇİN DEĞİL: kimliksiz bir ucun
// veritabanına gidebileceği azami hız bu sabitle bağlanıyor.
const readyTTL = time.Second

type readyCache struct {
	mu       sync.Mutex
	at       time.Time
	err      error
	inFlight bool
}

// registerHealthRoutes, sağlık uçlarını bağlar.
//
// ⚠️ SPA yakalayıcısından ÖNCE değil SONRA da olabilir — Go'nun
// ServeMux'ü en uzun eşleşmeyi seçiyor, yani "/healthz" her zaman "/"e
// tercih ediliyor. Yine de niyet açık olsun diye burada duruyorlar.
func (s *Server) registerHealthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
}

// handleHealthz: süreç ayakta.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	// noStore: bir vekilin sağlık cevabını önbelleğe alması, ölmüş bir
	// süreci ayakta göstermek demek olurdu.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

/*
 * handleReadyz: iş görebilir mi.
 *
 * Veritabanına ulaşılamıyorsa 503. Sebep gövdeye YAZILMIYOR: hata
 * metni DSN parçaları ya da ana makine adları taşıyabiliyor ve bu uç
 * kimlik istemiyor. Ayrıntı log'a gidiyor — operatörün bakacağı yer
 * orası zaten.
 */
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	if err := s.dbReady(r.Context()); err != nil {
		s.logger.Warn("readiness check failed", "error", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("not ready\n"))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready\n"))
}

/*
 * dbReady, veritabanının erişilebilirliğini ÖNBELLEKLİ döner.
 *
 * ⚠️ İSTEK BAŞINA BİR YOKLAMA DEĞİL. Kimliksiz bir uçtan gelen her
 * isteği veritabanına çevirmek, kimlik göstermeyen birine bastion'ın
 * veritabanını yorma imkânı verirdi.
 *
 * ⚠️ AYNI ANDA TEK YOKLAMA. Önbellek boşken gelen yüz istek yüz
 * yoklama açardı — tam da kaçındığımız şey. İlk isteyen yokluyor,
 * diğerleri bir öncekinin sonucunu alıyor: en kötü ihtimalle bir
 * saniyelik bayat bir cevap, ki bir sağlık kontrolü için kabul
 * edilebilir.
 */
func (s *Server) dbReady(ctx context.Context) error {
	now := time.Now()

	s.ready.mu.Lock()
	if !s.ready.at.IsZero() && now.Sub(s.ready.at) < readyTTL {
		err := s.ready.err
		s.ready.mu.Unlock()
		return err
	}
	if s.ready.inFlight {
		// Başkası yokluyor: en son bilinen cevabı ver.
		err := s.ready.err
		s.ready.mu.Unlock()
		return err
	}
	s.ready.inFlight = true
	s.ready.mu.Unlock()

	// ⚠️ İSTEĞİN BAĞLAMINA BAĞLI DEĞİL: istemci bağlantıyı kesince
	// yoklama iptal olsaydı, sonuç önbelleğe "hata" diye düşerdi ve
	// sağlıklı bir bastion bir sonraki saniye boyunca hasta görünürdü.
	pingCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	err := s.ping(pingCtx)

	s.ready.mu.Lock()
	s.ready.at = time.Now()
	s.ready.err = err
	s.ready.inFlight = false
	s.ready.mu.Unlock()

	return err
}
