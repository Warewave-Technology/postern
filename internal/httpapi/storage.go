package httpapi

import (
	"net/http"
	"time"

	"github.com/warewave/postern/internal/record"
)

/*
 * Kayıt diskinin ve arşiv kuyruğunun durumu.
 *
 * ⚠️ GÖRÜNÜRLÜK BUDAMADAN ÖNCE GELİR — ve arşivleme bunu zorunlu hâle
 * getirdi. record.Usage yazılmıştı, testi vardı ve HİÇBİR YERDEN
 * çağrılmıyordu: operatör ne kadar yer kapladığını göremeden bir
 * saklama süresi seçemez, göremediği için de seçmez.
 *
 * Arşivleme geldiğinden beri ikinci ve daha keskin bir sebep var:
 * yüklenemeyen kayıt BUDANMIYOR. Doğru davranış, ama görünmezse disk
 * sessizce doluyor ve operatör bir gün "oturumlar reddediliyor" diye
 * uyanıyor. Kuyruğun büyüklüğü ve EN ESKİSİNİN YAŞI, o günün haftalar
 * öncesinden görünmesinin tek yolu.
 *
 * ⚠️ YAŞ, SAYIDAN DAHA ÖNEMLİ. Ölmüş bir yükleyicinin belirtisi sayının
 * artması değil: sabit bir sayı da hiçbir şeyin ilerlemediği anlamına
 * gelebilir. Yaşlanan bir "en eski", ilerlemenin durduğunu söyleyen tek
 * işaret.
 */

// adminStorage: GET /api/admin/storage
func (s *Server) adminStorage(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{}

	/*
	 * ⚠️ ÖLÇÜLEMEYEN DEĞER SIFIR DİYE GÖSTERİLMİYOR.
	 *
	 * "0 dosya" ile "bakamadık" farklı şeyler ve ikisini birleştirmek,
	 * dizini okuyamayan bir kurulumu "her şey yolunda" diye
	 * göstermekti. Panel bu bayrağı görünce sayı yerine sebebi yazıyor.
	 */
	if s.records != nil {
		files, bytes, err := record.Usage(s.records.Root())
		if err != nil {
			s.logger.Error("recording usage unavailable", "error", err)
			out["recordings_error"] = true
		} else {
			out["recordings"] = map[string]any{"files": files, "bytes": bytes}
		}
	}

	pending, oldest, err := s.store.ArchiveBacklog(r.Context())
	if err != nil {
		s.logger.Error("archive backlog unavailable", "error", err)
		out["archive_error"] = true
		writeJSON(w, http.StatusOK, out)
		return
	}

	archive := map[string]any{"pending": pending}
	if pending > 0 && !oldest.IsZero() {
		archive["oldest_at"] = oldest.Format(time.RFC3339)
		archive["oldest_age_seconds"] = int64(time.Since(oldest).Seconds())
	}
	out["archive"] = archive

	writeJSON(w, http.StatusOK, out)
}
