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
		files, bytes, skipped, err := record.Usage(s.records.Root())
		switch {
		case err != nil:
			s.logger.Error("recording usage unavailable", "error", err)
			out["recordings_error"] = true
		default:
			rec := map[string]any{"files": files, "bytes": bytes}
			/*
			 * ⚠️ ÜÇÜNCÜ DURUM: KISMEN ÖLÇTÜK.
			 *
			 * Usage okunamayan alt ağaçları atlayıp devam ediyor
			 * (kasıtlı: eksik sayı, hiç sayı olmamasından iyi) ama
			 * eskiden bunu söylemenin yolu yoktu. Eksik bir toplamı
			 * tam gibi göstermek, "5 GB yer kaplıyor" diyen bir
			 * raporun aslında 40 GB'ı görmemesi demek — ve saklama
			 * süresi o rapora bakılarak seçiliyor.
			 */
			if skipped > 0 {
				rec["skipped"] = skipped
				s.logger.Warn("recording usage is partial",
					"skipped_entries", skipped)
			}
			out["recordings"] = rec
		}
	}

	b, err := s.store.ArchiveBacklog(r.Context())
	if err != nil {
		s.logger.Error("archive backlog unavailable", "error", err)
		out["archive_error"] = true
		writeJSON(w, http.StatusOK, out)
		return
	}

	archive := map[string]any{"pending": b.Pending}
	if b.Pending > 0 && !b.Oldest.IsZero() {
		archive["oldest_at"] = b.Oldest.Format(time.RFC3339)
		archive["oldest_age_seconds"] = int64(time.Since(b.Oldest).Seconds())
	}
	/*
	 * ⚠️ "BEKLİYOR" İLE "İLERLEMİYOR" AYRI. Üst üste başarısız olan
	 * satırlar, yükleyicinin geride kalmasından farklı bir şey
	 * söylüyor: bir şeyin düzeltilmesi gerekiyor. Sayı sıfırsa alan
	 * hiç gitmiyor — her cevaba sıfır koymak, ekranı okumayı
	 * zorlaştırır.
	 */
	if b.Failing > 0 {
		archive["failing"] = b.Failing
	}
	// ⚠️ KAYIP: dosyası olmadığı için hiç yüklenemeyecek kayıtlar.
	// "bekliyor" değiller — panel bunu "disk dolacak" gibi değil,
	// "kayıp" olarak göstermeli.
	if b.Lost > 0 {
		archive["lost"] = b.Lost
	}
	out["archive"] = archive

	writeJSON(w, http.StatusOK, out)
}
