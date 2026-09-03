package record

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

/*
 * Kayıt saklama ve disk koruması.
 *
 * ⚠️ İKİ AYRI SORUN, İKİ AYRI ÇÖZÜM ve karıştırılmamaları önemli:
 *
 *   1. KAYITLAR SINIRSIZ BÜYÜYOR. Çözümü budama — ama budama DENETİM
 *      KANITI SİLMEK demek, dolayısıyla varsayılanı "hiç silme".
 *      Operatör ne kadar sakladığını SÖYLEMEDEN hiçbir şey silinmiyor.
 *
 *   2. DOLU DİSK TAM KESİNTİ. postern kayıt tutamadığında oturumu
 *      reddediyor (denetim öncelikli politika, doğru karar) — ama
 *      lifecycle.go AÇIK oturumları da kapatıyor. Yani disk dolduğunda
 *      yeni girişler durmuyor, çalışan işler de kesiliyor. Çözümü
 *      budama DEĞİL: eşiğe gelmeden önce YENİ oturumu reddetmek.
 *      Aynı reddi daha erken ve daha az zararlı yapıyor.
 *
 * İkincisi varsayılan olarak AÇIK, birincisi KAPALI. Sebep: biri
 * kesintiyi küçültüyor, öbürü kanıt siliyor.
 */

// ErrDiskLow, kayıt için ayrılan yerde eşiğin altında boş alan kaldı.
var ErrDiskLow = errors.New("record: not enough free space for a new recording")

/*
 * FreeSpace, kayıt dizininin bulunduğu dosya sisteminde kalan bayt.
 *
 * ⚠️ AYRILMIŞ BLOKLAR SAYILMIYOR (Bavail, Bfree değil). root olmayan
 * bir süreç ayrılmış bloklara yazamıyor; onları "boş" saymak, gerçekte
 * dolmuş bir diskte hâlâ yer var demek olurdu.
 */
func FreeSpace(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, fmt.Errorf("record.FreeSpace: %w", err)
	}
	// #nosec G115 -- Bavail ve Bsize platforma göre int64/uint64;
	// ikisi de negatif olamaz.
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}

/*
 * CheckSpace, yeni bir kayıt açmadan önce yer var mı diye bakar.
 *
 * ⚠️ SIFIR EŞİK "KAPALI" DEMEK, "her zaman reddet" değil. Ayarın
 * yokluğu bir kapıyı kapatmamalı.
 *
 * ⚠️ ÖLÇÜM YAPILAMIYORSA GEÇİYORUZ. Statfs'in başarısız olması,
 * diskin dolu olduğunu göstermez — dosya sistemi hakkında hiçbir şey
 * bilmediğimizi gösterir. Bilmemeyi "dolu" saymak, ölçüm hatasını
 * kesintiye çevirirdi; asıl koruma zaten yazmanın kendisinin
 * başarısız olması.
 */
func (s *Store) CheckSpace(minFree uint64) error {
	if minFree == 0 {
		return nil
	}
	free, err := FreeSpace(s.dir)
	if err != nil {
		return nil
	}
	if free < minFree {
		return fmt.Errorf("%w: %d bytes free, %d required",
			ErrDiskLow, free, minFree)
	}
	return nil
}

// PruneResult, bir budama koşusunun sonucu.
type PruneResult struct {
	Files int
	Bytes int64
	// Dirs, tamamen boşalıp kaldırılan gün dizinleri.
	Dirs int

	/*
	 * ⚠️ TUTULANLAR DA SAYILIYOR, ve gerekçesi silinenler kadar önemli.
	 *
	 * Arşivlenmemiş bir kayıt saklama süresi dolsa bile silinmiyor.
	 * Doğru davranış bu — ama görünmezse, disk yavaşça doluyor ve
	 * operatör bir gün "oturumlar reddediliyor" diye uyanıyor. Sayılar
	 * her koşuda loglanıyor ki sıkışma günler önce görünsün.
	 */
	KeptUnarchived int
	KeptBytes      int64

	// Unknown, adından oturum kimliği çıkmayan dosyalar: yetim
	// kayıtlar ya da dizine düşmüş yabancılar. Silinmiyor, sayılıyor.
	Unknown int

	// Deleted, silinen oturumların kimlikleri. Çağıran bunları denetim
	// defterine yazıyor: kanıtın kaybolması da bir olay.
	Deleted []string
}

/*
 * Prune, cutoff'tan ESKİ kayıtları siler.
 *
 * ⚠️ DEĞİŞTİRİLME ZAMANINA BAKIYOR, dizin adına değil. Dizin adı
 * (2026-08-31) kaydın AÇILDIĞI günü söylüyor; uzun süren bir oturum
 * ertesi güne sarkabiliyor. Ada bakan bir budayıcı, ertesi gün hâlâ
 * yazılan o dosyayı yaşlı sanıp silerdi.
 *
 * ⚠️ AMA mtime YALNIZCA AKTİF YAZILANI KORUR. Çıktı üretmeyen boşta
 * bir oturumun mtime'ı da eskir; onu openIDs (açık oturum kümesi)
 * koruyor, mtime değil.
 *
 * ⚠️ SIFIR SÜRE HİÇBİR ŞEY SİLMİYOR. Bu fonksiyonun yanlış çağrılması
 * bütün denetim kaydını silmek demek; "ayar verilmemiş" hâlinin
 * "hepsini sil" olarak okunması, olabilecek en pahalı sıfır değeri
 * olurdu.
 */
/*
 * Archived, "bu kayıtlar başka bir yerde güvende mi" sorusunu soran
 * taraf. Uygulaması internal/archive'da; burada yalnızca ARAYÜZ var.
 *
 * ⚠️ ARAYÜZ TÜKETİCİ TARAFINDA TANIMLI, ÇÜNKÜ record PAKETİ HİÇBİR
 * PROJE PAKETİNİ IMPORT ETMİYOR — yalnızca standart kütüphane. Buraya
 * store'u sokmak, kayıt yazma yolunu veritabanına bağımlı hâle
 * getirirdi; oysa o yolun tek işi diske yazmak ve hiçbir dış sisteme
 * bağlı olmaması, "kayıt tutulamıyorsa oturum reddedilir" kuralının
 * anlamlı kalmasının şartı.
 */
type Archived interface {
	// ArchivedIDs, verilenlerden hangilerinin DOĞRULANMIŞ şekilde
	// arşivlendiğini döner. Kümede olmayan her kimlik "silinemez".
	ArchivedIDs(ctx context.Context, ids []string) (map[string]bool, error)
}

/*
 * Prune, saklama süresi dolan kayıtları siler.
 *
 * archived nil ise arşivleme kapalıdır ve davranış eskisiyle aynı:
 * yaşı geçen dosya silinir.
 *
 * ⚠️ archived DOLUYSA KAPI VARSAYILAN OLARAK KAPALI. Yalnızca
 * "evet, doğrulanmış şekilde arşivlendi" cevabı silmeye izin veriyor.
 * Sorgu hata verirse KOŞU İPTAL EDİLİYOR — hiçbir şey silinmeden.
 * Bu, bu dosyadaki diğer hata davranışlarının TERSİ (CheckSpace
 * ölçemediğinde nil dönüyor, dizin okunamadığında continue ediliyor)
 * ve fark bilinçli: orada bedel bir oturumun reddedilmemesi, burada
 * bedel denetim kanıtının yok olması.
 */
func Prune(ctx context.Context, dir string, keepFor time.Duration, now time.Time,
	archived Archived, openIDs map[string]bool) (PruneResult, error) {

	var res PruneResult
	if keepFor <= 0 {
		return res, nil
	}
	cutoff := now.Add(-keepFor)

	days, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return res, nil
		}
		return res, fmt.Errorf("record.Prune: %w", err)
	}

	for _, day := range days {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if !day.IsDir() {
			continue
		}
		dayPath := filepath.Join(dir, day.Name())

		entries, rerr := os.ReadDir(dayPath)
		if rerr != nil {
			continue
		}
		/*
		 * ⚠️ İZİN SORGUSU, SİLMELERDEN ÖNCE VE GÜN BAŞINA TEK SEFERDE.
		 *
		 * Dosya başına sormak, bir gün dizini için yüzlerce sorgu
		 * demekti. Koşunun başında bir kez sormak ise uzun süren bir
		 * budamada bayat cevap kullanmak olurdu — bu dizinin
		 * silmelerinin hemen öncesi doğru yer.
		 */
		allowed := map[string]bool{}
		if archived != nil {
			ids := make([]string, 0, len(entries))
			for _, e := range entries {
				if id, ok := sessionIDOf(e.Name()); ok {
					ids = append(ids, id)
				}
			}
			var qerr error
			allowed, qerr = archived.ArchivedIDs(ctx, ids)
			if qerr != nil {
				// ⚠️ HİÇBİR ŞEY SİLMEDEN ÇIK. "Soramadım" ile
				// "güvende" aynı şey değil; karıştırmanın bedeli
				// kanıtın yok olması.
				return res, fmt.Errorf("record.Prune: cannot tell what is archived, "+
					"deleting nothing: %w", qerr)
			}
		}

		remaining := 0
		for _, e := range entries {
			info, ierr := e.Info()
			if ierr != nil {
				remaining++
				continue
			}
			if !info.ModTime().Before(cutoff) {
				remaining++
				continue
			}

			/*
			 * ⚠️ HÂLÂ AÇIK BİR OTURUMUN KAYDI SİLİNMEZ.
			 *
			 * ÖLÇÜLEN ARIZA: değiştirilme zamanı yalnızca AKTİF YAZILAN
			 * bir dosyayı koruyor. Çıktı üretmeyen boşta bir kabuk
			 * (açık ama sessiz) 25 saat sonra eski bir mtime taşıyor ve
			 * oturum HÂLÂ açıkken kaydı siliniyordu — unlink'lenen
			 * inode'a yazma devam ettiği için oturum yolunda kimse fark
			 * etmiyor, ama kapanışta kayıt yok oluyor.
			 *
			 * openIDs, o an açık oturumların kümesi (canlı oturum
			 * defterinden). Kayıt dosyasının adı oturum kimliği ve ikisi
			 * aynı (lifecycle.go: record.NewSessionID hem dosyaya hem
			 * satıra gidiyor).
			 */
			if len(openIDs) > 0 {
				if id, ok := sessionIDOf(e.Name()); ok && openIDs[id] {
					remaining++
					continue
				}
			}

			if archived != nil {
				id, ok := sessionIDOf(e.Name())
				if !ok {
					// Adından oturum kimliği çıkmayan dosya: yetim ya
					// da yabancı. Silmiyoruz ve SAYIYORUZ — sessizce
					// atlamak, birikeni görünmez kılardı.
					res.Unknown++
					remaining++
					continue
				}
				if !allowed[id] {
					res.KeptUnarchived++
					res.KeptBytes += info.Size()
					remaining++
					continue
				}
			}

			size := info.Size()
			if rmErr := os.Remove(filepath.Join(dayPath, e.Name())); rmErr != nil {
				remaining++
				continue
			}
			res.Files++
			res.Bytes += size
			res.Deleted = append(res.Deleted, strings.TrimSuffix(e.Name(), ".cast"))
		}
		/*
		 * Boşalan gün dizini kaldırılıyor — ama YALNIZCA boşsa.
		 * RemoveAll kullanmıyoruz: bir dosyayı silememiş olsaydık
		 * onu da götürürdü.
		 */
		if remaining == 0 {
			if err := os.Remove(dayPath); err == nil {
				res.Dirs++
			}
		}
	}
	return res, nil
}

// sessionIDOf, "<id>.cast" adından oturum kimliğini çıkarır.
//
// Kimlik üreteci ^[a-zA-Z0-9_-]+$ garantisi veriyor (store.Create);
// desene uymayan bir ad bu dizine ait değil.
func sessionIDOf(name string) (string, bool) {
	id, ok := strings.CutSuffix(name, ".cast")
	if !ok || id == "" {
		return "", false
	}
	for i := range len(id) {
		c := id[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-' {
			continue
		}
		return "", false
	}
	return id, true
}

/*
 * Usage, kayıt dizininin toplam boyutu ve dosya sayısı.
 *
 * ⚠️ GÖRÜNÜRLÜK BUDAMADAN ÖNCE GELİR. Operatör ne kadar yer
 * kapladığını göremeden bir saklama süresi seçemez — ve göremediği
 * için de seçmez. Varsayılanı "hiç silme" olan bir ayarın işe
 * yaraması, bu sayının bir yerde yazmasına bağlı.
 */
func Usage(dir string) (files int, bytes int64, skipped int, err error) {
	werr := filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			// Okunamayan bir alt dizin toplamı düşürmemeli: eksik bir
			// sayı, hiç sayı olmamasından iyi.
			//
			// ⚠️ AMA SESSİZ DE OLMAMALI — ve öyleydi. Atlananları
			// saymadan `err == nil` dönmek, eksik bir toplamı tam bir
			// toplam gibi sunmak demekti: disk raporu "5 GB" diyor,
			// gerçekte 40 GB var ve aradaki fark okunamayan bir alt
			// ağaçta duruyor. Uç zaten "ölçemedik"i ayırıyor
			// (recordings_error); ayıramadığı "kısmen ölçtük"tü.
			skipped++
			return nil //nolint:nilerr // kasıtlı: bkz. yorum
		}
		if d.IsDir() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			skipped++
			return nil
		}
		files++
		bytes += info.Size()
		return nil
	})
	if werr != nil && !errors.Is(werr, os.ErrNotExist) {
		return files, bytes, skipped, fmt.Errorf("record.Usage: %w", werr)
	}
	return files, bytes, skipped, nil
}
