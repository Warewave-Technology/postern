package record

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
}

/*
 * Prune, cutoff'tan ESKİ kayıtları siler.
 *
 * ⚠️ DEĞİŞTİRİLME ZAMANINA BAKIYOR, dizin adına değil. Dizin adı
 * (2026-08-31) kaydın AÇILDIĞI günü söylüyor; uzun süren bir oturum
 * ertesi güne sarkabiliyor ve hâlâ yazılıyor olabilir. Ada bakan bir
 * budayıcı, o dosyayı yazılırken silerdi.
 *
 * ⚠️ SIFIR SÜRE HİÇBİR ŞEY SİLMİYOR. Bu fonksiyonun yanlış çağrılması
 * bütün denetim kaydını silmek demek; "ayar verilmemiş" hâlinin
 * "hepsini sil" olarak okunması, olabilecek en pahalı sıfır değeri
 * olurdu.
 */
func Prune(ctx context.Context, dir string, keepFor time.Duration, now time.Time) (PruneResult, error) {
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
			size := info.Size()
			if rmErr := os.Remove(filepath.Join(dayPath, e.Name())); rmErr != nil {
				remaining++
				continue
			}
			res.Files++
			res.Bytes += size
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

/*
 * Usage, kayıt dizininin toplam boyutu ve dosya sayısı.
 *
 * ⚠️ GÖRÜNÜRLÜK BUDAMADAN ÖNCE GELİR. Operatör ne kadar yer
 * kapladığını göremeden bir saklama süresi seçemez — ve göremediği
 * için de seçmez. Varsayılanı "hiç silme" olan bir ayarın işe
 * yaraması, bu sayının bir yerde yazmasına bağlı.
 */
func Usage(dir string) (files int, bytes int64, err error) {
	werr := filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			// Okunamayan bir alt dizin toplamı düşürmemeli: eksik bir
			// sayı, hiç sayı olmamasından iyi.
			return nil //nolint:nilerr // kasıtlı: bkz. yorum
		}
		if d.IsDir() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		files++
		bytes += info.Size()
		return nil
	})
	if werr != nil && !errors.Is(werr, os.ErrNotExist) {
		return files, bytes, fmt.Errorf("record.Usage: %w", werr)
	}
	return files, bytes, nil
}
