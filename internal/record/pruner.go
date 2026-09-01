package record

import (
	"context"
	"log/slog"
	"time"
)

/*
 * Budama döngüsü.
 *
 * ⚠️ VARSAYILAN KAPALI ve bu, bu dosyadaki tek önemli karar. Sildiği
 * şey DENETİM KANITI: bir oturumda ne olduğunun tek kaydı. Süreyi
 * söylemeyen bir kurulumda postern'in kendi başına kanıt silmesi,
 * sakladığı şeyin ne olduğunu anlamamak olurdu.
 *
 * ⚠️ SİLİNEN HER ŞEY LOGLANIYOR. Kanıt silen bir işlemin kendi izini
 * bırakmaması, silmeyi görünmez yapardı — ve görünmeyen bir silme,
 * eksik bir kaydı bir arıza gibi gösterir.
 */

// Pruner, eski kayıtları periyodik olarak siler.
type Pruner struct {
	dir     string
	keepFor time.Duration
	logger  *slog.Logger

	// interval, koşular arası süre.
	interval time.Duration
	// now, testlerin zamanı oynatabilmesi için.
	now func() time.Time
}

// NewPruner, kapalıysa nil döner — çağıranın ayrıca kontrol etmesi
// gerekmesin.
func NewPruner(dir string, keepFor time.Duration, logger *slog.Logger) *Pruner {
	if keepFor <= 0 {
		return nil
	}
	return &Pruner{
		dir: dir, keepFor: keepFor, logger: logger,
		interval: time.Hour, now: time.Now,
	}
}

/*
 * Start, döngüyü çalıştırır. ctx bitene kadar dönmüyor.
 *
 * ⚠️ AÇILIŞTA HEMEN BİR KOŞU YAPMIYOR. Bir saat beklemek, yanlış
 * yapılandırılmış bir sürenin (ör. "1h" yerine "1s") ilk saniyede
 * bütün arşivi silmesine karşı verilmiş bir pencere: operatör
 * açılıştaki log satırını görüp durdurabiliyor.
 */
func (p *Pruner) Start(ctx context.Context) {
	if p == nil {
		return
	}
	p.logger.Info("recording retention is on",
		"keep_for", p.keepFor, "dir", p.dir,
		"note", "recordings older than this are deleted, first run in "+p.interval.String())

	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.RunOnce(ctx)
		}
	}
}

// RunOnce, tek bir budama koşusu.
func (p *Pruner) RunOnce(ctx context.Context) PruneResult {
	res, err := Prune(ctx, p.dir, p.keepFor, p.now())
	if err != nil {
		p.logger.Error("recording prune failed", "error", err)
		return res
	}
	if res.Files == 0 {
		return res
	}
	// ⚠️ KANIT SİLİNDİĞİNDE SESSİZ KALINMIYOR.
	p.logger.Warn("recordings deleted by retention",
		"files", res.Files, "bytes", res.Bytes, "days_removed", res.Dirs,
		"keep_for", p.keepFor)
	return res
}
