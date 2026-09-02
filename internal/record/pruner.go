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

	// archived, "bu kayıt başka bir yerde güvende mi" sorusunu soran
	// taraf. nil ise arşivleme kapalı ve davranış eskisiyle aynı.
	archived Archived

	// deleted, silinen her oturum için çağrılıyor: kanıtın kaybolması
	// da denetim defterine düşmesi gereken bir olay.
	deleted func(ctx context.Context, sessionIDs []string)
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
 * WithArchive, budayıcıya arşiv kapısını takar.
 *
 * ⚠️ Bunu takmadan arşivleme açmak, henüz yüklenmemiş kayıtların
 * silinmesi demek. serve.go ikisini BİRLİKTE kuruyor; ayrı ayrı
 * yapılandırılabilir olsalardı biri unutulabilirdi.
 */
func (p *Pruner) WithArchive(a Archived, onDeleted func(context.Context, []string)) *Pruner {
	if p == nil {
		return nil
	}
	p.archived = a
	p.deleted = onDeleted
	return p
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
	res, err := Prune(ctx, p.dir, p.keepFor, p.now(), p.archived)
	if err != nil {
		p.logger.Error("recording prune failed", "error", err)
		return res
	}
	/*
	 * ⚠️ TUTULANLAR HER KOŞUDA LOGLANIYOR, silinen olmasa bile.
	 *
	 * Arşivlenmemiş kayıt silinmiyor — doğru davranış. Ama görünmezse
	 * disk sessizce doluyor ve operatör bir gün "oturumlar
	 * reddediliyor" diye uyanıyor. Sıkışmanın günler önce görünmesi
	 * bu satıra bağlı.
	 */
	if res.KeptUnarchived > 0 || res.Unknown > 0 {
		p.logger.Warn("recordings kept back at retention",
			"kept_unarchived", res.KeptUnarchived, "kept_bytes", res.KeptBytes,
			"unknown_files", res.Unknown, "keep_for", p.keepFor,
			"note", "these are past their retention but not yet safe elsewhere; "+
				"they will fill the disk if uploading stays broken")
	}

	if res.Files == 0 {
		return res
	}
	// ⚠️ KANIT SİLİNDİĞİNDE SESSİZ KALINMIYOR.
	p.logger.Warn("recordings deleted by retention",
		"files", res.Files, "bytes", res.Bytes, "days_removed", res.Dirs,
		"keep_for", p.keepFor)

	// Ve log'da kalmıyor: denetim defterine de yazılıyor.
	if p.deleted != nil && len(res.Deleted) > 0 {
		p.deleted(ctx, res.Deleted)
	}
	return res
}
