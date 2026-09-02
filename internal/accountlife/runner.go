// Package accountlife, kaynağın bir süredir doğrulamadığı hesapları
// pasifleştirir ve uzun süre pasif kalanları silinmiş işaretler.
//
// ⚠️ NEDEN AYRI BİR DÖNGÜ: groupsync dizine SORARAK çalışıyor ve OIDC'de
// sorulacak bir şey yok (bir claim ancak kullanıcı giriş yaparken gelir).
// Bu döngü hiçbir şey sormuyor; yalnızca "kaynak bu kişiyi en son ne
// zaman doğruladı" damgasına bakıyor. OIDC kurulumlarında var olan tek
// iptal yolu bu.
package accountlife

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/store"
)

// Runner, periyodik yaşam döngüsü işi.
type Runner struct {
	db     *store.Store
	logger *slog.Logger

	// interval, koşular arası süre.
	interval time.Duration

	/*
	 * maxFraction / minFloor: TEK KOŞUDA pasifleştirilebilecek üst sınır.
	 *
	 * ⚠️ PATLAMA YARIÇAPI KORUMASI, groupsync'teki tavanların aynısı ve
	 * aynı sebeple. Burada yanlış gidebilecek şey somut: sistem saati
	 * ileri kayarsa, ya da bir göç last_confirmed_at'i boşaltırsa,
	 * herkes bir anda "süresi dolmuş" görünür. Böyle bir koşu, bir
	 * yapılandırma hatasını toplu erişim kaybına çevirirdi.
	 *
	 * Tavan aşıldığında HİÇBİR ŞEY yapılmıyor ve durum loglanıyor:
	 * yarısını uygulamak, hem hasarı verip hem sebebi gizlemek olurdu.
	 *
	 * İKİ EŞİK BİRLİKTE aşılmalı: küçük bir kurulumda oran tek kişide
	 * tetiklenir, büyük bir kurulumda taban tek başına anlamsız kalır.
	 */
	maxFraction float64
	minFloor    int
}

func New(db *store.Store, logger *slog.Logger) *Runner {
	return &Runner{
		db: db, logger: logger,
		interval:    time.Hour,
		maxFraction: 0.10,
		minFloor:    3,
	}
}

// Start, döngüyü çalıştırır; ctx iptal edilene kadar.
func (r *Runner) Start(ctx context.Context) {
	t := time.NewTicker(r.interval)
	defer t.Stop()

	// İlk koşu hemen: açılıştan bir saat sonra değil.
	r.RunOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.RunOnce(ctx)
		}
	}
}

// Report, tek koşunun sonucu.
type Report struct {
	Deactivated []string
	Deleted     []string
	Skipped     string
}

/*
 * RunOnce, tek bir koşu yürütür.
 *
 * İki eşik, iki ayrı iş:
 *   confirm_ttl  dolmuş AKTİF hesap  → pasif
 *   delete_after dolmuş PASİF hesap  → silinmiş (işaret; fiziki silme yok)
 */
func (r *Runner) RunOnce(ctx context.Context) Report {
	var rep Report

	confirmTTL := auth.ConfirmTTL(ctx, r.db)
	deleteTTL := auth.DeleteTTL(ctx, r.db)
	now := time.Now()

	if confirmTTL > 0 {
		stale, err := r.db.StaleAccounts(ctx, now.Add(-confirmTTL), store.StateActive)
		if err != nil {
			r.logger.Error("account lifecycle: stale lookup failed", "error", err)
			return rep
		}
		if ok, why := r.withinBlastRadius(ctx, len(stale)); !ok {
			r.logger.Warn("account lifecycle aborted by blast-radius guard", "reason", why)
			rep.Skipped = why
			return rep
		}
		for _, a := range stale {
			if err := r.db.SetAccountState(ctx, a.Username, store.StateInactive); err != nil {
				r.logger.Error("deactivate failed", "user", a.Username, "error", err)
				continue
			}
			/*
			 * ⚠️ ROLLER SİLİNMİYOR, hesap kapanıyor.
			 *
			 * Rolleri silmek, kişi geri döndüğünde onları yeniden
			 * kurmayı gerektirirdi — ve elle verilmiş roller (source
			 * 'manual') geri gelmezdi. Kapı zaten kapalı; yetkiyi de
			 * yok etmenin faydası yok, kaybı var.
			 */
			r.logger.Warn("account deactivated: the source has not confirmed it",
				"user", a.Username, "last_confirmed", a.Confirmed.Format(time.RFC3339),
				"ttl", confirmTTL.String())
			if lerr := r.db.LogAdmin(ctx, store.AdminLogEntry{
				Actor: "system", Via: "sync", Action: "user.deactivated", Entity: a.Username,
				Details: "the source has not confirmed this account since " +
					a.Confirmed.Format("2006-01-02") + "; signing in reactivates it",
			}); lerr != nil {
				r.logger.Error("audit write failed", "error", lerr)
			}
			rep.Deactivated = append(rep.Deactivated, a.Username)
		}
	}

	if deleteTTL > 0 {
		gone, err := r.db.StaleAccounts(ctx, now.Add(-deleteTTL), store.StateInactive)
		if err != nil {
			r.logger.Error("account lifecycle: inactive lookup failed", "error", err)
			return rep
		}
		/*
		 * ⚠️ SİLME GEÇİŞİNİN DE TAVANI VAR — VE YOKTU.
		 *
		 * Pasifleştirme guard'dan geçiyordu, "silindi" damgası hiç
		 * sormuyordu. Oysa ikisi aynı arızanın iki adımı: yanlış bir
		 * saat ya da yanlış bir TTL önce herkesi pasifleştirir, bir
		 * sonraki koşuda da hepsini silinmiş işaretler. Korumayı
		 * yalnızca ilk adıma koymak, ikinciyi serbest bırakıyordu.
		 */
		if ok, why := r.withinBlastRadius(ctx, len(gone)); !ok {
			r.logger.Warn("account deletion aborted by blast-radius guard", "reason", why)
			rep.Skipped = why
			return rep
		}
		for _, a := range gone {
			if err := r.db.SetAccountState(ctx, a.Username, store.StateDeleted); err != nil {
				r.logger.Error("mark deleted failed", "user", a.Username, "error", err)
				continue
			}
			// ⚠️ FİZİKİ SİLME YOK: denetim kaydı ve oturum kayıtları bu
			// satıra bağlı ve geçmişin okunabilir kalması gerekiyor.
			r.logger.Warn("account marked deleted", "user", a.Username,
				"last_confirmed", a.Confirmed.Format(time.RFC3339))
			if lerr := r.db.LogAdmin(ctx, store.AdminLogEntry{
				Actor: "system", Via: "sync", Action: "user.marked_deleted", Entity: a.Username,
				Details: "inactive since " + a.Confirmed.Format("2006-01-02") +
					"; the row is kept so the audit trail stays readable",
			}); lerr != nil {
				r.logger.Error("audit write failed", "error", lerr)
			}
			rep.Deleted = append(rep.Deleted, a.Username)
		}
	}
	return rep
}

/*
 * withinBlastRadius, bu koşunun fazla hesabı kapatıp kapatmadığına bakar.
 *
 * ⚠️ SAYAMIYORSAK GEÇİRMİYORUZ — VE GEÇİRİYORDU. Koşul
 * `if err != nil || total == 0 { return true, "" }` idi: sayım
 * BAŞARISIZ olduğunda "sınır içinde" deniyordu. Yani bir saat ya da
 * yapılandırma arızasıyla toplu pasifleştirme arasındaki tek tavan, tam
 * da bir şeylerin ters gittiği anda devre dışı kalıyordu — korumanın
 * var olma sebebi olan durumda.
 *
 * total == 0 AYRI bir durum ve o geçiyor: hiç kaynak hesabı yoksa
 * kapatılacak bir şey de yok, oran hesaplanamaz ve bu bir arıza değil.
 */
func (r *Runner) withinBlastRadius(ctx context.Context, count int) (bool, string) {
	if count == 0 {
		return true, ""
	}
	total, err := r.db.SourceAccountCount(ctx)
	if err != nil {
		return false, "the number of source accounts could not be read, " +
			"so the blast-radius ceiling cannot be checked"
	}
	if total == 0 {
		return true, ""
	}
	frac := float64(count) / float64(total)
	if count > r.minFloor && frac > r.maxFraction {
		return false, fmt.Sprintf(
			"would deactivate %d of %d source accounts (%.0f%%, ceiling %.0f%%); "+
				"this looks like a clock or configuration problem, not %d departures",
			count, total, frac*100, r.maxFraction*100, count)
	}
	return true, ""
}
