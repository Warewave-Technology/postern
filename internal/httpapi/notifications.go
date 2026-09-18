package httpapi

/*
 * Bildirimler: yöneticinin bakması gereken, bekleyen işler.
 *
 * ⚠️ KALICI BİR BİLDİRİM TABLOSU YOK, VE BU BİLİNÇLİ. Bir bildirim
 * tablosu, olayı yazan yol ile durumu tutan yolu ayırır: iş çoktan
 * yapılmış olsa bile satır orada durur, "okundu" işaretlenene kadar.
 * Sonuç, kendi kendine bayatlayan bir liste — ve bayat bir uyarı
 * listesi, bir süre sonra hiç okunmayan bir listedir.
 *
 * Buradaki liste HER ÇAĞRIDA durumdan türetiliyor: bekleyen makine
 * kaydedilince satırı da gider, onaylanan kimlik listeden düşer, geri
 * alınabilen hak kaybolur. Yani "okundu" diye bir durum gerekmiyor;
 * bildirimin kaybolma şartı, işin yapılmış olması.
 *
 * ⚠️ HEPSİ YÖNETİCİ İŞİ. Üç kaynağın üçü de yalnızca yöneticinin
 * yapabileceği bir işi gösteriyor; uç de yönetici kapısının arkasında.
 */

import (
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/Warewave-Technology/postern/internal/store"
)

func (s *Server) registerNotificationRoutes(mux *http.ServeMux) {
	admin := func(h http.HandlerFunc) http.Handler {
		return noStore(s.requireSession(s.requireAdmin(s.sameOrigin(h))))
	}
	mux.Handle("GET /api/admin/notifications", admin(s.adminNotifications))
}

/*
 * notification, tek bir bekleyen iş.
 *
 * ⚠️ At, "bu iş NE ZAMANDAN BERİ bekliyor" — bildirimin üretildiği an
 * değil. Türetilmiş bir listede "üretildiği an" her çağrıda şimdi
 * olurdu ve hiçbir şey söylemezdi; oysa üç gündür bekleyen bir onay ile
 * beş dakikadır bekleyen bir onay aynı aciliyette değil.
 */
type notification struct {
	Kind    string    `json:"kind"`
	At      time.Time `json:"at"`
	Summary string    `json:"summary"`
	Detail  string    `json:"detail"`
	// Section, işin yapılacağı panel bölümü — satır oraya götürüyor.
	Section string `json:"section"`
}

/*
 * adminNotifications: GET /api/admin/notifications
 *
 * ⚠️ BİR KAYNAK OKUNAMAZSA LİSTE YİNE DÖNÜYOR. Üç sorgudan birinin
 * düşmesi öbür ikisinin haberini de yutsaydı, keşif tablosundaki bir
 * arıza "onay bekleyen kimlik yok" diye okunurdu. Okunamayan kaynak
 * kendi satırını bırakıyor: sayı eksik kalmıyor, sebebi de ekranda.
 */
func (s *Server) adminNotifications(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	out := []notification{}

	if machines, err := s.store.DiscoveredMachines(ctx, ""); err != nil {
		out = append(out, notification{
			Kind: "error", At: time.Now(),
			Summary: "Discovered machines could not be read",
			Detail:  err.Error(), Section: "discovery",
		})
	} else {
		for _, m := range machines {
			// "yeni" durumunun tanımı: hedef değil, yok sayılmamış,
			// kaynakta duruyor, sorunsuz ve anahtarı okunmuş. Panelin
			// rozeti ile listesi aynı şeyi saymak zorunda.
			if m.TargetID != "" || m.Ignored || !m.MissingSince.IsZero() ||
				m.Problem != "" || m.HostKey == "" {
				continue
			}
			out = append(out, notification{
				Kind: "discovery.new", At: m.FirstSeen,
				Summary: m.Name + " is waiting to be registered",
				Detail: fmt.Sprintf("Found by %s. It becomes a target — and reachable — only once you register it.",
					m.Source),
				Section: "discovery",
			})
		}
	}

	if pending, err := s.store.ListPending(ctx); err != nil {
		out = append(out, notification{
			Kind: "error", At: time.Now(),
			Summary: "Pending identities could not be read",
			Detail:  err.Error(), Section: "pending",
		})
	} else {
		for _, p := range pending {
			if p.State != "waiting" {
				continue
			}
			out = append(out, notification{
				Kind: "identity.pending", At: p.FirstSeen,
				Summary: p.Username + " is waiting for approval",
				Detail: fmt.Sprintf("Signed in through %s and has no account here yet; approving one creates it.",
					p.Source),
				Section: "pending",
			})
		}
	}

	if failed, err := s.store.FailedRevokes(ctx); err != nil {
		out = append(out, notification{
			Kind: "error", At: time.Now(),
			Summary: "Temporary access could not be read",
			Detail:  err.Error(), Section: "jit",
		})
	} else {
		for _, g := range failed {
			/*
			 * ⚠️ BU SATIR BİR HESABIN HÂLÂ AÇIK OLDUĞUNU SÖYLÜYOR.
			 * Süpürücü denemeye devam ediyor, ama denemenin sürmesi
			 * hesabın kapandığı anlamına gelmiyor ve aradaki fark
			 * yöneticinin bilmesi gereken bir fark.
			 */
			out = append(out, notification{
				Kind: "grant.revoke_failed", At: g.ExpiresAt,
				Summary: fmt.Sprintf("%s could not be removed from %s", g.OSUser, g.Target),
				Detail: fmt.Sprintf("The access expired but the account is still there after %d attempt(s): %s",
					g.RevokeAttempts, g.RevokeError),
				Section: "jit",
			})
		}
	}

	/*
	 * ⚠️ KİLİTLENEN HESAP DA BEKLEYEN BİR İŞ. Otomatik yol hesabı
	 * kilitliyor ama silmiyor (K3); kararı verecek kişi bunu görmezse
	 * kilitli hesaplar veritabanında birikir ve kimse onlara dönmez —
	 * yani "kapattık" denen şey yarım kalır.
	 */
	if locked, err := s.store.HostAccountsAwaitingDecision(ctx); err != nil {
		out = append(out, notification{
			Kind: "error", At: time.Now(),
			Summary: "Locked accounts could not be read",
			Detail:  err.Error(), Section: "hostaccounts",
		})
	} else {
		for _, a := range locked {
			origin := "postern opened this account"
			if a.Origin == store.OriginAdopted {
				origin = "the account was already there when postern first saw it"
			}
			out = append(out, notification{
				Kind: "account.locked", At: a.UpdatedAt,
				Summary: a.OSUser + " is locked on " + a.TargetName,
				Detail: "No group grants this target any more, so the account was locked. " +
					origin + "; the home directory is untouched until someone decides.",
				Section: "hostaccounts",
			})
		}
	}

	// En eski bekleyen üstte: en uzun süredir duran iş, en çok bakılması
	// gereken iş.
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })

	writeJSON(w, http.StatusOK, map[string]any{"items": out, "count": len(out)})
}
