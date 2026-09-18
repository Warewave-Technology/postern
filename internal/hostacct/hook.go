package hostacct

/*
 * Sıcak yolun kablolanmış hâli.
 *
 * ⚠️ TEK YERDE KURULUYOR, ÇÜNKÜ İKİ KAPI VAR. SSH kanalı ve panelin web
 * terminali aynı proxy.Deps'ten geçiyor; kancayı iki yerde kurmak,
 * birinde unutulduğunda "terminalden girince hesap açılıyor, ssh'tan
 * girince açılmıyor" gibi açıklanamaz bir fark üretirdi.
 */

import (
	"context"
	"log/slog"
	"time"

	"github.com/Warewave-Technology/postern/internal/ca"
	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/provision"
	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/upstream"
)

/*
 * Hook, proxy.Deps.EnsureAccount'a takılacak fonksiyonu üretir.
 *
 * ⚠️ DÖNEN HATA OTURUMU KESMİYOR — çağıran onu yalnızca dial hatasına
 * ekliyor (bkz. proxy.Deps.EnsureAccount). Burada hata döndürmek,
 * "hazırlanamadı" cümlesini taşımanın yolu; "içeri alma" emri değil.
 */
func Hook(db *store.Store, authority *ca.CA, logger *slog.Logger) func(context.Context, model.User, model.Target) error {
	deps := Deps{
		Rules: db.GroupSudoRules,
		Row:   db.HostAccountFor,
		Save:  db.SaveHostAccount,
		Connect: func(ctx context.Context, t model.Target, reason string) (Runner, error) {
			return provision.Connect(ctx, t, authority, "system", reason)
		},
		Caps: func(ctx context.Context, r Runner) (upstream.ManageCapabilities, error) {
			sr, ok := r.(*provision.SSHRunner)
			if !ok {
				return upstream.ManageCapabilities{}, errNotSSH
			}

			return sr.Conn().Capabilities(ctx)
		},
		Audit: func(ctx context.Context, target, detail string) error {
			/*
			 * ⚠️ HEDEFE YAZILDIĞINDA DEFTERE SATIR, HIZLI ŞERİTTE YOK.
			 * Her bağlantı satır yazsaydı defter, hiçbir şeyin
			 * değişmediği milyonlarca satırla dolar ve içindeki gerçek
			 * yazma olayları görünmez olurdu.
			 */
			return db.LogAdmin(ctx, store.AdminLogEntry{
				At: time.Now(), Actor: "system", Via: "sync",
				Action: "account.provision", Entity: target, Details: detail,
			})
		},
	}

	return func(ctx context.Context, u model.User, t model.Target) error {
		out := Ensure(ctx, deps, u, t)
		if out.Reason != "" {
			return errReason(out.Reason)
		}
		if out.Wrote && logger != nil {
			logger.Info("prepared an account on a target",
				"target", t.Name, "user", u.Name, "os_user", u.OSUser)
		}

		return nil
	}
}

type errReason string

func (e errReason) Error() string { return string(e) }

const errNotSSH = errReason("the management connection is not an SSH runner")
