package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/Warewave-Technology/postern/internal/config"
	"github.com/Warewave-Technology/postern/internal/store"
)

/*
 * Rolleri okuma ve bir rolden hedef alma.
 *
 * ⚠️ İKİ EKSİK DE AYNI SINIFTAN: depoda fonksiyon var, CLI'dan çağıran
 * yok. store.Roles yazılmıştı ve yalnızca panel okuyordu; store.
 * RevokeTarget yazılmıştı ve yalnızca panel çağırıyordu. Yani host'a
 * girmiş bir operatör hangi rollerin var olduğunu göremiyor ve yanlış
 * verilmiş bir hedefi geri alamıyordu.
 *
 * Bunun neden `user grant-role` ile aynı sürümde olması gerektiği:
 * panelin çalışmadığı gün `user revoke-role` bir kişiyi kesiyor, ama
 * yanlışlıkla role bağlanmış bir makine o rolü taşıyan HERKES için açık
 * kalıyor ve host tarafında geri alınamıyordu. Aynı boşluğu bir seviye
 * yukarıda bırakmak, yarısını düzeltmek olurdu.
 */

func newRoleListCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List roles and the targets they reach",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			ctx := context.Background()
			db, err := store.Open(ctx, cfg.Database.DSN)
			if err != nil {
				return err
			}
			defer db.Close()

			roles, err := db.Roles(ctx)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if len(roles) == 0 {
				// ⚠️ Boş liste SESSİZ GEÇMİYOR. "hiç rol yok" ile
				// "listeyi alamadım" farklı şeyler ve boş bir çıktı
				// ikisini birbirine karıştırırdı.
				fmt.Fprintln(out, "no roles defined")
				return nil
			}

			w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tTARGETS")
			for _, r := range roles {
				targets := "-"
				if len(r.Targets) > 0 {
					targets = strings.Join(r.Targets, ",")
				}
				fmt.Fprintf(w, "%s\t%s\n", r.Name, targets)
			}
			return w.Flush()
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	return cmd
}

func newRoleRevokeTargetCmd() *cobra.Command {
	var configPath, name string
	var targets []string

	cmd := &cobra.Command{
		Use:   "revoke-target",
		Short: "Take a target away from a role",
		Long: "Removes a target from a role. Everyone holding the role loses\n" +
			"that machine at their next connection; sessions already open are\n" +
			"not affected — close those from the panel.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			ctx := context.Background()
			db, err := store.Open(ctx, cfg.Database.DSN)
			if err != nil {
				return err
			}
			defer db.Close()

			out := cmd.OutOrStdout()
			for _, target := range targets {
				/*
				 * ⚠️ "ZATEN BAĞLI DEĞİLDİ" AYRI BİR CÜMLE.
				 *
				 * RevokeTarget de bağ yokken sessiz no-op. Hedef adını
				 * yanlış yazan operatörün "alındı" okuması, erişimin
				 * kapandığını sanması demek olurdu.
				 */
				had, err := roleHasTarget(ctx, db, name, target)
				if err != nil {
					return targetErr(err, name, target)
				}

				if err := db.RevokeTarget(ctx, name, target); err != nil {
					return targetErr(err, name, target)
				}
				// Panelin yazdığı adın aynısı: aynı olay iki adla
				// kaydedilirse denetim sorgusu birini kaçırır.
				if err := auditCLI(ctx, db, "role.revoke", name, "target "+target); err != nil {
					return err
				}

				if had {
					fmt.Fprintf(out, "role %q: target %q revoked\n", name, target)
				} else {
					fmt.Fprintf(out, "role %q did not reach target %q; nothing changed\n",
						name, target)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	cmd.Flags().StringVar(&name, "name", "", "rol adı (zorunlu)")
	cmd.Flags().StringArrayVar(&targets, "target", nil, "alınacak hedef (tekrarlanabilir, zorunlu)")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("target")
	return cmd
}

// roleHasTarget, rolün o hedefe erişip erişmediğini söyler.
func roleHasTarget(ctx context.Context, db *store.Store, name, target string) (bool, error) {
	roles, err := db.Roles(ctx)
	if err != nil {
		return false, err
	}
	for _, r := range roles {
		if r.Name != name {
			continue
		}
		for _, t := range r.Targets {
			if strings.EqualFold(t, target) {
				return true, nil
			}
		}
		return false, nil
	}
	return false, fmt.Errorf("store.Roles: no role %q: %w", name, store.ErrNotFound)
}

/*
 * targetErr, "not found"u hangi adın yanlış olduğunu söyleyen bir
 * cümleye çevirir.
 *
 * ⚠️ roleHasTarget rolü ZATEN doğruluyor ve rol yoksa kendi hatasını
 * veriyor; buraya düşen not-found hedef adına dair. İç zincir gövdeye
 * gitmiyor: operatöre "sql: no rows in result set" göstermek, hangi
 * adı düzelteceğini söylememek demek.
 */
func targetErr(err error, name, target string) error {
	if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if strings.Contains(err.Error(), "no role") {
		return fmt.Errorf("no role %q — see `postern role list`", name)
	}
	return fmt.Errorf("no target %q — see `postern target list`", target)
}
