package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/warewave/postern/internal/config"
	"github.com/warewave/postern/internal/store"
)

// newRoleCmd, rol yönetimi. Yetki modeli için user.go'daki nota bak.
func newRoleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "role",
		Short: "Manage roles",
	}
	cmd.AddCommand(newRoleAddCmd())
	return cmd
}

// newRoleAddCmd, rolü tek komutta tanımlar ve istenirse hedeflere bağlar:
//
//	postern role add --name ops --target web01 --target db01
//
// Kısmi başarı stratejisi user/target add ile aynı: rol zaten varsa komut
// grant'lerle devam eder (GrantTarget idempotent) — rolün user'daki
// os_user gibi çelişebilecek bir kimlik alanı olmadığı için karşılaştırma
// da gerekmiyor. Hedef yoksa açık hata: "yoksa oluştur" davranışı yazım
// hatasını sessizce yeni bir hedefe çevirirdi.
func newRoleAddCmd() *cobra.Command {
	var configPath, name string
	var targets []string

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Create a role and optionally grant targets",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}

			ctx := context.Background()

			db, err := store.Open(ctx, cfg.Database.Path)
			if err != nil {
				return err
			}
			defer db.Close()

			out := cmd.OutOrStdout()

			_, err = db.CreateRole(ctx, name)
			switch {
			case errors.Is(err, store.ErrConflict):
				fmt.Fprintf(out, "role %q already exists, updating grants\n", name)
			case err != nil:
				return err
			default:
				fmt.Fprintf(out, "role %q created\n", name)
			}

			for _, target := range targets {
				if err := db.GrantTarget(ctx, name, target); err != nil {
					if errors.Is(err, store.ErrNotFound) {
						return fmt.Errorf("target %q not found — register it with `postern target add`, then re-run this command (already-applied grants are kept)", target)
					}
					return err
				}
				fmt.Fprintf(out, "  target %q granted\n", target)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	cmd.Flags().StringVar(&name, "name", "", "rol adı (zorunlu)")
	cmd.Flags().StringArrayVar(&targets, "target", nil, "eriştirilecek hedef (tekrarlanabilir)")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}
