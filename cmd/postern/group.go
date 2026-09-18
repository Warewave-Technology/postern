package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Warewave-Technology/postern/internal/config"
	"github.com/Warewave-Technology/postern/internal/store"
)

// newGroupCmd, grup yönetimi. Yetki modeli için user.go'daki nota bak.
func newGroupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "group",
		Short: "Manage groups",
	}
	cmd.AddCommand(newGroupAddCmd())
	cmd.AddCommand(newGroupListCmd())
	cmd.AddCommand(newGroupRevokeTargetCmd())
	cmd.AddCommand(newGroupPathCmd())
	cmd.AddCommand(newGroupSudoCmd())
	return cmd
}

// newGroupAddCmd, grubu tek komutta tanımlar ve istenirse hedeflere bağlar:
//
//	postern group add --name ops --target web01 --target db01
//
// Kısmi başarı stratejisi user/target add ile aynı: grup zaten varsa komut
// grant'lerle devam eder (GrantTarget idempotent) — grubun user'daki
// os_user gibi çelişebilecek bir kimlik alanı olmadığı için karşılaştırma
// da gerekmiyor. Hedef yoksa açık hata: "yoksa oluştur" davranışı yazım
// hatasını sessizce yeni bir hedefe çevirirdi.
func newGroupAddCmd() *cobra.Command {
	var configPath, name string
	var targets []string

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Create a group and optionally grant targets",
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

			_, err = db.CreateGroup(ctx, name)
			switch {
			case errors.Is(err, store.ErrConflict):
				fmt.Fprintf(out, "group %q already exists, updating grants\n", name)
			case err != nil:
				return err
			default:
				if aerr := auditCLI(ctx, db, "group.create", name, ""); aerr != nil {
					return aerr
				}
				fmt.Fprintf(out, "group %q created\n", name)
			}

			for _, target := range targets {
				if err := db.GrantTarget(ctx, name, target); err != nil {
					if errors.Is(err, store.ErrNotFound) {
						return fmt.Errorf("target %q not found — register it with `postern target add`, then re-run this command (already-applied grants are kept)", target)
					}
					return err
				}
				if aerr := auditCLI(ctx, db, "group.grant", name,
					"granted target "+target); aerr != nil {
					return aerr
				}
				fmt.Fprintf(out, "  target %q granted\n", target)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "path to the config file")
	cmd.Flags().StringVar(&name, "name", "", "group name (required)")
	cmd.Flags().StringArrayVar(&targets, "target", nil, "target to grant (repeatable)")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}
