package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/warewave/postern/internal/config"
	"github.com/warewave/postern/internal/store"
)

// newDBCmd, veritabanı bakım komutları.
func newDBCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "db",
		Short: "Database maintenance",
	}
	cmd.AddCommand(newDBMigrateCmd())
	return cmd
}

func newDBMigrateCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Apply pending schema migrations",
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

			currentSchemaVersion, err := db.SchemaVersion(ctx)
			if err != nil {
				return err
			}

			before := currentSchemaVersion

			err = db.Migrate(ctx)
			if err != nil {
				return err
			}

			currentSchemaVersion, err = db.SchemaVersion(ctx)
			if err != nil {
				return err
			}

			// "Zaten günceldi" ile "N adım uyguladım" ayırt edilsin:
			// sessiz bir migrate, ne yaptığını bilmediğin bir migrate'tir.
			if currentSchemaVersion == before {
				fmt.Fprintf(cmd.OutOrStdout(), "already up to date (schema version %d)\n", before)
				return nil
			}

			fmt.Fprintf(cmd.OutOrStdout(), "migrated: schema version %d -> %d\n", before, currentSchemaVersion)

			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	return cmd
}
