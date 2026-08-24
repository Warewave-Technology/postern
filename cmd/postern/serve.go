package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/warewave/postern/internal/config"
	"github.com/warewave/postern/internal/sshd"
	"github.com/warewave/postern/internal/store"
)

func newServeCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the bastion (SSH listener)",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

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

			pending, err := db.PendingMigrations(ctx)
			if err != nil {
				return err
			}
			if pending > 0 {
				return fmt.Errorf("schema is %d migration(s) behind; run `postern db migrate` first", pending)
			}

			logger.Info("config loaded",
				"listen", cfg.Listen.Addr,
				"database", cfg.Database.Path,
			)

			s, err := sshd.New(cfg, db, logger)
			if err != nil {
				return err
			}

			return s.ListenAndServe(ctx)
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	return cmd
}
