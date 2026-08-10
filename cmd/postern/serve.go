package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/warewave/postern/internal/config"
	"github.com/warewave/postern/internal/sshd"
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

			logger.Info("config loaded",
				"listen", cfg.Listen.Addr,
				"targets", len(cfg.Targets),
				"users", len(cfg.Users),
			)

			// S1.2: burada sshd.Server kurulup ListenAndServe çağrılacak.
			s, err := sshd.New(cfg, logger)
			if err != nil {
				return err
			}

			return s.ListenAndServe(context.Background())
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	return cmd
}
