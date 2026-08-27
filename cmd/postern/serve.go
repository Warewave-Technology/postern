package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/config"
	"github.com/warewave/postern/internal/httpapi"
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

			// OOB girişi yalnızca yapılandırıldıysa: OIDC discovery +
			// login kaydı + HTTP dinleyicisi. Yoksa bastion eskisi gibi
			// yalnızca public key kabul eder.
			if cfg.OOBEnabled() {
				oidcClient, err := auth.NewOIDC(ctx, auth.OIDCConfig{
					IssuerURL:    cfg.OIDC.IssuerURL,
					ClientID:     cfg.OIDC.ClientID,
					ClientSecret: cfg.OIDC.ClientSecret,
					RedirectURL:  strings.TrimRight(cfg.HTTP.ExternalURL, "/") + "/auth/callback",
				})
				if err != nil {
					return err
				}

				logins := auth.NewLogins(oidcClient)
				s.EnableOOB(logins, 0)

				api := &http.Server{
					Addr:    cfg.HTTP.Addr,
					Handler: httpapi.New(oidcClient, logins, db, logger).Handler(),
				}
				go func() {
					logger.Info("http listener started", "addr", cfg.HTTP.Addr)
					if err := api.ListenAndServe(); err != nil && err != http.ErrServerClosed {
						logger.Error("http listener failed", "error", err)
					}
				}()
				defer api.Shutdown(context.Background())

				logger.Info("oob login enabled", "issuer", cfg.OIDC.IssuerURL)
			}

			return s.ListenAndServe(ctx)
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	return cmd
}
