package main

import (
	"context"
	"fmt"
	"log/slog"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/Warewave-Technology/postern/internal/config"
	"github.com/Warewave-Technology/postern/internal/groupsync"
	"github.com/Warewave-Technology/postern/internal/ldap"
	"github.com/Warewave-Technology/postern/internal/store"
)

// postern sync — dizin senkronizasyonunun durumu ve elle koşturma.
//
// ⚠️ TETİKLEME BİLEREK YALNIZCA CLI'DA. Panelde "şimdi senkronize et"
// düğmesi yok: toplu yetki iptali başlatan bir düğme, çalınmış bir admin
// oturumunun ya da bir XSS'in eline verilmemesi gereken bir kol. Meşru
// ihtiyacı zamanlayıcı zaten karşılıyor.

func newSyncCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Directory synchronisation status and manual runs",
	}
	cmd.AddCommand(newSyncStatusCmd(), newSyncRunCmd())
	return cmd
}

func newSyncStatusCmd() *cobra.Command {
	var limit int

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show recent synchronisation runs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, db, err := openStoreFromConfig(cmd)
			if err != nil {
				return err
			}
			defer db.Close()
			_ = cfg

			runs, err := db.SyncRuns(cmd.Context(), limit)
			if err != nil {
				return err
			}
			if len(runs) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no synchronisation runs yet")
				return nil
			}

			// "Son BAŞARILI koşu" en önemli alan: görülmeyen bir iptal,
			// hiç senkronizasyon olmamasıyla aynı arıza.
			var lastOK time.Time
			for _, r := range runs {
				if r.Outcome == "ok" && !r.FinishedAt.IsZero() {
					lastOK = r.FinishedAt
					break
				}
			}
			if lastOK.IsZero() {
				fmt.Fprintln(cmd.OutOrStdout(),
					"⚠️  no successful run in the listed history")
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "last successful run: %s (%s ago)\n\n",
					lastOK.Format(time.RFC3339), time.Since(lastOK).Round(time.Second))
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "STARTED\tTRIGGER\tOUTCOME\tSEEN\tABSENT\tUNKNOWN\tREVOKED\tREASON")
			for _, r := range runs {
				reason := r.Reason
				if len(reason) > 60 {
					reason = reason[:57] + "..."
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%s\n",
					r.StartedAt.Format(time.RFC3339), r.Trigger, r.Outcome,
					r.Present, r.Absent, r.Unknown, r.Revoked, reason)
			}
			return w.Flush()
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 20, "how many runs to show")
	cmd.Flags().String("config", "postern.yaml", "config dosyası yolu")
	return cmd
}

func newSyncRunCmd() *cobra.Command {
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run a synchronisation now",
		Long: "Run a synchronisation now.\n\n" +
			"Use --dry-run first: it computes and reports every decision " +
			"without writing anything.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, db, err := openStoreFromConfig(cmd)
			if err != nil {
				return err
			}
			defer db.Close()

			logger := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), nil))

			runner := groupsync.NewRunner(db,
				func(c context.Context) (groupsync.Directory, error) {
					return ldap.SourceFromStore(c, db)
				},
				groupsync.Config{
					Timeout: cfg.Sync.TimeoutOrDefault(),
					DryRun:  dryRun || cfg.Sync.DryRun,
					Limits: groupsync.Limits{
						Grace:              cfg.Sync.GraceOrDefault(),
						MaxZeroFraction:    cfg.Sync.MaxZeroFractionOrDefault(),
						MinZeroFloor:       cfg.Sync.MinZeroFloorOrDefault(),
						MaxUnknownFraction: cfg.Sync.MaxUnknownFractionOrDefault(),
						MaxRevokePerRun:    cfg.Sync.MaxRevokePerRunOrDefault(),
					},
				}, logger)

			rep, err := runner.RunOnce(cmd.Context(), "cli")
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "outcome:   %s\n", rep.Outcome)
			if rep.Reason != "" {
				fmt.Fprintf(out, "reason:    %s\n", rep.Reason)
			}
			fmt.Fprintf(out, "considered %d  present %d  absent %d  unknown %d\n",
				rep.Considered, rep.Present, rep.Absent, rep.Unknown)
			fmt.Fprintf(out, "revoked    %d\n", rep.Revoked)

			// Elle verilmiş roller ayrı satırda: "iptal edildi" okuyup
			// erişimin tamamen bittiğini sanmak kolay.
			if len(rep.KeptManual) > 0 {
				fmt.Fprintf(out, "\n⚠️  still reachable — these users kept manually granted roles:\n")
				for _, u := range rep.KeptManual {
					fmt.Fprintf(out, "    %s\n", u)
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "compute and report, write nothing")
	cmd.Flags().String("config", "postern.yaml", "config dosyası yolu")
	return cmd
}

// openStoreFromConfig, config'i yükler ve store'u açar.
func openStoreFromConfig(cmd *cobra.Command) (*config.Config, *store.Store, error) {
	path, err := cmd.Flags().GetString("config")
	if err != nil {
		return nil, nil, err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, nil, err
	}
	db, err := store.Open(cmd.Context(), cfg.Database.DSN)
	if err != nil {
		return nil, nil, err
	}
	return cfg, db, nil
}
