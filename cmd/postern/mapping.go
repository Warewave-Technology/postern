package main

import (
	"context"
	"errors"
	"fmt"
	"os/user"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/warewave/postern/internal/config"
	"github.com/warewave/postern/internal/store"
)

// newMappingCmd, dış grup → rol eşlemesi yönetimi.
//
// Yetki modeli user.go'daki notla aynı: bastion hostunda, veritabanına
// erişebilen kişi çalıştırır.
func newMappingCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mapping",
		Short: "Manage IdP group to role mappings",
	}
	cmd.AddCommand(newMappingAddCmd())
	cmd.AddCommand(newMappingListCmd())
	cmd.AddCommand(newMappingRemoveCmd())
	cmd.AddCommand(newMappingUnmappedCmd())
	return cmd
}

func openStore(configPath string) (*store.Store, context.Context, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()
	db, err := store.Open(ctx, cfg.Database.DSN)
	if err != nil {
		return nil, nil, err
	}
	return db, ctx, nil
}

func newMappingAddCmd() *cobra.Command {
	var configPath, group, role string

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Map an IdP group to a role",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			db, ctx, err := openStore(configPath)
			if err != nil {
				return err
			}
			defer db.Close()

			if err := db.AddGroupMapping(ctx, group, role, cliActor()); err != nil {
				if errors.Is(err, store.ErrConflict) {
					return fmt.Errorf("group %q is already mapped to role %q", group, role)
				}
				if errors.Is(err, store.ErrNotFound) {
					return fmt.Errorf("role %q not found — create it with `postern role add`", role)
				}
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "group %q mapped to role %q\n", group, role)
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	cmd.Flags().StringVar(&group, "group", "", "IdP/LDAP grup adı (zorunlu)")
	cmd.Flags().StringVar(&role, "role", "", "postern rolü (zorunlu)")
	_ = cmd.MarkFlagRequired("group")
	_ = cmd.MarkFlagRequired("role")
	return cmd
}

func newMappingRemoveCmd() *cobra.Command {
	var configPath, group, role string

	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove a group to role mapping",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			db, ctx, err := openStore(configPath)
			if err != nil {
				return err
			}
			defer db.Close()

			if err := db.RemoveGroupMapping(ctx, group, role); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					return fmt.Errorf("no mapping from %q to %q", group, role)
				}
				return err
			}
			// Etki alanını açıkça söyle: mevcut oturumlar ve atamalar
			// bir sonraki girişe kadar değişmez.
			fmt.Fprintf(cmd.OutOrStdout(),
				"mapping removed (affects users on their next login)\n")
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	cmd.Flags().StringVar(&group, "group", "", "IdP/LDAP grup adı (zorunlu)")
	cmd.Flags().StringVar(&role, "role", "", "postern rolü (zorunlu)")
	_ = cmd.MarkFlagRequired("group")
	_ = cmd.MarkFlagRequired("role")
	return cmd
}

func newMappingListCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List group to role mappings",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			db, ctx, err := openStore(configPath)
			if err != nil {
				return err
			}
			defer db.Close()

			mappings, err := db.GroupMappings(ctx)
			if err != nil {
				return err
			}
			if len(mappings) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no group mappings defined")
				return nil
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "IDP GROUP\tROLE\tCREATED\tBY")
			for _, m := range mappings {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", m.ExternalGroup, m.Role,
					m.CreatedAt.Local().Format("2006-01-02"), m.CreatedBy)
			}
			return w.Flush()
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	return cmd
}

// newMappingUnmappedCmd, IdP'nin gönderdiği ama eşlenmemiş grupları
// gösterir — "eşleme neden çalışmıyor" sorusunun teşhis aracı.
func newMappingUnmappedCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "unmapped",
		Short: "Show IdP groups seen at login but not mapped to any role",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			db, ctx, err := openStore(configPath)
			if err != nil {
				return err
			}
			defer db.Close()

			groups, err := db.UnmappedGroups(ctx)
			if err != nil {
				return err
			}
			if len(groups) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no unmapped groups seen yet")
				return nil
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "IDP GROUP\tTIMES SEEN\tLAST SEEN")
			for _, g := range groups {
				fmt.Fprintf(w, "%s\t%d\t%s\n", g.Name, g.SeenCount,
					g.LastSeen.Local().Format("2006-01-02 15:04"))
			}
			if err := w.Flush(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"\nmap one with:  postern mapping add --group <name> --role <role>\n")
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	return cmd
}

// cliActor, CLI'dan yapılan değişikliklerin aktörü: işletim sistemi
// kullanıcısı. Yetki modeli zaten dosya erişimine dayanıyor (S3
// sözleşmesi), aktör de o.
func cliActor() string {
	if u := osUsername(); u != "" {
		return u
	}
	return "cli"
}

// osUsername, süreci çalıştıran işletim sistemi kullanıcısını döner.
func osUsername() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}
