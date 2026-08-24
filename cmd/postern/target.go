package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/config"
	"github.com/warewave/postern/internal/model"
	"github.com/warewave/postern/internal/store"
)

// newTargetCmd, hedef yönetimi. Yetki modeli için user.go'daki nota bak.
func newTargetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "target",
		Short: "Manage targets",
	}
	cmd.AddCommand(newTargetAddCmd())
	cmd.AddCommand(newTargetListCmd())
	return cmd
}

// newTargetAddCmd, hedefi tek komutta tanımlar ve istenirse rollere bağlar:
//
//	postern target add --name web01 --host 192.168.1.30 --port 22 \
//	    --host-key-file web01.pub --grant-role ops
//
// Kısmi başarı stratejisi user add ile aynı: host key dosyası yazmadan
// önce parse edilir; hedef zaten varsa ve tanımı bayraklarla AYNIYSA
// komut grant'lerle devam eder (GrantTarget idempotent), tanım çelişiyorsa
// açık hata verir — "add" var olanı sessizce değiştirmez.
func newTargetAddCmd() *cobra.Command {
	var configPath, name, host, hostKeyFile string
	var port int
	var grantRoles []string

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Register a target and optionally grant it to roles",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Önce doğrula: bozuk host key, hedef yaratılmadan yakalanmalı.
			// İlk bağlantıda "handshake failed" kovalamak pahalı.
			data, err := os.ReadFile(hostKeyFile)
			if err != nil {
				return fmt.Errorf("host key file: %w", err)
			}
			pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
			if err != nil {
				return fmt.Errorf("host key file %s: not a valid public key: %w", hostKeyFile, err)
			}
			// Kanonik satır saklanır (yorumsuz): aynı anahtarın iki farklı
			// metni iki farklı değer gibi görünmesin. hostKeyCallback'in
			// beklediği format tam olarak bu.
			hostKey := string(ssh.MarshalAuthorizedKey(pub))

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
			want := model.Target{Name: name, Host: host, Port: port, HostKey: hostKey}

			_, err = db.CreateTarget(ctx, want)
			switch {
			case errors.Is(err, store.ErrConflict):
				existing, terr := db.Target(ctx, name)
				if terr != nil {
					return terr
				}
				// Ad karşılaştırması bilerek yok: COLLATE NOCASE yüzünden
				// "Web01" ile "web01" aynı hedef, ve saklanan kanonik ad
				// zaten existing.Name'de.
				if existing.Host != want.Host || existing.Port != want.Port || existing.HostKey != want.HostKey {
					return fmt.Errorf("target %q exists with a different definition (host %s:%d); refusing to change it implicitly",
						name, existing.Host, existing.Port)
				}
				fmt.Fprintf(out, "target %q already exists, updating grants\n", name)
			case err != nil:
				return err
			default:
				fmt.Fprintf(out, "target %q registered\n", name)
			}

			for _, role := range grantRoles {
				// Rol yoksa oluşturMUYORUZ: yazım hatası sessizce yeni bir
				// role dönüşmemeli. Rol yaratmak ayrı, bilinçli bir iş.
				if err := db.GrantTarget(ctx, role, name); err != nil {
					if errors.Is(err, store.ErrNotFound) {
						return fmt.Errorf("role %q not found — create it with `postern role add`, then re-run this command (already-applied grants are kept)", role)
					}
					return err
				}
				fmt.Fprintf(out, "  granted to role %q\n", role)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	cmd.Flags().StringVar(&name, "name", "", "hedef adı (zorunlu)")
	cmd.Flags().StringVar(&host, "host", "", "adres (zorunlu)")
	cmd.Flags().IntVar(&port, "port", 22, "SSH portu")
	cmd.Flags().StringVar(&hostKeyFile, "host-key-file", "", "hedefin host public key dosyası (zorunlu)")
	cmd.Flags().StringArrayVar(&grantRoles, "grant-role", nil, "bu role eriştir (tekrarlanabilir)")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("host")
	_ = cmd.MarkFlagRequired("host-key-file")
	return cmd
}

// newTargetListCmd, hedefleri listeler.
func newTargetListCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List targets",
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

			targets, err := db.Targets(ctx)
			if err != nil {
				return err
			}
			if len(targets) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no targets defined")
				return nil
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tHOST\tPORT\tHOST KEY")

			for _, t := range targets {
				// 550 karakterlik base64 satırı yerine parmak izi: insan
				// için karşılaştırılabilir, `ssh-keygen -lf` ile aynı format.
				fingerprint := "(invalid key)"
				if pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(t.HostKey)); err == nil {
					fingerprint = ssh.FingerprintSHA256(pub)
				}
				fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", t.Name, t.Host, t.Port, fingerprint)
			}

			return w.Flush()
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	return cmd
}
