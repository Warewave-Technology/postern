package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/config"
	"github.com/warewave/postern/internal/ldap"
	"github.com/warewave/postern/internal/secret"
	"github.com/warewave/postern/internal/store"
)

// newSecretCmd, sır anahtarı yönetimi.
func newSecretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Manage the key that seals stored secrets",
	}
	cmd.AddCommand(newSecretInitCmd())
	return cmd
}

func newSecretInitCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create the master key for encrypted settings",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			if cfg.SecretKeyFile == "" {
				return fmt.Errorf("secret_key_file is not set in %s", configPath)
			}

			// Init var olan anahtarın üstüne yazmaz: yazsaydı o anahtarla
			// mühürlenmiş her sır kalıcı olarak okunamaz hale gelirdi.
			if _, err := secret.Init(cfg.SecretKeyFile); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "secret key written to %s\n", cfg.SecretKeyFile)
			fmt.Fprintln(cmd.OutOrStdout(),
				"keep it out of the database's backup path — together they defeat the encryption")
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	return cmd
}

// newSettingsCmd, çalışma zamanı ayarları.
func newSettingsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "settings",
		Short: "Manage runtime settings stored in the database",
	}
	cmd.AddCommand(newSettingsSetCmd())
	cmd.AddCommand(newSettingsListCmd())
	cmd.AddCommand(newSettingsTestLDAPCmd())
	return cmd
}

// openStoreWithSecrets, sır anahtarı bağlanmış store döner.
func openStoreWithSecrets(configPath string) (*store.Store, context.Context, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()
	db, err := store.Open(ctx, cfg.Database.DSN)
	if err != nil {
		return nil, nil, err
	}
	if cfg.SecretKeyFile != "" {
		box, err := secret.Load(cfg.SecretKeyFile)
		if err != nil {
			db.Close()
			return nil, nil, err
		}
		db.UseSecretBox(box)
	}
	return db, ctx, nil
}

func newSettingsSetCmd() *cobra.Command {
	var configPath, key, value string
	var isSecret bool

	cmd := &cobra.Command{
		Use:   "set",
		Short: "Set a runtime setting",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			db, ctx, err := openStoreWithSecrets(configPath)
			if err != nil {
				return err
			}
			defer db.Close()

			// Sır bilinen anahtarlarda otomatik: yönetici --secret
			// yazmayı unutup parolayı düz metin bırakmasın.
			if ldap.SecretKeys[key] {
				isSecret = true
			}

			// Sır değeri komut satırında GEÇMEZ: kabuk geçmişine ve
			// süreç listesine (ps) düşer. Terminalden yankısız okunur.
			if isSecret && value == "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "value for %s: ", key)
				raw, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Fprintln(cmd.ErrOrStderr())
				if err != nil {
					return fmt.Errorf("reading value: %w", err)
				}
				value = strings.TrimSpace(string(raw))
			}

			if err := db.SetSetting(ctx, key, value, isSecret, cliActor()); err != nil {
				return err
			}

			if isSecret {
				fmt.Fprintf(cmd.OutOrStdout(), "%s set (encrypted, not shown again)\n", key)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "%s = %s\n", key, value)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	cmd.Flags().StringVar(&key, "key", "", "ayar adı, örn. ldap.url (zorunlu)")
	cmd.Flags().StringVar(&value, "value", "", "değer; sırlar için boş bırak, terminalden sorulur")
	cmd.Flags().BoolVar(&isSecret, "secret", false, "değeri şifreleyerek sakla (--secret=true)")
	_ = cmd.MarkFlagRequired("key")
	return cmd
}

func newSettingsListCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List runtime settings (secrets masked)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			db, ctx, err := openStore(configPath)
			if err != nil {
				return err
			}
			defer db.Close()

			views, err := db.Settings(ctx)
			if err != nil {
				return err
			}
			if len(views) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no settings stored")
				return nil
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "KEY\tVALUE\tUPDATED\tBY")
			for _, v := range views {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", v.Key, v.Value,
					v.UpdatedAt.Local().Format("2006-01-02 15:04"), v.UpdatedBy)
			}
			return w.Flush()
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	return cmd
}

// newSettingsTestLDAPCmd, yapılandırmayı gerçekten deneyerek doğrular.
//
// Kullanıcının istediği "config test" bu: yanlış base DN ya da bind
// parolası ilk gerçek girişte değil, burada ortaya çıksın.
func newSettingsTestLDAPCmd() *cobra.Command {
	var configPath, username string

	cmd := &cobra.Command{
		Use:   "test-ldap",
		Short: "Test the stored LDAP configuration",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			db, ctx, err := openStoreWithSecrets(configPath)
			if err != nil {
				return err
			}
			defer db.Close()

			src, err := ldap.SourceFromStore(ctx, db)
			if err != nil {
				if errors.Is(err, ldap.ErrNotConfigured) {
					return fmt.Errorf("ldap is not configured (set %s first)", ldap.KeyURL)
				}
				return err
			}

			out := cmd.OutOrStdout()
			if err := src.Test(ctx); err != nil {
				return err
			}
			fmt.Fprintln(out, "connection and bind: ok")

			// Kullanıcı verildiyse gerçek bir arama yap: filtrenin
			// çalıştığını görmenin tek yolu.
			if username != "" {
				res, err := src.Groups(ctx, authIdentity(username))
				if err != nil {
					return err
				}
				// ⚠️ ÜÇ AYRI CEVAP, ÜÇ AYRI MESAJ. Eskiden üçü de "found
				// no groups" diye çıkıyordu ve "dizin bu kullanıcıyı
				// tanımıyor" ile "tanıyor ama grubu yok" aynı satıra
				// düşüyordu; ilkinde operatör grup ayarlarını
				// kurcalayarak saatler harcıyordu.
				switch res.Presence {
				case auth.GroupsAbsent:
					fmt.Fprintf(out, "user %q: the directory answered, and it has no such user "+
						"(check user_base and user_filter; postern looks the name up as given)\n", username)
					return nil
				case auth.GroupsUnknown:
					fmt.Fprintf(out, "user %q: the directory could not answer for this name\n", username)
					return nil
				}
				groups := res.Groups
				if len(groups) == 0 {
					fmt.Fprintf(out, "user %q: found in the directory, but in no groups within scope\n", username)
					return nil
				}
				fmt.Fprintf(out, "user %q groups: %s\n", username, strings.Join(groups, ", "))

				// Hangileri role dönüşüyor: eşlemenin çalışıp
				// çalışmadığını burada gör.
				roles, unmapped, err := db.RolesForGroups(ctx, groups)
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "  mapped to roles: %s\n", joinOrDash(roles))
				fmt.Fprintf(out, "  unmapped groups: %s\n", joinOrDash(unmapped))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	cmd.Flags().StringVar(&username, "user", "", "bu kullanıcının gruplarını da sorgula")
	return cmd
}

// authIdentity, test komutunun ihtiyaç duyduğu asgari kimlik.
func authIdentity(username string) auth.Identity {
	return auth.Identity{Username: username}
}

func joinOrDash(v []string) string {
	if len(v) == 0 {
		return "-"
	}
	return strings.Join(v, ", ")
}
