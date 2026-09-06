package main

// Rol başına SFTP yol kuralları.

import (
	"context"
	"errors"
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/Warewave-Technology/postern/internal/config"
	"github.com/Warewave-Technology/postern/internal/store"
)

// newRolePathCmd, yol kurallarının yönetimi.
func newRolePathCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "path",
		Short: "Manage the SFTP path rules of a role",
		Long: "Rules decide which paths a role may reach over SFTP.\n\n" +
			"A role with no rules is unrestricted, which is what every role is\n" +
			"before you write the first one. Restriction starts when a rule is\n" +
			"added, so upgrading does not change anybody's access. One ruleless\n" +
			"role therefore keeps everything open — rules restrict a ROLE, not a\n" +
			"user — and the panel's file browser refuses to open at all until at\n" +
			"least one rule exists.\n\n" +
			"The rules of every role a user holds are pooled, and the LONGEST\n" +
			"matching prefix decides. That is how a branch is carved out of an\n" +
			"allowed tree. At equal length a --deny beats an --allow, including\n" +
			"one written on a different role: an explicit refusal cannot be\n" +
			"reopened by a second role granting the same prefix. A LONGER allow\n" +
			"still wins, so a deny is not a blanket veto over everything beneath\n" +
			"it — write the deny at or below the depth you mean.\n\n" +
			"Prefixes match at directory boundaries: /home/user does not match\n" +
			"/home/username.\n\n" +
			"Two exceptions worth knowing:\n\n" +
			"  - realpath on a relative path is answered without a rule. A client\n" +
			"    asks it before it knows any absolute path at all, so refusing it\n" +
			"    would end the session before the first rule could apply.\n" +
			"  - rename, symlink and link are checked on BOTH paths. Checking one\n" +
			"    would leave moving a file out of a denied tree wide open.\n\n" +
			"What this cannot see: symbolic links. postern has no access to the\n" +
			"target filesystem, so a link inside an allowed directory pointing\n" +
			"elsewhere looks allowed. The rules constrain the path the CLIENT\n" +
			"writes, not where the target resolves it.",
	}
	cmd.AddCommand(newRolePathSetCmd())
	cmd.AddCommand(newRolePathListCmd())
	cmd.AddCommand(newRolePathRemoveCmd())

	return cmd
}

func newRolePathSetCmd() *cobra.Command {
	var configPath, role, prefix string
	var deny, write bool

	cmd := &cobra.Command{
		Use:   "set",
		Short: "Add or update a path rule",
		Long: "Grants a role access to a path prefix.\n\n" +
			"  postern role path set --role dev --prefix /home/dev --write\n" +
			"  postern role path set --role dev --prefix /home/dev/.ssh --deny\n\n" +
			"Without --write the rule is read-only. --deny makes it an explicit\n" +
			"refusal, which is how a branch is carved out of an allowed tree.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if deny && write {
				return errors.New("--deny and --write contradict each other: a refusal grants nothing")
			}

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

			if err := db.SetRolePath(ctx, role, prefix, !deny, write); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					return fmt.Errorf("role %q not found — create it with `postern role add`", role)
				}
				return err
			}

			verb := "read"
			if deny {
				verb = "denied"
			} else if write {
				verb = "read+write"
			}
			if aerr := auditCLI(ctx, db, "role.path.set", role,
				prefix+" ("+verb+")"); aerr != nil {
				return aerr
			}

			fmt.Fprintf(cmd.OutOrStdout(), "rule set: %s %s on role %q\n", prefix, verb, role)

			/*
			 * ⚠️ İLK KURAL BİR EŞİK. O ana kadar rol kısıtsızdı; ilk
			 * kuralla birlikte KAPSAMADIĞI her yol kapanıyor. Bunu
			 * söylememek, yöneticinin bir dizine izin verdiğini sanıp
			 * aslında geri kalan her şeyi kapattığını fark etmemesi
			 * demek olurdu.
			 */
			rules, rerr := db.RolePaths(ctx, role)
			if rerr == nil && len(rules) == 1 {
				fmt.Fprintf(cmd.OutOrStdout(),
					"\nThis is the first rule on %q. The role was unrestricted until now;\n"+
						"from here on every path it does not cover is refused.\n", role)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "path to the config file")
	cmd.Flags().StringVar(&role, "role", "", "role name (required)")
	cmd.Flags().StringVar(&prefix, "prefix", "", "absolute path prefix, e.g. /home/dev (required)")
	cmd.Flags().BoolVar(&write, "write", false, "allow writes as well as reads")
	cmd.Flags().BoolVar(&deny, "deny", false, "refuse this prefix instead of allowing it")
	_ = cmd.MarkFlagRequired("role")
	_ = cmd.MarkFlagRequired("prefix")

	return cmd
}

func newRolePathListCmd() *cobra.Command {
	var configPath, role string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "Show the path rules of a role",
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

			rules, err := db.RolePaths(ctx, role)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if len(rules) == 0 {
				fmt.Fprintf(out, "role %q has no path rules and is unrestricted over SFTP\n", role)
				return nil
			}

			w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "PREFIX\tACCESS")
			for _, r := range rules {
				access := "read"
				switch {
				case !r.Allow:
					access = "denied"
				case r.CanWrite:
					access = "read+write"
				}
				fmt.Fprintf(w, "%s\t%s\n", r.Prefix, access)
			}

			return w.Flush()
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "path to the config file")
	cmd.Flags().StringVar(&role, "role", "", "role name (required)")
	_ = cmd.MarkFlagRequired("role")

	return cmd
}

func newRolePathRemoveCmd() *cobra.Command {
	var configPath, role, prefix string

	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove a path rule",
		Long: "Removing the LAST rule makes the role unrestricted again, which is\n" +
			"the opposite of what removing a rule usually suggests. The command\n" +
			"says so when it happens.",
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

			if err := db.DeleteRolePath(ctx, role, prefix); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					return fmt.Errorf("role %q has no rule for %q", role, prefix)
				}
				return err
			}
			if aerr := auditCLI(ctx, db, "role.path.remove", role, prefix); aerr != nil {
				return aerr
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "rule removed: %s from role %q\n", prefix, role)

			/*
			 * ⚠️ SON KURALI SİLMEK ROLÜ AÇIYOR. "Kural sil" cümlesi
			 * sezgisel olarak daraltmayı düşündürüyor; burada tersi
			 * oluyor ve sessiz kalmak kabul edilemez.
			 */
			if rules, rerr := db.RolePaths(ctx, role); rerr == nil && len(rules) == 0 {
				fmt.Fprintf(out,
					"\nThat was the last rule on %q. The role is now UNRESTRICTED over\n"+
						"SFTP: every path it can reach a target on is allowed again.\n", role)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "path to the config file")
	cmd.Flags().StringVar(&role, "role", "", "role name (required)")
	cmd.Flags().StringVar(&prefix, "prefix", "", "the prefix to remove (required)")
	_ = cmd.MarkFlagRequired("role")
	_ = cmd.MarkFlagRequired("prefix")

	return cmd
}
