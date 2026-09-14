package main

// Rolün taşıdığı sudo kuralı.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Warewave-Technology/postern/internal/config"
	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/sudoers"
)

// newRoleSudoCmd, rolün sudo kuralının yönetimi.
func newRoleSudoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sudo",
		Short: "Manage the sudo rule a role carries on the machines it reaches",
		Long: "A role's rule is written on a target as a group rule:\n\n" +
			"  %<role> ALL=(root) NOPASSWD: <commands>\n\n" +
			"in /etc/sudoers.d/postern-<role>. Everyone in the role draws it from\n" +
			"membership in that group, so the rule is written once instead of per\n" +
			"person. What a temporary grant adds on top is written into the\n" +
			"account's own file and leaves with the account.\n\n" +
			"A role carries one rule with as many commands as it needs: on the\n" +
			"target a group has a single sudoers file.\n\n" +
			"The rule reaches a machine the next time postern works on it — today\n" +
			"that means when a temporary account is opened there. Writing a rule\n" +
			"here does not push it to every target the role can reach, and\n" +
			"removing one does not take the file off machines that already have\n" +
			"it.\n\n" +
			"A command that can start another program (an editor, a pager,\n" +
			"find -exec) hands out a root shell. Such a rule is refused unless\n" +
			"--i-accept-a-root-shell says the risk was understood.",
	}
	cmd.AddCommand(newRoleSudoSetCmd())
	cmd.AddCommand(newRoleSudoShowCmd())
	cmd.AddCommand(newRoleSudoRemoveCmd())

	return cmd
}

func newRoleSudoSetCmd() *cobra.Command {
	var configPath, role, runAs string
	var commands []string
	var accept bool

	cmd := &cobra.Command{
		Use:   "set",
		Short: "Write the role's sudo rule",
		Long: "Replaces the role's rule with the commands given.\n\n" +
			"  postern role sudo set --role dba \\\n" +
			"      --command '/usr/bin/pg_ctl reload' \\\n" +
			"      --command '/usr/sbin/nginx -t'\n\n" +
			"Each --command is one sudoers entry: the first word is the path, the\n" +
			"rest are the arguments it is allowed to take. --run-as defaults to\n" +
			"root.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(commands) == 0 {
				return errors.New("--command is required: a rule with no command grants nothing")
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

			rule := sudoers.Rule{RunAs: runAs, Acknowledged: accept}
			for _, c := range commands {
				fields := strings.Fields(c)
				if len(fields) == 0 {
					continue
				}
				rule.Commands = append(rule.Commands,
					sudoers.Command{Path: fields[0], Args: fields[1:]})
			}

			if err := db.SetRoleSudo(ctx, role, rule, cliActor()); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					return fmt.Errorf("role %q not found — create it with `postern role add`", role)
				}
				return err
			}
			if aerr := auditCLI(ctx, db, "role.sudo_set", role, describeCLIRule(rule)); aerr != nil {
				return aerr
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "sudo rule written on role %q\n", role)
			/*
			 * ⚠️ ROLÜN ANLAMI DEĞİŞTİ VE BU SÖYLENİYOR. O ana kadar rol
			 * "şu makinelere erişebilir" demekti; artık "şu komutları root
			 * olarak çalıştırabilir" de diyor. Rolü birine vermek bundan
			 * sonra daha fazlasını veriyor.
			 */
			fmt.Fprintf(out,
				"\nEveryone in %q now gets these commands with sudo on the machines it\n"+
					"reaches. The rule lands on a machine the next time postern works on\n"+
					"it; the ones it has not touched yet still carry what they had.\n", role)

			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "path to the config file")
	cmd.Flags().StringVar(&role, "role", "", "role that carries the rule (required)")
	cmd.Flags().StringArrayVar(&commands, "command", nil,
		"a command the role may run, with its arguments (repeatable)")
	cmd.Flags().StringVar(&runAs, "run-as", "", "user the commands run as (default root)")
	cmd.Flags().BoolVar(&accept, "i-accept-a-root-shell", false,
		"write the rule even though a command in it can start another program")
	_ = cmd.MarkFlagRequired("role")

	return cmd
}

func newRoleSudoShowCmd() *cobra.Command {
	var configPath, role string

	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show the role's sudo rule",
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

			rs, err := db.RoleSudoRule(ctx, role)
			if errors.Is(err, store.ErrNotFound) {
				fmt.Fprintf(cmd.OutOrStdout(),
					"role %q carries no sudo rule; its members get whatever the machine\n"+
						"already gives them and whatever a temporary grant adds.\n", role)
				return nil
			}
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			runAs := rs.Rule.RunAs
			if runAs == "" {
				runAs = "root"
			}
			fmt.Fprintf(out, "role %s — written by %s on %s\n",
				rs.Role, rs.UpdatedBy, rs.UpdatedAt.Format("2006-01-02 15:04 MST"))
			fmt.Fprintf(out, "file on each target: /etc/sudoers.d/postern-%s\n", rs.Role)
			fmt.Fprintf(out, "runs as: %s\n", runAs)
			for _, c := range rs.Rule.Commands {
				fmt.Fprintf(out, "  %s\n", c.String())
			}
			if rs.Rule.Acknowledged {
				fmt.Fprintln(out,
					"\nA command in this rule can start another program, which is a way to a\n"+
						"root shell. Someone accepted that when the rule was written.")
			}

			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "path to the config file")
	cmd.Flags().StringVar(&role, "role", "", "role to show (required)")
	_ = cmd.MarkFlagRequired("role")

	return cmd
}

func newRoleSudoRemoveCmd() *cobra.Command {
	var configPath, role string

	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove the role's sudo rule",
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

			if err := db.DeleteRoleSudo(ctx, role); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					return fmt.Errorf("role %q carries no sudo rule", role)
				}
				return err
			}
			if aerr := auditCLI(ctx, db, "role.sudo_delete", role, "rule removed"); aerr != nil {
				return aerr
			}

			/*
			 * ⚠️ "SİLDİM" YETKİNİN KALKTIĞI ANLAMINA GELMİYOR. Kural
			 * postern'de gitti; dosyayı taşıyan makineler onu postern
			 * oraya bir daha dokunana kadar taşımaya devam ediyor.
			 * Söylenmezse operatör kaldırmadığı bir yetkiyi kaldırdığını
			 * sanır.
			 */
			fmt.Fprintf(cmd.OutOrStdout(),
				"sudo rule removed from role %q in postern.\n\n"+
					"Machines that already have /etc/sudoers.d/postern-%s keep it until\n"+
					"postern next works on them. Take it off a machine now with\n"+
					"`sudo rm /etc/sudoers.d/postern-%s` there.\n", role, role, role)

			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "path to the config file")
	cmd.Flags().StringVar(&role, "role", "", "role to clear (required)")
	_ = cmd.MarkFlagRequired("role")

	return cmd
}

// describeCLIRule, denetim satırının gövdesi: ne verildiği yazılıyor.
func describeCLIRule(r sudoers.Rule) string {
	runAs := r.RunAs
	if runAs == "" {
		runAs = "root"
	}
	cmds := make([]string, 0, len(r.Commands))
	for _, c := range r.Commands {
		cmds = append(cmds, c.String())
	}
	line := "as " + runAs + ": " + strings.Join(cmds, ", ")
	if r.Acknowledged {
		line += "; acknowledged as a way out to a root shell"
	}

	return line
}
