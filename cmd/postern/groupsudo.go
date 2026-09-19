package main

// Rolün taşıdığı sudo kuralı.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Warewave-Technology/postern/v2/internal/config"
	"github.com/Warewave-Technology/postern/v2/internal/store"
	"github.com/Warewave-Technology/postern/v2/internal/sudoers"
)

// newGroupSudoCmd, grubun sudo kuralının yönetimi.
func newGroupSudoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sudo",
		Short: "Manage the sudo rule a group carries on the machines it reaches",
		Long: "A group's rule is written on a target as a group rule:\n\n" +
			"  %<group> ALL=(root) NOPASSWD: <commands>\n\n" +
			"in /etc/sudoers.d/postern-<group>. Everyone in the group draws it from\n" +
			"membership in that group, so the rule is written once instead of per\n" +
			"person. What a temporary grant adds on top is written into the\n" +
			"account's own file and leaves with the account.\n\n" +
			"A group carries one rule with as many commands as it needs: on the\n" +
			"target a group has a single sudoers file.\n\n" +
			"The rule reaches a machine the next time postern works on it — today\n" +
			"that means when a temporary account is opened there. Writing a rule\n" +
			"here does not push it to every target the group can reach, and\n" +
			"removing one does not take the file off machines that already have\n" +
			"it.\n\n" +
			"A command that can start another program (an editor, a pager,\n" +
			"find -exec) hands out a root shell. Such a rule is refused unless\n" +
			"--i-accept-a-root-shell says the risk was understood.",
	}
	cmd.AddCommand(newGroupSudoSetCmd())
	cmd.AddCommand(newGroupSudoShowCmd())
	cmd.AddCommand(newGroupSudoRemoveCmd())

	return cmd
}

func newGroupSudoSetCmd() *cobra.Command {
	var configPath, group, runAs string
	var commands []string
	var accept bool

	cmd := &cobra.Command{
		Use:   "set",
		Short: "Write the group's sudo rule",
		Long: "Replaces the group's rule with the commands given.\n\n" +
			"  postern group sudo set --group dba \\\n" +
			"      --command '/usr/bin/pg_ctl reload' \\\n" +
			"      --command '/usr/sbin/nginx -t'\n\n" +
			"Each --command is one sudoers entry: the first word is the path, the\n" +
			"rest are the arguments it is allowed to take. --run-as defaults to\n" +
			"root and applies to the WHOLE rule: this command cannot give two\n" +
			"commands two different accounts. If the rule already does, writing\n" +
			"from here stops rather than moving them to root — the panel edits\n" +
			"each command on its own row.",
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

			/*
			 * ⚠️ BU KOMUT KOMUT-BAŞINA HESABI İFADE EDEMİYOR, O YÜZDEN
			 * ÜSTÜNE YAZMADAN ÖNCE SORUYOR.
			 *
			 * set, kuralın TAMAMINI değiştiriyor ve buradan yazılan her
			 * komut kural başına tek bir hesabı (--run-as, varsayılanı
			 * root) alıyor. Panelde "pg_ctl reload postgres olarak"
			 * yazılmış bir kuralın üstüne buradan yazmak, o komutu
			 * SESSİZCE root'a çıkarıyordu — 1.3.0'ın güvenlik satırında
			 * anlatılan hatanın aynısı, ikinci bir kapıdan.
			 *
			 * Reddetmiyoruz, NİYET İSTİYORUZ: --run-as açıkça verilmişse
			 * operatör "hepsi bu hesapla koşsun" demiş oluyor. Verilmediyse
			 * hangi komutun nereye taşınacağını söyleyip duruyoruz. Acil
			 * çıkış yolu kapanmıyor, sessizliği kapanıyor.
			 */
			if !cmd.Flags().Changed("run-as") {
				if prev, perr := db.GroupSudoRule(ctx, group); perr == nil {
					var moved []string
					for _, c := range prev.Rule.Commands {
						if acc := c.RunAsOr(prev.Rule.RunAs); acc != "root" {
							moved = append(moved, fmt.Sprintf("%s (runs as %s)", c.String(), acc))
						}
					}
					if len(moved) > 0 {
						return fmt.Errorf(
							"the rule on group %q gives these to an account other than root:\n  %s\n"+
								"This command writes one account for the whole rule, so writing from "+
								"here would move them to root. Pass --run-as to say which account you "+
								"mean, or edit the rule in the panel where each command keeps its own.",
							group, strings.Join(moved, "\n  "))
					}
				}
			}

			if err := db.SetGroupSudo(ctx, group, rule, cliActor()); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					return fmt.Errorf("group %q not found — create it with `postern group add`", group)
				}
				return err
			}
			if aerr := auditCLI(ctx, db, "group.sudo_set", group, describeCLIRule(rule)); aerr != nil {
				return aerr
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "sudo rule written on group %q\n", group)
			/*
			 * ⚠️ ROLÜN ANLAMI DEĞİŞTİ VE BU SÖYLENİYOR. O ana kadar grup
			 * "şu makinelere erişebilir" demekti; artık "şu komutları root
			 * olarak çalıştırabilir" de diyor. Rolü birine vermek bundan
			 * sonra daha fazlasını veriyor.
			 */
			fmt.Fprintf(out,
				"\nEveryone in %q now gets these commands with sudo on the machines it\n"+
					"reaches. The rule lands on a machine the next time postern works on\n"+
					"it; the ones it has not touched yet still carry what they had.\n", group)

			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "path to the config file")
	cmd.Flags().StringVar(&group, "group", "", "group that carries the rule (required)")
	cmd.Flags().StringArrayVar(&commands, "command", nil,
		"a command the group may run, with its arguments (repeatable)")
	cmd.Flags().StringVar(&runAs, "run-as", "", "user the commands run as (default root)")
	cmd.Flags().BoolVar(&accept, "i-accept-a-root-shell", false,
		"write the rule even though a command in it can start another program")
	_ = cmd.MarkFlagRequired("group")

	return cmd
}

func newGroupSudoShowCmd() *cobra.Command {
	var configPath, group string

	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show the group's sudo rule",
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

			rs, err := db.GroupSudoRule(ctx, group)
			if errors.Is(err, store.ErrNotFound) {
				fmt.Fprintf(cmd.OutOrStdout(),
					"group %q carries no sudo rule; its members get whatever the machine\n"+
						"already gives them and whatever a temporary grant adds.\n", group)
				return nil
			}
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "group %s — written by %s on %s\n",
				rs.Group, rs.UpdatedBy, rs.UpdatedAt.Format("2006-01-02 15:04 MST"))
			fmt.Fprintf(out, "file on each target: /etc/sudoers.d/postern-%s\n", rs.Group)
			/*
			 * ⚠️ HESAP KOMUT BAŞINA YAZILIYOR, KURAL BAŞINA DEĞİL.
			 *
			 * Önceki hâl tek bir "runs as:" satırı basıp komutları altına
			 * diziyordu. Kural artık komut başına hesap taşıyor (bkz.
			 * sudoers.Command.RunAs), yani o satır "pg_ctl reload postgres
			 * olarak çalışıyor" gerçeğini GİZLİYORDU: okuyan kişi hepsinin
			 * baştaki hesapla koştuğunu sanıyordu. Yetkinin yarısı hangi
			 * hesapla çalıştığıdır; komutun yanında durmak zorunda.
			 */
			for _, c := range rs.Rule.Commands {
				fmt.Fprintf(out, "  %s  (runs as %s)\n", c.String(), c.RunAsOr(rs.Rule.RunAs))
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
	cmd.Flags().StringVar(&group, "group", "", "group to show (required)")
	_ = cmd.MarkFlagRequired("group")

	return cmd
}

func newGroupSudoRemoveCmd() *cobra.Command {
	var configPath, group string

	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove the group's sudo rule",
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

			if err := db.DeleteGroupSudo(ctx, group); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					return fmt.Errorf("group %q carries no sudo rule", group)
				}
				return err
			}
			if aerr := auditCLI(ctx, db, "group.sudo_delete", group, "rule removed"); aerr != nil {
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
				"sudo rule removed from group %q in postern.\n\n"+
					"Machines that already have /etc/sudoers.d/postern-%s keep it until\n"+
					"postern next works on them. Take it off a machine now with\n"+
					"`sudo rm /etc/sudoers.d/postern-%s` there.\n", group, group, group)

			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "path to the config file")
	cmd.Flags().StringVar(&group, "group", "", "group to clear (required)")
	_ = cmd.MarkFlagRequired("group")

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
