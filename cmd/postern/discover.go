package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/warewave/postern/internal/discover"
)

/*
 * `postern discover` — sanallaştırma platformundan makine keşfi.
 *
 * ⚠️ ÖNİZLEME VARSAYILAN, YAZMA AÇIK İSTEK.
 *
 * Bu komut rol yaratıp hedef ekliyor; yani envanterin şeklini
 * değiştiriyor. Bir keşif taraması insanın gözünden geçmeden
 * yazmamalı: etiketi yanlış yazılmış tek bir makine, adı yanlış bir rol
 * yaratır ve o rol bir daha kimsenin bakmadığı bir yerde durur.
 * `--apply` yazmak, gördüğünü onaylamak demek.
 *
 * ⚠️ KEŞİF ERİŞİM VERMİYOR. Hedef ve rol yaratıyor, rolü İNSANA
 * bağlamıyor. Erişim yalnızca kullanıcı→rol atamasından geliyor ve o
 * ayrı, bilinçli bir adım.
 */
func newDiscoverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Find machines on a virtualisation platform and turn their tags into roles",
	}
	cmd.AddCommand(newDiscoverProxmoxCmd())
	cmd.AddCommand(newDiscoverVSphereCmd())
	return cmd
}

func newDiscoverVSphereCmd() *cobra.Command {
	var (
		configPath, url, username, password string
		caFile, tagKey                      string
		insecure, apply                     bool
		port                                int
		timeout                             time.Duration
	)

	cmd := &cobra.Command{
		Use:   "vsphere",
		Short: "Discover machines from vCenter",
		Long: "Reads the inventory, turns a tag category into a role, registers each\n" +
			"machine as a target and grants it to that role.\n\n" +
			"In vSphere a tag really is key/value: the CATEGORY is the key and the\n" +
			"TAG is the value, so --tag-key names a tag category.\n\n" +
			"Nothing is written without --apply. A machine with no tag in that\n" +
			"category lands in the \"" + discover.UnknownRole + "\" role rather than\n" +
			"being dropped.\n\n" +
			"Needs vCenter 7.0 U2 or newer.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(tagKey) == "" {
				return errors.New("--tag-key is required: it names the tag category that carries the role")
			}
			// ⚠️ Parola ortam değişkeninden de okunuyor: komut satırına
			// yazılan bir parola `ps` ile görülebilir ve kabuk geçmişine
			// düşer.
			if password == "" {
				password = os.Getenv("POSTERN_VSPHERE_PASSWORD")
			}

			src, err := discover.NewVSphere(discover.VSphereConfig{
				BaseURL: url, Username: username, Password: password,
				CAFile: caFile, Insecure: insecure, Timeout: timeout,
			})
			if err != nil {
				return err
			}

			db, ctx, err := openStore(configPath)
			if err != nil {
				return err
			}
			defer db.Close()

			out := cmd.OutOrStdout()
			if insecure {
				fmt.Fprintln(out,
					"WARNING: --insecure skips TLS verification of vCenter. Anyone able "+
						"to sit between you and it can decide which machine lands in which "+
						"role, and can read the session id. Use --ca-file instead.")
			}

			machines, err := src.Machines(ctx)
			if err != nil {
				return fmt.Errorf("vsphere: %w", err)
			}
			if len(machines) == 0 {
				fmt.Fprintln(out, "no machines found")
				return nil
			}

			res, err := discover.Planner{
				DB: db, TagKey: tagKey, Port: port, Actor: "cli",
			}.Run(ctx, machines, apply)
			if err != nil {
				return err
			}

			printDiscovery(cmd, res, apply, tagKey)
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	cmd.Flags().StringVar(&url, "url", "", "vCenter adresi, https:// (zorunlu)")
	cmd.Flags().StringVar(&username, "username", "", "vCenter kullanıcısı (zorunlu, YALNIZCA OKUMA yetkili olmalı)")
	cmd.Flags().StringVar(&password, "password", "",
		"vCenter parolası; tercihen POSTERN_VSPHERE_PASSWORD ortam değişkeni")
	cmd.Flags().StringVar(&caFile, "ca-file", "", "vCenter sertifikasını doğrulayacak kök")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "TLS doğrulamasını kapat (önerilmez)")
	cmd.Flags().StringVar(&tagKey, "tag-key", "", "rolü taşıyan etiket KATEGORİSİ, ör. role (zorunlu)")
	cmd.Flags().IntVar(&port, "port", 22, "hedeflerin SSH portu")
	cmd.Flags().BoolVar(&apply, "apply", false, "gerçekten yaz (varsayılan: yalnızca göster)")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "API isteği zaman aşımı")
	return cmd
}

func newDiscoverProxmoxCmd() *cobra.Command {
	var (
		configPath, url, tokenID, tokenSecret string
		caFile, node, tagKey                  string
		insecure, apply                       bool
		port                                  int
		timeout                               time.Duration
	)

	cmd := &cobra.Command{
		Use:   "proxmox",
		Short: "Discover machines from Proxmox VE",
		Long: "Reads the cluster inventory, turns a tag into a role, registers each\n" +
			"machine as a target and grants it to that role.\n\n" +
			"Nothing is written without --apply. A machine whose tag does not name a\n" +
			"role lands in the \"" + discover.UnknownRole + "\" role rather than being dropped.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(tagKey) == "" {
				return errors.New("--tag-key is required: it names the tag that carries the role")
			}
			/*
			 * ⚠️ SIR ORTAM DEĞİŞKENİNDEN DE OKUNUYOR.
			 *
			 * Komut satırına yazılan bir jeton, makinedeki her
			 * kullanıcının `ps` ile görebildiği ve kabuk geçmişine
			 * düşen bir jetondur. Bayrağı kaldırmıyoruz (betikler için
			 * lazım) ama ortam değişkeni yolunu ÖNCE belgeliyoruz.
			 */
			if tokenSecret == "" {
				tokenSecret = os.Getenv("POSTERN_PROXMOX_TOKEN_SECRET")
			}

			src, err := discover.NewProxmox(discover.ProxmoxConfig{
				BaseURL:     url,
				TokenID:     tokenID,
				TokenSecret: tokenSecret,
				CAFile:      caFile,
				Insecure:    insecure,
				Node:        node,
				Timeout:     timeout,
			})
			if err != nil {
				return err
			}

			db, ctx, err := openStore(configPath)
			if err != nil {
				return err
			}
			defer db.Close()

			out := cmd.OutOrStdout()
			if insecure {
				// ⚠️ Uyarı ÇIKTIYA: araya giren biri hangi makinenin
				// hangi role gideceğini yazabilir.
				fmt.Fprintln(out,
					"WARNING: --insecure skips TLS verification of the hypervisor. "+
						"Anyone able to sit between you and it can decide which machine "+
						"lands in which role. Use --ca-file instead.")
			}

			machines, err := src.Machines(ctx)
			if err != nil {
				return fmt.Errorf("proxmox: %w", err)
			}
			if len(machines) == 0 {
				fmt.Fprintln(out, "no machines found")
				return nil
			}

			res, err := discover.Planner{
				DB: db, TagKey: tagKey, Port: port, Actor: "cli",
			}.Run(ctx, machines, apply)
			if err != nil {
				return err
			}

			printDiscovery(cmd, res, apply, tagKey)
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	cmd.Flags().StringVar(&url, "url", "", "Proxmox adresi, https:// (zorunlu)")
	cmd.Flags().StringVar(&tokenID, "token-id", "", "API jeton kimliği, user@pam!name (zorunlu)")
	cmd.Flags().StringVar(&tokenSecret, "token-secret", "",
		"API jeton sırrı; tercihen POSTERN_PROXMOX_TOKEN_SECRET ortam değişkeni")
	cmd.Flags().StringVar(&caFile, "ca-file", "", "hipervizörün sertifikasını doğrulayacak kök")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "TLS doğrulamasını kapat (önerilmez)")
	cmd.Flags().StringVar(&node, "node", "", "yalnızca bu düğüm")
	cmd.Flags().StringVar(&tagKey, "tag-key", "", "rolü taşıyan etiket anahtarı, ör. role (zorunlu)")
	cmd.Flags().IntVar(&port, "port", 22, "hedeflerin SSH portu")
	cmd.Flags().BoolVar(&apply, "apply", false, "gerçekten yaz (varsayılan: yalnızca göster)")
	cmd.Flags().DurationVar(&timeout, "timeout", 20*time.Second, "API isteği zaman aşımı")
	return cmd
}

// printDiscovery, sonucu okunur bir tabloya çevirir.
func printDiscovery(cmd *cobra.Command, res []discover.Outcome, apply bool, tagKey string) {
	out := cmd.OutOrStdout()
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "MACHINE\tADDRESS\tROLE\tFROM\tRESULT")

	var created, granted, skipped, roles int
	for _, o := range res {
		addr := o.Machine.Host
		if addr == "" {
			addr = o.Machine.Name
		}
		from := "tag"
		if !o.Tagged {
			// ⚠️ "Etiketsiz" ayrı yazılıyor: unknown rolündeki bir
			// makinenin oraya neden düştüğü, operatörün soracağı ilk şey.
			from = "untagged"
		}

		result := "would add"
		switch {
		case o.Skipped != "":
			result = "SKIPPED: " + o.Skipped
			skipped++
		case apply && o.CreatedTarget:
			result = "added"
			created++
		case apply && o.Existing:
			result = "already registered; role granted"
		case o.Existing:
			result = "already registered"
		}
		if o.CreatedRole {
			roles++
		}
		if o.Granted {
			granted++
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", o.Machine.Name, addr, o.Role, from, result)
	}
	_ = w.Flush()

	fmt.Fprintf(out, "\n%d machine(s); %d skipped.\n", len(res), skipped)
	if !apply {
		/*
		 * ⚠️ ÖNİZLEMENİN ÖNİZLEME OLDUĞU SÖYLENİYOR. Tabloyu görüp
		 * "oldu" sanan operatör, envanterin yazıldığını düşünerek
		 * gider — ve eksikliği fark ettiğinde nerede aramaya
		 * başlayacağını bilmez.
		 */
		fmt.Fprintf(out, "Nothing was written. Re-run with --apply to create "+
			"the roles and targets above.\n")
		return
	}
	fmt.Fprintf(out, "Created %d target(s) and %d role(s); granted %d.\n",
		created, roles, granted)
	fmt.Fprintf(out, "\nThese roles hold targets but no people yet: access comes from "+
		"assigning a role to a user, which discovery deliberately does not do.\n")
	fmt.Fprintf(out, "Machines with no \"%s\" tag are in the %q role.\n",
		tagKey, discover.UnknownRole)
}
