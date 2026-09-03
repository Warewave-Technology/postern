package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/Warewave-Technology/postern/internal/discover"
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

			return printDiscovery(cmd, res, apply, tagKey)
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "path to the config file")
	cmd.Flags().StringVar(&url, "url", "", "vCenter address, https:// (required)")
	cmd.Flags().StringVar(&username, "username", "", "vCenter user (required; must be READ-ONLY)")
	cmd.Flags().StringVar(&password, "password", "",
		"vCenter password; prefer the POSTERN_VSPHERE_PASSWORD environment variable")
	cmd.Flags().StringVar(&caFile, "ca-file", "", "root certificate that verifies vCenter")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "skip TLS verification (not recommended)")
	cmd.Flags().StringVar(&tagKey, "tag-key", "", "tag CATEGORY that carries the role, e.g. role (required)")
	cmd.Flags().IntVar(&port, "port", 22, "SSH port on the discovered targets")
	cmd.Flags().BoolVar(&apply, "apply", false, "actually write the changes (default: preview only)")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "timeout for API requests")
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
			"TAGS: Proxmox tags are plain strings and its character set is narrow —\n" +
			"[a-z0-9_.+-], so a tag cannot contain = or :. Write the role as\n" +
			"  <key>_<role>      e.g. role-name_os-admins  with --tag-key role-name\n" +
			"Everything after the first \"<key>_\" is the role, so underscores inside\n" +
			"either half are fine.\n\n" +
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

			return printDiscovery(cmd, res, apply, tagKey)
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "path to the config file")
	cmd.Flags().StringVar(&url, "url", "", "Proxmox address, https:// (required)")
	cmd.Flags().StringVar(&tokenID, "token-id", "", "API token id, user@pam!name (required)")
	cmd.Flags().StringVar(&tokenSecret, "token-secret", "",
		"API token secret; prefer the POSTERN_PROXMOX_TOKEN_SECRET environment variable")
	cmd.Flags().StringVar(&caFile, "ca-file", "", "root certificate that verifies the hypervisor")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "skip TLS verification (not recommended)")
	cmd.Flags().StringVar(&node, "node", "", "only this node")
	cmd.Flags().StringVar(&tagKey, "tag-key", "",
		"tag key that carries the role; tags look like <key>_<role>, e.g. role-name (required)")
	cmd.Flags().IntVar(&port, "port", 22, "SSH port on the discovered targets")
	cmd.Flags().BoolVar(&apply, "apply", false, "actually write the changes (default: preview only)")
	cmd.Flags().DurationVar(&timeout, "timeout", 20*time.Second, "timeout for API requests")
	return cmd
}

// printDiscovery, sonucu okunur bir tabloya çevirir.
/*
 * printDiscovery, raporu basar ve koşumun BAŞARILI SAYILIP
 * SAYILMAYACAĞINI döner.
 *
 * ⚠️ ÇIKIŞ KODU ÖNEMLİ. Bu komut betikten çalıştırılıyor ve eskiden
 * HER ZAMAN 0 dönüyordu: bütün makineler atlanmış olsa bile. Yani
 * zamanlanmış bir keşif, hiçbir şey yapmadan "başarılı" raporluyordu ve
 * kimse envanterin donduğunu fark etmiyordu.
 *
 * Atlama TEK BAŞINA hata değil — kapalı bir sanal makine olağan. Hata
 * olan şey, --apply istendiği hâlde HİÇBİR ŞEYİN yazılmaması.
 */
func printDiscovery(cmd *cobra.Command, res []discover.Outcome, apply bool, tagKey string) error {
	out := cmd.OutOrStdout()
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "MACHINE\tADDRESS\tROLE\tFROM\tRESULT")

	var created, granted, skipped, roles, tagged int
	for _, o := range res {
		addr := o.Machine.Host
		if addr == "" {
			addr = o.Machine.Name
		}
		from := "tag"
		if o.Tagged {
			tagged++
		}
		if !o.Tagged {
			// ⚠️ "Etiketsiz" ayrı yazılıyor: unknown rolündeki bir
			// makinenin oraya neden düştüğü, operatörün soracağı ilk şey.
			from = "untagged"
		}

		result := "would add"
		switch {
		case o.KeyUnchecked != "":
			// Kayıtlı hedef, rol bağı yenilendi ama anahtar bu turda
			// doğrulanamadı. "already registered" demek, kontrol
			// edilmiş gibi göstermek olurdu.
			result = "role granted; " + o.KeyUnchecked
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

	/*
	 * ⚠️ HİÇBİRİ EŞLEŞMEDİYSE BUNU BAĞIRARAK SÖYLE.
	 *
	 * ÖLÇÜLEN ARIZA: etiket ayrıştırıcısı bir süre yalnızca "anahtar=değer"
	 * ve "anahtar:değer" tanıyordu. Proxmox etiketlerinde `=` ve `:`
	 * YAZILAMIYOR (karakter kümesi [a-z0-9_.+-]), dolayısıyla gerçek bir
	 * Proxmox kurulumunda HER makine sessizce unknown'a düşüyordu — çıktı
	 * satır satır "untagged" diyordu ama hiçbir yerde "anahtarın hiçbir
	 * şeyle eşleşmedi" yazmıyordu. Operatör bunu ancak envanteri
	 * inceleyip şaşırarak fark etti.
	 *
	 * Gerçekten görülen etiketleri basmak da bunun parçası: yanlış
	 * anahtarı yazan kişi doğrusunu ekranda görüyor.
	 */
	if len(res) > 0 && tagged == 0 {
		fmt.Fprintf(out, "\nWARNING: not one machine carried a %q tag.\n", tagKey)
		if seen := sampleTags(res); len(seen) > 0 {
			fmt.Fprintf(out, "The tags actually seen were: %s\n", strings.Join(seen, ", "))
			fmt.Fprintf(out, "A tag is read as \"<key><separator><role>\", where the "+
				"separator is _ = or : — so %q would need --tag-key %q.\n",
				seen[0], tagKeyOf(seen[0]))
		} else {
			fmt.Fprintf(out, "These machines carry no tags at all.\n")
		}
	}
	if !apply {
		/*
		 * ⚠️ ÖNİZLEMENİN ÖNİZLEME OLDUĞU SÖYLENİYOR. Tabloyu görüp
		 * "oldu" sanan operatör, envanterin yazıldığını düşünerek
		 * gider — ve eksikliği fark ettiğinde nerede aramaya
		 * başlayacağını bilmez.
		 */
		fmt.Fprintf(out, "Nothing was written. Re-run with --apply to create "+
			"the roles and targets above.\n")
		return nil
	}
	fmt.Fprintf(out, "Created %d target(s) and %d role(s); granted %d.\n",
		created, roles, granted)
	fmt.Fprintf(out, "\nThese roles hold targets but no people yet: access comes from "+
		"assigning a role to a user, which discovery deliberately does not do.\n")
	fmt.Fprintf(out, "Machines with no \"%s\" tag are in the %q role.\n",
		tagKey, discover.UnknownRole)

	if len(res) > 0 && created == 0 && granted == 0 && roles == 0 {
		return fmt.Errorf("nothing was written: all %d machine(s) were skipped", len(res))
	}
	return nil
}

/*
 * sampleTags, raporda gösterilecek birkaç GERÇEK etiket.
 *
 * Anahtarı yanlış yazan operatöre doğrusunu göstermenin en kısa yolu,
 * makinelerin üzerinde ne yazdığını basmak. Sınırlı: 200 makinelik bir
 * envanterin bütün etiketlerini dökmek, uyarıyı okunmaz yapardı.
 */
func sampleTags(res []discover.Outcome) []string {
	const max = 6
	seen := map[string]bool{}
	out := make([]string, 0, max)
	for _, o := range res {
		for _, t := range o.Machine.Tags {
			if t == "" || seen[t] {
				continue
			}
			seen[t] = true
			out = append(out, t)
			if len(out) == max {
				return out
			}
		}
	}
	return out
}

// tagKeyOf, örnek bir etiketten anahtarın ne olması gerektiğini tahmin
// eder — yalnızca uyarı metninde öneri olarak kullanılıyor.
func tagKeyOf(tag string) string {
	best := tag
	for _, sep := range []string{"=", ":", "_"} {
		if k, _, ok := strings.Cut(tag, sep); ok && len(k) < len(best) {
			best = k
		}
	}
	return best
}
