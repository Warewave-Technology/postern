package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/config"
	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/sshalg"
	"github.com/Warewave-Technology/postern/internal/store"
)

// newTargetCmd, hedef yönetimi. Yetki modeli için user.go'daki nota bak.
func newTargetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "target",
		Short: "Manage targets",
	}
	cmd.AddCommand(newTargetAddCmd())
	cmd.AddCommand(newTargetListCmd())
	cmd.AddCommand(newTargetLabelCmd())
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
			// #nosec G304 -- yol CLI bayrağından gelir; komutu çalıştıran zaten host'ta
			data, err := os.ReadFile(hostKeyFile)
			if err != nil {
				return fmt.Errorf("host key file: %w", err)
			}
			/*
			 * ⚠️ DOSYADAKİ TÜM ANAHTARLAR OKUNUYOR VE EN İYİSİ SEÇİLİYOR
			 * — İLKİNİN ALINDIĞI HÂLİ ÖLÇÜLDÜ.
			 *
			 * Belgelerin verdiği çift `ssh-keyscan host > web-01.pub` ile
			 * bu komut. ssh-keyscan üç anahtar türünü PARALEL soruyor,
			 * yani çıktı sırası VARIŞ sırası. Yalnızca ilkini alıp
			 * gerisini atmak, aynı makineyi aynı iki komutla kaydetmenin
			 * her seferinde başka bir anahtar pinlemesi demekti: ölçümde
			 * sekiz koşuda ilk sıra rsa/ecdsa/rsa/rsa/ed25519/ecdsa/
			 * ecdsa/rsa çıktı.
			 *
			 * Bedeli iki katmanlı. Operatör hangi anahtarın pinlendiğini
			 * bilmiyor ve makinedeki `ssh-keygen -lf` çıktısıyla
			 * eşleştiremiyor; ve pinlenen tür sonradan postern'in
			 * müzakere edeceği tür olduğu için (upstream.hostKeyCallback
			 * algoları pinlenmiş anahtardan türetiyor) rastgele RSA'ya
			 * düşmek, her oturumu hedefin RSA anahtarını korumasına
			 * bağlıyordu.
			 *
			 * ScanHostKey bu soruyu zaten doğru cevaplıyor: sunucunun
			 * keyfi tercihi değil, sshalg.HostKeyAlgorithms sırasına göre
			 * "elimizdekilerin en iyisi". CLI yolu artık onunla aynı.
			 */
			pub, err := bestHostKey(data)
			if err != nil {
				return fmt.Errorf("host key file %s: %w", hostKeyFile, err)
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

			db, err := store.Open(ctx, cfg.Database.DSN)
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
				// Ad karşılaştırması bilerek yok: hedef adı harf duyarsız
				// olduğu için "Web01" ile "web01" aynı hedef, ve saklanan
				// yazım zaten existing.Name'de.
				if existing.Host != want.Host || existing.Port != want.Port || existing.HostKey != want.HostKey {
					return fmt.Errorf("target %q exists with a different definition (host %s:%d); refusing to change it implicitly",
						name, existing.Host, existing.Port)
				}
				fmt.Fprintf(out, "target %q already exists, updating grants\n", name)
			case err != nil:
				return err
			default:
				if aerr := auditCLI(ctx, db, "target.create", name,
					fmt.Sprintf("%s:%d", host, port)); aerr != nil {
					return aerr
				}
				fmt.Fprintf(out, "target %q registered\n", name)
				/*
				 * ⚠️ HANGİ ANAHTARIN PİNLENDİĞİ SÖYLENİYOR. Dosyada
				 * birden çok anahtar olabiliyor (ssh-keyscan üçünü de
				 * yazıyor) ve seçilen tür sonraki her oturumun müzakere
				 * edeceği tür. Söylenmediğinde operatör bunu makinedeki
				 * `ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub` çıktısıyla
				 * eşleştiremiyordu.
				 */
				fmt.Fprintf(out, "  host key %s %s\n",
					pub.Type(), ssh.FingerprintSHA256(pub))
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
				if aerr := auditCLI(ctx, db, "role.grant", role,
					"granted target "+name); aerr != nil {
					return aerr
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

			db, err := store.Open(ctx, cfg.Database.DSN)
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
			fmt.Fprintln(w, "NAME\tHOST\tPORT\tLABELS\tHOST KEY")

			for _, t := range targets {
				// 550 karakterlik base64 satırı yerine parmak izi: insan
				// için karşılaştırılabilir, `ssh-keygen -lf` ile aynı format.
				fingerprint := "(invalid key)"
				if pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(t.HostKey)); err == nil {
					fingerprint = ssh.FingerprintSHA256(pub)
				}
				fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n",
					t.Name, t.Host, t.Port, formatLabels(t.Labels), fingerprint)
			}

			return w.Flush()
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	return cmd
}

// formatLabels, etiketleri sıralı ve okunur tek satıra çevirir.
//
// SIRALI: Go'da map yineleme sırası rastgele ve sıralamazsak aynı
// hedefin çıktısı her koşuda farklı görünür — iki çıktıyı diff'leyen
// operatör için gürültü.
func formatLabels(l map[string]string) string {
	if len(l) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+l[k])
	}
	return strings.Join(parts, ",")
}

// newTargetLabelCmd, hedef etiketleri.
func newTargetLabelCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "label",
		Short: "Manage target labels",
	}
	cmd.AddCommand(newTargetLabelSetCmd(), newTargetLabelRemoveCmd())
	return cmd
}

func newTargetLabelSetCmd() *cobra.Command {
	var configPath, target, key, value string

	cmd := &cobra.Command{
		Use:   "set",
		Short: "Add or change a label on a target",
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

			if err := db.SetTargetLabel(ctx, target, key, value, cliActor(), "cli"); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "target %q: %s=%s\n", target, key, value)
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	cmd.Flags().StringVar(&target, "target", "", "hedef adı (zorunlu)")
	cmd.Flags().StringVar(&key, "key", "", "etiket anahtarı (zorunlu)")
	cmd.Flags().StringVar(&value, "value", "", "etiket değeri")
	_ = cmd.MarkFlagRequired("target")
	_ = cmd.MarkFlagRequired("key")
	return cmd
}

func newTargetLabelRemoveCmd() *cobra.Command {
	var configPath, target, key string

	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove a label from a target",
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

			if err := db.DeleteTargetLabel(ctx, target, key, cliActor(), "cli"); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "target %q: label %q removed\n", target, key)
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "postern.yaml", "config dosyası yolu")
	cmd.Flags().StringVar(&target, "target", "", "hedef adı (zorunlu)")
	cmd.Flags().StringVar(&key, "key", "", "etiket anahtarı (zorunlu)")
	_ = cmd.MarkFlagRequired("target")
	_ = cmd.MarkFlagRequired("key")
	return cmd
}

/*
 * bestHostKey, ssh-keyscan/authorized_keys biçimindeki bir dosyadaki
 * anahtarlar arasından postern'in TERCİH SIRASINA göre en iyisini seçer.
 *
 * ⚠️ NEDEN "İLKİ" DEĞİL: ssh-keyscan türleri paralel soruyor ve çıktı
 * sırası varış sırası — yani "ilki" makinenin tercihi bile değil, ağın
 * o anki cilvesi. Seçim upstream.ScanHostKey ile aynı listeden
 * (sshalg.HostKeyAlgorithms) yapılıyor ki iki kayıt yolu aynı makine
 * için aynı anahtarı pinlesin.
 *
 * Hiçbiri müzakere edilemiyorsa hata BULUNANLARI sayıyor: dosyada üç
 * anahtar varken "ssh-dss kabul edilmiyor" demek, hangisinin konu
 * olduğunu söylemiyor.
 */
func bestHostKey(data []byte) (ssh.PublicKey, error) {
	// Tel formatı → tercih sırası. RSA'nın iki imza varyantı da tek tel
	// formatına (ssh-rsa) karşılık geliyor; ilk göreni kazanıyor.
	rank := map[string]int{}
	for i, a := range sshalg.HostKeyAlgorithms {
		t := a
		if a == ssh.KeyAlgoRSASHA512 || a == ssh.KeyAlgoRSASHA256 {
			t = ssh.KeyAlgoRSA
		}
		if _, seen := rank[t]; !seen {
			rank[t] = i
		}
	}

	var best ssh.PublicKey
	bestRank := len(sshalg.HostKeyAlgorithms) + 1
	var found []string

	rest := data
	for {
		pub, _, _, remaining, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			break
		}
		rest = remaining
		found = append(found, pub.Type())
		if r, ok := rank[pub.Type()]; ok && r < bestRank {
			best, bestRank = pub, r
		}
	}

	if len(found) == 0 {
		return nil, errors.New("no public key found in it")
	}
	if best == nil {
		return nil, fmt.Errorf(
			"none of its keys can be negotiated (found: %s); postern accepts %s",
			strings.Join(found, ", "), strings.Join(sshalg.HostKeyAlgorithms, ", "))
	}
	return best, nil
}
