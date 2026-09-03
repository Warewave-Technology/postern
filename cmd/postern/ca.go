package main

import (
	"fmt"

	"github.com/Warewave-Technology/postern/internal/ca"
	"github.com/spf13/cobra"
)

// defaultCAKeyPath, --key verilmediğinde kullanılacak yol.
//
// S2.3'te bu değer config'e taşınacak (ca.key_file gibi bir alan), çünkü
// `postern serve` de aynı anahtara ihtiyaç duyacak: her oturumda efemeral
// bir anahtar çifti üretip bu CA ile imzalayacak. Şimdilik bayrak yeterli.
const defaultCAKeyPath = "ca_ed25519"

func newCACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Manage the certificate authority",
	}

	var keyPath string
	cmd.PersistentFlags().StringVar(&keyPath, "key", defaultCAKeyPath, "CA private key file")

	cmd.AddCommand(newCAInitCmd(&keyPath))
	cmd.AddCommand(newCAShowCmd(&keyPath))
	return cmd
}

func newCAInitCmd(keyPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Generate a new CA key",
		Long: "Generates a new CA key pair. It will NOT overwrite an existing\n" +
			"key: losing that key invalidates the TrustedUserCAKeys line on\n" +
			"every target you have already configured.",
		RunE: func(cmd *cobra.Command, args []string) error {
			authority, err := ca.Init(*keyPath)
			if err != nil {
				return fmt.Errorf("ca init: %w", err)
			}

			// Talimat metni stderr'e: stdout "veri", stderr "insana hitap"
			// kanalı. Böylece `postern ca init > /dev/null` diyen biri de
			// sıradaki adımı görür ve iki alt komut tutarlı davranır.
			//
			// Basılan, CA'nın PUBLIC anahtarıdır. Özel anahtar diskte kaldı
			// (0600) ve hiçbir zaman ekrana ya da log'a çıkmaz.
			out := cmd.ErrOrStderr()
			fmt.Fprintf(out, "CA key created: %s\n\n", *keyPath)
			fmt.Fprintf(out, "Public key — this is what targets trust:\n%s\n", authority.AuthorizedKey())
			fmt.Fprintf(out, "On every target:\n")
			fmt.Fprintf(out, "  1. write the line above to /etc/ssh/postern_ca.pub\n")
			fmt.Fprintf(out, "  2. add to /etc/ssh/sshd_config:  TrustedUserCAKeys /etc/ssh/postern_ca.pub\n")
			fmt.Fprintf(out, "  3. reload sshd\n")

			return nil
		},
	}
}

func newCAShowCmd(keyPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print the CA public key (for TrustedUserCAKeys)",
		RunE: func(cmd *cobra.Command, args []string) error {
			authority, err := ca.Load(*keyPath)
			if err != nil {
				return fmt.Errorf("ca show: %w", err)
			}

			// Yalnızca anahtar satırı, yalnızca stdout: çıktı doğrudan
			// dosyaya yönlendirilecek (postern ca show > postern_ca.pub).
			// Boru hattı erkenden kapanırsa hatayı yut ma.
			if _, err := fmt.Fprint(cmd.OutOrStdout(), authority.AuthorizedKey()); err != nil {
				return fmt.Errorf("ca show: %w", err)
			}
			return nil
		},
	}
}
