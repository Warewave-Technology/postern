// Command postern is a certificate-based, session-recording SSH bastion.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Warewave-Technology/postern/internal/version"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "postern:", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "postern",
		Short:         "Certificate-based, session-recording SSH bastion",
		SilenceUsage:  true,
		SilenceErrors: true,

		// ⚠️ `--version` TEK SATIR. Betikler bunu ayrıştırıyor;
		// ayrıntı (commit, kirlilik, Go sürümü) `postern version`da.
		Version: version.Get().Short(),
	}
	// Cobra'nın varsayılan şablonu "postern version X" basıyor;
	// yalnızca değeri istiyoruz.
	root.SetVersionTemplate("{{.Version}}\n")
	root.AddCommand(newServeCmd())
	root.AddCommand(newCACmd())
	root.AddCommand(newDBCmd())
	root.AddCommand(newSessionCmd())
	root.AddCommand(newUserCmd())
	root.AddCommand(newAdminCmd())
	root.AddCommand(newTargetCmd())
	root.AddCommand(newDiscoverCmd())
	root.AddCommand(newRoleCmd())
	root.AddCommand(newMappingCmd())
	root.AddCommand(newSecretCmd())
	root.AddCommand(newSettingsCmd())
	root.AddCommand(newSyncCmd())
	root.AddCommand(newArchiveCmd())
	root.AddCommand(newLogCmd())
	root.AddCommand(newVersionCmd())
	return root
}
