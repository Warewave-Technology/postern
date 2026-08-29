// Command postern is a certificate-based, session-recording SSH bastion.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
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
	}
	root.AddCommand(newServeCmd())
	root.AddCommand(newCACmd())
	root.AddCommand(newDBCmd())
	root.AddCommand(newSessionCmd())
	root.AddCommand(newUserCmd())
	root.AddCommand(newAdminCmd())
	root.AddCommand(newTargetCmd())
	root.AddCommand(newRoleCmd())
	root.AddCommand(newMappingCmd())
	root.AddCommand(newSecretCmd())
	root.AddCommand(newSettingsCmd())
	root.AddCommand(newSyncCmd())
	return root
}
