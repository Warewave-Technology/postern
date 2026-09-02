package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/warewave/postern/internal/version"
)

/*
 * newVersionCmd, çalışan ikilinin ne olduğunu söyler.
 *
 * ⚠️ AYRI BİR KOMUT VE root.Version'ın İKİSİ BİRDEN VAR ve gerekçesi
 * farklı iki soru: `--version` "hangi sürüm" diye soran betiğin
 * beklediği tek satır; `postern version` ise "yamalı mıyım" diye soran
 * insanın ihtiyaç duyduğu commit, kirlilik ve derleme bilgisi.
 * Birincisini ikincisiyle doldurmak, sürümü ayrıştıran betikleri
 * kırardı.
 */
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show which build of postern this is",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprint(cmd.OutOrStdout(), version.Get().String())
			return nil
		},
	}
}
