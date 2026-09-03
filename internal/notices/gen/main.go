// Command gen, THIRD-PARTY-NOTICES.md dosyasını üretir.
//
// `make notices` bunu çağırıyor ve goreleaser sürümden ÖNCE koşuyor:
// dosya elle tutulsaydı, bir bağımlılık eklendiği gün sessizce eksik
// kalırdı.
package main

import (
	"fmt"
	"os"

	"github.com/Warewave-Technology/postern/internal/notices"
)

func main() {
	mods, err := notices.Collect(".", "./cmd/postern")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile("THIRD-PARTY-NOTICES.md",
		[]byte(notices.Render(mods)), 0o644); err != nil { // #nosec G306 -- yayınlanan belge
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("THIRD-PARTY-NOTICES.md: %d module\n", len(mods))
}
