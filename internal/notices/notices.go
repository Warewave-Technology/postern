/*
 * Package notices, ikiliye derlenen üçüncü taraf modüllerin lisans
 * metinlerini toplar.
 *
 * ⚠️ NEDEN VAR: sürüm arşivi yalnızca postern'in kendi LICENSE'ını
 * taşıyordu, oysa ikilinin içinde 20 modül var — 8 MIT, 7 BSD-3, 3
 * Apache-2.0. MIT ve BSD, telif ve izin bildiriminin "bütün kopyalarda"
 * taşınmasını şart koşuyor ve statik olarak bağlanmış bir ikili de bir
 * kopya. Apache-2.0 kendi lisansının bir nüshasını istiyor.
 *
 * ⚠️ ÜRETİLİYOR, ELLE YAZILMIYOR. Elle tutulan bir bildirim dosyası,
 * bir bağımlılık eklendiği gün sessizce eksik kalır — ve eksik olduğunu
 * kimse fark etmez. Kaynak, `go list`in verdiği gerçek bağımlılık
 * kümesi.
 */
package notices

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Module, bir bağımlılık ve lisans metni.
type Module struct {
	Path    string
	Version string
	License string // dosya adı, ör. "LICENSE"
	Text    string
}

// licenseNames, modül kökünde aranan dosya adları — yaygınlık sırasında.
var licenseNames = []string{
	"LICENSE", "LICENSE.txt", "LICENSE.md",
	"LICENCE", "LICENCE.txt",
	"COPYING", "COPYING.txt",
}

/*
 * Collect, verilen paketin (ör. ./cmd/postern) derlenmiş hâline giren
 * modülleri ve lisanslarını toplar.
 *
 * ⚠️ `go list -deps` KULLANILIYOR, go.mod'un require bloğu DEĞİL:
 * require bloğu derlemeye girmeyen modülleri de sayıyor ve sayarsa
 * bildirim, taşımadığımız kod için telif iddiası taşır.
 */
func Collect(dir, pkg string) ([]Module, error) {
	// #nosec G204 -- argümanlar sabit; pkg'yi veren tek çağıran
	// internal/notices/gen ve orada "./cmd/postern" yazılı. Bu paket
	// ÜRÜNE GİRMİYOR: yalnızca `make notices` için var, cmd/postern onu
	// import etmiyor.
	cmd := exec.Command("go", "list", "-deps", "-json", pkg)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("notices: go list: %w", err)
	}

	seen := map[string]Module{}
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var p struct {
			Standard bool
			Module   *struct {
				Path, Version, Dir string
			}
		}
		if derr := dec.Decode(&p); derr != nil {
			return nil, fmt.Errorf("notices: decode: %w", derr)
		}
		if p.Standard || p.Module == nil || p.Module.Version == "" || p.Module.Dir == "" {
			continue // standart kütüphane ve ana modül
		}
		if _, ok := seen[p.Module.Path]; ok {
			continue
		}
		m := Module{Path: p.Module.Path, Version: p.Module.Version}
		for _, name := range licenseNames {
			b, rerr := os.ReadFile(filepath.Join(p.Module.Dir, name)) // #nosec G304 -- modül önbelleği
			if rerr == nil {
				m.License, m.Text = name, string(b)
				break
			}
		}
		seen[p.Module.Path] = m
	}

	mods := make([]Module, 0, len(seen))
	for _, m := range seen {
		mods = append(mods, m)
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Path < mods[j].Path })
	return mods, nil
}

// Render, bildirim dosyasının metnini üretir.
func Render(mods []Module) string {
	var b strings.Builder
	b.WriteString("# Third-party notices\n\n")
	b.WriteString("postern is distributed as a single statically linked binary. " +
		"The following modules are compiled into it, and their licences require " +
		"that these notices travel with the binary.\n\n")
	b.WriteString("postern's own licence is in `LICENSE` (Apache-2.0). " +
		"To see the exact versions a binary you already hold was built with:\n\n")
	b.WriteString("```\ngo version -m ./postern\n```\n\n")
	b.WriteString("| Module | Version |\n|---|---|\n")
	for _, m := range mods {
		fmt.Fprintf(&b, "| `%s` | %s |\n", m.Path, m.Version)
	}
	b.WriteString("\n---\n")
	for _, m := range mods {
		fmt.Fprintf(&b, "\n## %s %s\n\n", m.Path, m.Version)
		if m.Text == "" {
			b.WriteString("_No licence file found in the module. " +
				"See the module's repository._\n")
			continue
		}
		fmt.Fprintf(&b, "```\n%s\n```\n", strings.TrimRight(m.Text, "\n"))
	}
	return b.String()
}
