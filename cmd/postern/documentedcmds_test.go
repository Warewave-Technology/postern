package main

import (
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

/*
 * ⚠️ BELGELERDE ADI GEÇEN HER KOMUT GERÇEKTEN VAR OLMALI.
 *
 * Ölçülen arıza: CHANGELOG'un *Needs action* bölümü, kalıcı kayıp
 * işaretlenmiş kayıtlar için çareyi `postern archive status` diye
 * gösteriyordu. Öyle bir komut yok — `postern archive`in tek alt
 * komutu `check` ve o kovayı yokluyor, kayıp saymıyor. Yani zaten
 * kayıt kaybetmiş bir operatör, çare diye var olmayan bir komuta
 * gönderiliyordu.
 *
 * Bu sınıf duyuru günü en pahalı olanı: okuyucunun ilk yaptığı şey
 * belgedeki komutu kopyalayıp yapıştırmak.
 *
 * ⚠️ TEST ÜRÜNÜN KENDİ KOMUT AĞACINI SORUYOR, bir listeyi değil —
 * elle tutulan bir liste ikinci bir yalan kaynağı olurdu.
 */
func TestEveryDocumentedCommandExists(t *testing.T) {
	root := repoRootOf(t)

	docs := []string{
		"README.md", "CHANGELOG.md", "SECURITY.md", "RELEASING.md",
		filepath.Join("deploy", "README.md"),
		filepath.Join("site", "index.html"),
		filepath.Join("site", "docs", "index.html"),
	}

	// `postern <alt> <alt> ...` — bayraklar ve devamı atılıyor.
	re := regexp.MustCompile(`postern ((?:[a-z][a-z0-9-]*)(?: [a-z][a-z0-9-]*)*)`)

	known, needsSub := commandPaths(newRootCmd())
	var bad []string
	seen := map[string]bool{}

	for _, d := range docs {
		b, err := os.ReadFile(filepath.Join(root, d))
		if err != nil {
			continue
		}
		text := string(b)
		if strings.HasSuffix(d, ".html") {
			text = html.UnescapeString(regexp.MustCompile(`<[^>]+>`).ReplaceAllString(text, " "))
		}
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			words := strings.Fields(m[1])

			/*
			 * En uzun eşleşen öneki bul. Kalanı genelde argüman —
			 * AMA eşleşen komut alt komut İSTİYORSA (kendi RunE'si
			 * yok) sonraki sözcük bir argüman olamaz: ya bilinen bir
			 * alt komuttur ya da yanlıştır. Bu ayrım olmadan test
			 * `postern archive status`ü "archive + argüman" sayıp
			 * geçiriyordu — ölçülen arızanın kendisi.
			 */
			hit, n := false, 0
			for k := len(words); k >= 1; k-- {
				if known[strings.Join(words[:k], " ")] {
					hit, n = true, k
					break
				}
			}
			if hit && !(needsSub[strings.Join(words[:n], " ")] && n < len(words)) {
				continue
			}
			// İlk sözcük hiç komut değilse bu bir düzyazı eşleşmesi
			// ("postern is an SSH bastion"): sessizce geç.
			if !anyCommandNamed(known, words[0]) {
				continue
			}
			key := d + ": postern " + strings.Join(words, " ")
			if !seen[key] {
				seen[key] = true
				bad = append(bad, key)
			}
		}
	}

	if len(bad) > 0 {
		t.Errorf("belgeler var olmayan komutlar gösteriyor:\n  %s\n\n"+
			"Belgedeki bir komutu kopyalayıp yapıştırmak okuyucunun ilk "+
			"yaptığı şey; çalışmayan bir komut, en çok ihtiyaç duyulduğu "+
			"anda çıkmaz sokak.", strings.Join(bad, "\n  "))
	}
}

/*
 * commandPaths, komut ağacındaki tüm yolları ("user add" gibi) ve
 * hangilerinin ALT KOMUT İSTEDİĞİNİ döner.
 *
 * İkincisi olmadan `postern archive status` "archive + argüman" diye
 * geçiyordu; oysa archive'in kendi RunE'si yok, yani ardından gelen
 * sözcük bir alt komut olmak ZORUNDA.
 */
func commandPaths(root *cobra.Command) (paths, needsSub map[string]bool) {
	paths, needsSub = map[string]bool{}, map[string]bool{}
	var walk func(c *cobra.Command, p []string)
	walk = func(c *cobra.Command, p []string) {
		if len(p) > 0 {
			key := strings.Join(p, " ")
			paths[key] = true
			if c.RunE == nil && c.Run == nil && c.HasSubCommands() {
				needsSub[key] = true
			}
		}
		for _, sub := range c.Commands() {
			if sub.Name() == "help" || sub.Name() == "completion" {
				continue
			}
			walk(sub, append(append([]string{}, p...), sub.Name()))
		}
	}
	walk(root, nil)
	return paths, needsSub
}

func anyCommandNamed(known map[string]bool, first string) bool {
	for k := range known {
		if k == first || strings.HasPrefix(k, first+" ") {
			return true
		}
	}
	return false
}

func repoRootOf(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, serr := os.Stat(filepath.Join(dir, "go.mod")); serr == nil {
			return dir
		}
		p := filepath.Dir(dir)
		if p == dir {
			t.Fatal("go.mod bulunamadı")
		}
		dir = p
	}
}
