package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

/*
 * ⚠️ KULLANICIYA GÖRÜNEN CLI METİNLERİ İNGİLİZCE OLMALI.
 *
 * Bu depoda kod YORUMLARI Türkçe ve bu bilinçli bir ev kuralı; ama
 * operatöre bakan her şey — belgeler, commit mesajları, hata metinleri —
 * İngilizce. Yardım metinleri o tarafta ve bir süre değildi: 56 yardım
 * sayfasının 39'u ve 114 bayrak açıklamasının 91'i Türkçeydi.
 *
 * Bedeli, belgelerin kendi akışında: kurulum sayfası kırk kadar
 * `postern ...` çağrısını İngilizce anlatıyor ve bayrakların açıklandığı
 * TEK yer o. Yabancı bir CLI'da insanın ilk yaptığı şey `--help`
 * eklemek; geri gelen metin okunamıyordu. `discover vsphere`de bu,
 * --insecure'ün vCenter TLS doğrulamasını kapattığını ve --apply'ın kuru
 * koşumu gerçek yazmaya çevirdiğini söyleyen satırların okunamaması
 * demekti.
 *
 * Test Türkçe'ye ÖZGÜ harfleri arıyor: İngilizce metinde bulunamazlar,
 * yani yanlış alarm vermiyor.
 */
func TestUserFacingHelpIsEnglish(t *testing.T) {
	const turkishOnly = "ğışİĞŞ"

	var bad []string
	var walk func(c *cobra.Command, path string)
	walk = func(c *cobra.Command, path string) {
		name := strings.TrimSpace(path + " " + c.Name())

		check := func(what, v string) {
			if strings.ContainsAny(v, turkishOnly) {
				bad = append(bad, name+" "+what+": "+firstLine(v))
			}
		}
		check("Short", c.Short)
		check("Long", c.Long)
		check("Example", c.Example)

		c.Flags().VisitAll(func(f *pflag.Flag) {
			check("--"+f.Name, f.Usage)
		})

		for _, sub := range c.Commands() {
			walk(sub, name)
		}
	}
	walk(newRootCmd(), "")

	if len(bad) > 0 {
		t.Errorf("kullanıcıya görünen %d CLI metni Türkçe:\n  %s\n\n"+
			"Yorumlar Türkçe kalıyor — bu ev kuralı. Ama yardım metni "+
			"operatöre bakıyor ve bayrakların açıklandığı tek yer, "+
			"belgeler o çağrıları İngilizce anlatırken.",
			len(bad), strings.Join(bad, "\n  "))
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
