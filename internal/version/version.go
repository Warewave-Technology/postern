// Package version, çalışan ikilinin ne olduğunu söyler.
package version

import (
	"fmt"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
)

/*
 * ⚠️ NEDEN VAR: "hangi sürümü çalıştırıyorum" sorusunun cevabı yoktu.
 *
 * Bir güvenlik açığı yayınlandığında operatörün ilk sorusu bu ve
 * postern'de sorulacak yer yoktu: ne `--version`, ne açılış log'unda
 * bir satır, ne de panelde. Bugün x/crypto'da iki DoS yayınlandı ve
 * "yamalı mıyım" sorusuna cevap vermenin tek yolu ikilinin hash'ini
 * elle karşılaştırmaktı.
 *
 * ⚠️ İKİ KAYNAK, BİRİ YALAN SÖYLEYEMEZ.
 *
 * `version` derleme sırasında -ldflags ile basılıyor (Makefile'daki
 * `git describe`). Basılmamışsa "dev" kalıyor ve ÖYLE söyleniyor:
 * kendini sürüm sanan bir geliştirme derlemesi, "yamalı mıyım"
 * sorusuna verilebilecek en kötü cevap.
 *
 * VCS bilgisi (commit, tarih, çalışma ağacı kirli mi) Go'nun kendi
 * gömdüğü debug.BuildInfo'dan geliyor — elle basılamıyor, dolayısıyla
 * etiketle çelişemiyor. Kirli bir ağaçtan derlenmiş bir "v1.0.0",
 * v1.0.0 DEĞİLDİR ve çıktı bunu söylüyor.
 */

// version, derlemede basılan sürüm etiketi. Boşsa "dev".
//
// Makefile: -ldflags "-X github.com/Warewave-Technology/postern/internal/version.version=$(VERSION)"
var version = ""

// Info, çalışan ikili hakkında bilinen her şey.
type Info struct {
	// Version, etiket ("v1.0.0") ya da "dev".
	Version string

	// Tagged, sürümün derlemede basılıp basılmadığı.
	//
	// ⚠️ Version != "dev" ile aynı şey DEĞİL: birisi ileride
	// varsayılanı değiştirebilir. Niyet ayrı bir alanda duruyor.
	Tagged bool

	// Commit / CommitTime, Go'nun gömdüğü VCS bilgisi. Boş olabilir:
	// `-buildvcs=false` ya da git ağacı dışında derleme.
	Commit     string
	CommitTime string

	// Dirty, derleme anında çalışma ağacında commit'lenmemiş
	// değişiklik olup olmadığı.
	//
	// ⚠️ AYRI BİR ALAN, dipnot değil. Kirli bir ağaçtan derlenen bir
	// ikili, taşıdığı etikete karşılık gelen kaynak DEĞİLDİR — ve bir
	// güvenlik yaması doğrulanırken tam olarak bu fark önemli.
	Dirty bool

	GoVersion string
	Platform  string
}

/*
 * pseudoVersion, Go'nun etiketsiz bir commit için ürettiği sürüm.
 *
 * Üç biçimi de (vX.0.0-<ts>-<hash>, vX.Y.Z-pre.0.<ts>-<hash>,
 * vX.Y.Z-0.<ts>-<hash>) aynı kuyrukla bitiyor: 14 haneli zaman damgası
 * ve 12 haneli commit öneki. Kuyruğu aramak üçünü birden yakalıyor ve
 * yeni bir bağımlılık (x/mod) getirmiyor.
 */
var pseudoVersion = regexp.MustCompile(`-[0-9]{14}-[0-9a-f]{12}$`)

// Get, çalışan ikilinin bilgisini toplar.
func Get() Info {
	i := Info{
		Version:   version,
		Tagged:    version != "",
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		if i.Version == "" {
			i.Version = "dev"
		}
		return i
	}

	/*
	 * ⚠️ ldflag BOŞSA, GO'NUN KENDİ GÖMDÜĞÜ SÜRÜME DÜŞ.
	 *
	 * `go install module@v1.2.3` ldflag basmıyor ama Go, etiketi
	 * bi.Main.Version'a koyuyor. Eskiden bunu yok sayıyorduk: bir
	 * etiketten `go install` ile kurulmuş ikili "not a tagged build"
	 * diyordu — Tagged alanının kendi yorumu ("etiketi biliyoruz")
	 * ile çelişen bir yalan.
	 *
	 * "(devel)" bir etiket değil (etiketsiz `go build`); onu atlıyoruz.
	 * "+dirty" ekini kırpıyoruz — kirlilik zaten ayrı alanda (Dirty).
	 *
	 * ⚠️ SAHTE SÜRÜM (pseudo-version) DE ETİKET DEĞİL — VE SAYILDIĞI
	 * HÂLİ ÖLÇÜLDÜ.
	 *
	 * "(devel)" kontrolü yalnızca modül dışı derlemeleri yakalıyordu.
	 * Bu depoda etiket yokken `make build` şunu basıyordu:
	 *
	 *   postern v0.0.0-20260903172313-67c66c03fa77
	 *
	 * uyarı OLMADAN. Yani Go'nun "hangi commit" demek için ürettiği
	 * sözde sürüm, gerçek bir sürüm etiketi gibi sunuluyordu — bir
	 * bakışta gerçek sürüm ikilisinden ayırt edilemez.
	 *
	 * Bu tam olarak Makefile'ın `git describe`'dan `--always`ı
	 * kaldırma sebebi ve .goreleaser.yaml'ın snapshot için "olamaz"
	 * dediği şey; CHANGELOG ve belgeler de "etiketten gelmeyen bir
	 * derleme bunu SÖYLER, sayı uydurmaz" sözünü veriyor. Üçü birden
	 * yanlıştı — ve etkilenen ikili, RELEASING.md'nin asla
	 * gönderilmemesi gerektiğini söylediği snapshot ikilisi.
	 *
	 * Sürüm metni yine de KULLANILIYOR: hangi commit olduğunu söylemesi
	 * işe yarıyor. Yalan olan Tagged'di, o yüzden yalnızca o false
	 * kalıyor ve uyarı geri geliyor.
	 */
	if i.Version == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		i.Version = strings.TrimSuffix(bi.Main.Version, "+dirty")
		i.Tagged = !pseudoVersion.MatchString(i.Version)
	}
	if i.Version == "" {
		i.Version = "dev"
	}

	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			i.Commit = s.Value
		case "vcs.time":
			i.CommitTime = s.Value
		case "vcs.modified":
			i.Dirty = s.Value == "true"
		}
	}
	return i
}

/*
 * Short, tek satırlık özet — log ve `--version` için.
 *
 * ⚠️ KİRLİLİK VE ETİKETSİZLİK BURADA DA GÖRÜNÜYOR. Kısa biçim
 * sürümün en çok okunacağı yer (açılış log'u); ayrımı yalnızca uzun
 * biçime koymak, onu pratikte hiç görünmez yapardı.
 */
func (i Info) Short() string {
	var b strings.Builder
	b.WriteString(i.Version)
	if !i.Tagged {
		b.WriteString(" (not a tagged build)")
	}
	if i.Commit != "" {
		fmt.Fprintf(&b, " %s", shortCommit(i.Commit))
	}
	if i.Dirty {
		b.WriteString(" (dirty tree)")
	}
	return b.String()
}

// String, çok satırlı ayrıntı — `postern version` için.
func (i Info) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "postern %s\n", i.Version)
	if !i.Tagged {
		// ⚠️ CÜMLE, ROZET DEĞİL. "dev" yazısını görüp yine de bunu bir
		// sürüm sanmak kolay; ne olmadığını söylemek gerekiyor.
		fmt.Fprintf(&b, "  %-9s this binary was not built from a release tag\n", "warning")
	}
	if i.Commit != "" {
		state := "clean"
		if i.Dirty {
			state = "MODIFIED — this is not the source of any commit"
		}
		fmt.Fprintf(&b, "  %-9s %s (%s)\n", "commit", shortCommit(i.Commit), state)
	}
	if i.CommitTime != "" {
		fmt.Fprintf(&b, "  %-9s %s\n", "committed", i.CommitTime)
	}
	fmt.Fprintf(&b, "  %-9s %s\n", "go", i.GoVersion)
	fmt.Fprintf(&b, "  %-9s %s\n", "platform", i.Platform)
	return b.String()
}

// shortCommit, hash'in okunur kısmı.
//
// On iki hane: git'in kısaltmasından uzun (çakışma riski daha düşük),
// bir log satırını taşıracak kadar uzun değil.
func shortCommit(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}
