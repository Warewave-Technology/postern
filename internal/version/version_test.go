package version

import (
	"strings"
	"testing"
)

/*
 * ⚠️ ETİKETSİZ DERLEME KENDİNİ SÜRÜM SANMAMALI.
 *
 * "Yamalı mıyım" sorusuna verilebilecek en kötü cevap, bir geliştirme
 * derlemesinin kendini v1.0.0 diye tanıtması. Uyarı hem kısa hem uzun
 * biçimde duruyor: kısa biçim açılış log'unda görünen tek satır ve
 * ayrımı yalnızca uzun biçime koymak, onu pratikte görünmez yapardı.
 */
func TestUntaggedBuildSaysSo(t *testing.T) {
	i := Info{Version: "dev", GoVersion: "go1.26.6", Platform: "linux/amd64"}

	if !strings.Contains(i.Short(), "not a tagged build") {
		t.Errorf("kısa biçim etiketsizliği söylemiyor: %q", i.Short())
	}
	if !strings.Contains(i.String(), "not built from a release tag") {
		t.Errorf("uzun biçim etiketsizliği söylemiyor:\n%s", i)
	}
}

// Etiketli derleme uyarı BASMAMALI: her çıktıya uyarı koymak, uyarıyı
// okunmaz hâle getirir.
func TestTaggedBuildIsQuiet(t *testing.T) {
	i := Info{Version: "v1.0.0", Tagged: true, GoVersion: "go1.26.6", Platform: "linux/amd64"}

	if strings.Contains(i.Short(), "not a tagged") {
		t.Errorf("etiketli derlemede uyarı çıktı: %q", i.Short())
	}
	if strings.Contains(i.String(), "warning") {
		t.Errorf("etiketli derlemede uyarı çıktı:\n%s", i)
	}
}

/*
 * ⚠️ KİRLİ AĞAÇTAN DERLENEN "v1.0.0", v1.0.0 DEĞİLDİR.
 *
 * Bir güvenlik yaması doğrulanırken önemli olan tam olarak bu fark:
 * etiket, ikilinin içindeki kodun o commit olduğunu garanti etmiyor.
 * VCS bilgisi elle basılamıyor, dolayısıyla etiketle çelişebiliyor —
 * ve çeliştiğinde bunu söylemek gerekiyor.
 */
func TestDirtyTreeIsReportedEvenWhenTagged(t *testing.T) {
	i := Info{
		Version: "v1.0.0", Tagged: true, Dirty: true,
		Commit: "15911df1ee66aabbccdd", GoVersion: "go1.26.6", Platform: "linux/amd64",
	}

	if !strings.Contains(i.Short(), "dirty") {
		t.Errorf("kısa biçim kirliliği gizledi: %q", i.Short())
	}
	if !strings.Contains(i.String(), "not the source of any commit") {
		t.Errorf("uzun biçim kirliliği gizledi:\n%s", i)
	}
}

// Hash okunur uzunlukta kısaltılıyor ama kısa hash'ler bozulmuyor.
func TestShortCommit(t *testing.T) {
	if got := shortCommit("15911df1ee66aabbccddeeff"); got != "15911df1ee66" {
		t.Errorf("kısaltma = %q", got)
	}
	if got := shortCommit("abc"); got != "abc" {
		t.Errorf("kısa hash bozuldu: %q", got)
	}
}

/*
 * Get(), VCS bilgisi hiç yokken bile çalışmalı.
 *
 * `-buildvcs=false` ile ya da git ağacı dışında derlenen bir ikilide
 * debug.BuildInfo bu alanları taşımıyor; orada panik atmak yerine
 * bilmediğini söylemesi gerekiyor.
 */
func TestGetWorksWithoutVCSInfo(t *testing.T) {
	i := Get()
	if i.Version == "" {
		t.Error("sürüm boş: en azından 'dev' olmalı")
	}
	if i.GoVersion == "" || i.Platform == "" {
		t.Errorf("derleme bilgisi eksik: %+v", i)
	}
}
