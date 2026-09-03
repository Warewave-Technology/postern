package version_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

/*
 * ⚠️ SÜRÜM DAMGASININ DERLEMEDEN SAĞ ÇIKTIĞINI KİMSE ÖLÇMÜYORDU.
 *
 * version paketinin testleri Info değerlerini elle kurup biçimlendirmeyi
 * sınıyor — ldflag'in gerçekten basıldığını ve ikilinin onu taşıdığını
 * değil. Damga yolu (Makefile/goreleaser -X) sessizce bozulsa bütün o
 * testler yeşil kalırdı: "hangi sürümü çalıştırıyorum" sorusu tam da
 * yamayı doğrularken cevapsız kalırdı.
 *
 * Bu test ikiliyi GERÇEKTEN -ldflags ile derliyor ve `version` çıktısının
 * etiketi taşıdığını, "not a tagged build" DEMEDİĞİNİ doğruluyor.
 */
func TestVersionStampSurvivesTheBuild(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: derleme gerektiren test atlandı")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go yok")
	}

	dir := t.TempDir()
	bin := filepath.Join(dir, "postern")
	const tag = "v9.9.9-stamptest"

	build := exec.Command(goBin, "build",
		"-ldflags", "-X github.com/Warewave-Technology/postern/internal/version.version="+tag,
		"-o", bin, "./cmd/postern")
	build.Dir = repoRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("derleme başarısız: %v\n%s", err, out)
	}

	out, err := exec.Command(bin, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("postern version: %v\n%s", err, out)
	}
	got := string(out)
	if !strings.Contains(got, tag) {
		t.Errorf("ikili etiketi taşımıyor; çıktı:\n%s", got)
	}
	if strings.Contains(got, "not built from a release tag") {
		t.Errorf("damgalı ikili kendini etiketsiz sanıyor; çıktı:\n%s", got)
	}
}

/*
 * ⚠️ AYNASI: DAMGASIZ İKİLİ ETİKETSİZ OLDUĞUNU SÖYLEMELİ.
 *
 * Damgalı yönü yukarıdaki test ölçüyordu; damgasız yönü hiçbir şey
 * ölçmüyordu — ve orada bir yalan vardı. ldflag boş bırakılınca kod
 * Go'nun gömdüğü bi.Main.Version'a düşüyor; etiketsiz bir ağaçta o
 * değer bir SAHTE SÜRÜM (v0.0.0-<zaman>-<commit>) oluyor ve kod bunu
 * gerçek bir etiket sayıp uyarıyı düşürüyordu. Ölçüldü: `make build`
 * (etiket yok) `postern v0.0.0-20260903172313-67c66c03fa77` diyordu,
 * uyarı olmadan — gerçek bir sürüm ikilisinden ayırt edilemez.
 *
 * ⚠️ VE BU, SÜREÇ İÇİ BİR TESTLE GÖRÜLEMEZ. Test ikilisinde
 * debug.ReadBuildInfo, Main.Version'ı "(devel)" veriyor; yani paket
 * içinden yazılan bir test bu dala HİÇ giremiyor. Onun için gerçekten
 * `go build` yapılıyor — sahte sürümü yalnızca gerçek bir derleme
 * üretiyor.
 */
func TestUnstampedBuildSaysItIsNotARelease(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: derleme gerektiren test atlandı")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go yok")
	}

	dir := t.TempDir()
	bin := filepath.Join(dir, "postern")

	// -X YOK: goreleaser'ın snapshot'ta ve `go install .../cmd/postern@main`
	// ile olan hâli.
	build := exec.Command(goBin, "build", "-o", bin, "./cmd/postern")
	build.Dir = repoRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("derleme başarısız: %v\n%s", err, out)
	}

	out, err := exec.Command(bin, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("postern version: %v\n%s", err, out)
	}
	got := string(out)

	/*
	 * ⚠️ AĞACIN ETİKETLİ OLUP OLMADIĞI SORULUYOR — VE SORULMADIĞI HÂLİ
	 * SÜRÜMÜ TAMAMEN BLOKE EDİYORDU.
	 *
	 * Test "damgasız derleme uyarıyı basar" diye sabitlenmişti ve bu,
	 * yalnızca HEAD etiketsizken doğru. Go, ana modülün sürümünü VCS'ten
	 * türetiyor: etiketli bir commit'te -X olmadan derlenen ikili
	 * etiketin KENDİSİNİ taşıyor, dolayısıyla uyarı çıkmıyor ve
	 * doğrusu da bu.
	 *
	 * Bedeli ölçüldü: `git tag -a v1.0.0` atılmış bir kopyada bu test
	 * düşüyor. release.yml'in verify işi `make ci` koşuyor ve release
	 * işi `needs: verify` — yani ilk etiket, tam test takımını
	 * koşturduktan sonra burada durur ve HİÇBİR sürüm üretilmezdi.
	 * Etiket atılana kadar da görünmez: etiketsiz her commit'te Go
	 * sahte sürüm gömüyor ve test geçiyor.
	 *
	 * İki dal da anlamlı, o yüzden ikisi de sınanıyor: etiketsizken
	 * sahte sürümün etiket SAYILMADIĞI (testin yazılma sebebi),
	 * etiketliyken gerçek etiketin SAYILDIĞI.
	 */
	tag := exactTag(t, goBin)
	if tag == "" {
		if !strings.Contains(got, "not built from a release tag") {
			t.Errorf("damgasız ikili kendini SÜRÜM ilan ediyor — belgeler ve "+
				"goreleaser bunun olamayacağını söylüyor; çıktı:\n%s", got)
		}
		return
	}

	if strings.Contains(got, "not built from a release tag") {
		t.Errorf("HEAD %s etiketinde ama ikili kendini etiketsiz sanıyor — "+
			"Go'nun gömdüğü gerçek etiket kabul edilmiyor; çıktı:\n%s", tag, got)
	}
	if !strings.Contains(got, tag) {
		t.Errorf("ikili %s etiketini taşımıyor; çıktı:\n%s", tag, got)
	}
}

// exactTag, HEAD tam olarak bir etikete oturuyorsa onun adını döner,
// yoksa boş. git yoksa ya da burası bir çalışma kopyası değilse de boş:
// o hâlde Go da VCS bilgisi gömmüyor ve "etiketsiz" doğru cevap.
func exactTag(t *testing.T, goBin string) string {
	t.Helper()
	gitBin, err := exec.LookPath("git")
	if err != nil {
		return ""
	}
	cmd := exec.Command(gitBin, "describe", "--tags", "--exact-match", "HEAD")
	cmd.Dir = repoRoot(t)
	out, derr := cmd.Output()
	if derr != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// repoRoot, go.mod'un bulunduğu dizini bulur.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod bulunamadı")
		}
		dir = parent
	}
}
