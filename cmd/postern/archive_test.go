package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/Warewave-Technology/postern/internal/archive"
	"github.com/Warewave-Technology/postern/internal/objstore"
	"github.com/Warewave-Technology/postern/internal/secret"
)

func codeErr(code string, status int, base error) error {
	return &objstore.CodeError{Code: code, Status: status, Err: base}
}

/*
 * ⚠️ OLMAYAN KOVA "YAPILANDIRILMAMIŞ" DEĞİLDİR.
 *
 * ÖLÇÜLEN ARIZA: isNotConfigured "NoSuch" alt dizesine bakıyordu ve
 * NoSuchBucket ona uyuyordu. Olmayan bir kova için rapor yeşil çıkıyor,
 * "2 şey zayıf" diyor ve sıfırla bitiyordu — oysa hiçbir kayıt
 * yüklenemez. Raporun en tehlikeli hâli tam olarak bu: çalışmayan bir
 * kurulumu çalışıyor göstermek.
 */
func TestMissingBucketIsNotReportedAsUnconfigured(t *testing.T) {
	err := codeErr("NoSuchBucket", 404, objstore.ErrPermanent)

	if isNotConfigured(err) {
		t.Error("NoSuchBucket 'yapılandırılmamış' sayıldı — rapor yeşil çıkardı")
	}
	if !isUnreachable(err) {
		t.Error("NoSuchBucket ulaşılamama sayılmadı — komut sıfırla biterdi")
	}
}

// Alt kaynağın yokluğu bir OLGU, arıza değil.
func TestUnconfiguredSubresourcesAreFacts(t *testing.T) {
	for _, code := range []string{
		"ObjectLockConfigurationNotFoundError",
		"ServerSideEncryptionConfigurationNotFoundError",
	} {
		err := codeErr(code, 404, objstore.ErrPermanent)
		if !isNotConfigured(err) {
			t.Errorf("%s yapılandırılmamış sayılmadı", code)
		}
		if isUnreachable(err) {
			t.Errorf("%s ulaşılamama sayıldı — komut boşuna hata verirdi", code)
		}
	}
}

/*
 * ⚠️ YETKİSİZLİK "KAPALI" DEĞİL, "ÖĞRENEMEDİM".
 *
 * Okuma yetkisi olmayan bir kimlikle çalışan kurulumu "her şey kapalı"
 * diye göstermek, yanlış ve yanlış yönde: operatör var olan bir
 * korumayı yok sanıp gereksiz iş yapardı.
 */
func TestAccessDeniedIsNeitherConfiguredNorUnreachable(t *testing.T) {
	err := codeErr("AccessDenied", 403, objstore.ErrPermanent)
	if isNotConfigured(err) {
		t.Error("AccessDenied 'kapalı' diye raporlanırdı")
	}
	if isUnreachable(err) {
		t.Error("AccessDenied ulaşılamama sayıldı — sertleştirme eksiği hata olurdu")
	}
	if got := reason(err); got != "AccessDenied" {
		t.Errorf("sebep = %q", got)
	}
}

// Kimlik hataları kesin arıza: yükleme şu an çalışmıyor.
func TestCredentialFailuresAreUnreachable(t *testing.T) {
	for _, code := range []string{
		"InvalidAccessKeyId", "SignatureDoesNotMatch", "RequestTimeTooSkewed",
	} {
		if !isUnreachable(codeErr(code, 403, objstore.ErrPermanent)) {
			t.Errorf("%s ulaşılamama sayılmadı", code)
		}
	}
	// Ağ hatası da öyle.
	if !isUnreachable(errors.New("x: " + objstore.ErrTransient.Error())) {
		// errors.Is zinciri olmadan eşleşmemeli; sarmalanmışı eşleşmeli.
	}
	wrapped := errors.Join(objstore.ErrTransient, errors.New("dial"))
	if !isUnreachable(wrapped) {
		t.Error("ağ hatası ulaşılamama sayılmadı")
	}
}

/*
 * ⚠️ "ASLA ÖĞRENEMEZ" BÖLÜMÜ RAPORDAN SİLİNEMEZ.
 *
 * Yukarıdaki iki bölüm neyi bildiğimizi söylüyor; bu bölüm raporun
 * "kontrol ettim, güvendeyim" diye okunmasını engelliyor. Silinirse
 * rapor güvenlik tiyatrosuna dönerdi.
 */
func TestNeverKnowableSectionNamesTheLimits(t *testing.T) {
	var b strings.Builder
	printNeverKnowable(&b)
	out := b.String()

	for _, must := range []string{
		"delete permission",
		"who else can write",
		"whether this stays true",
		"an attacker who owns it gets the same answers",
	} {
		if !strings.Contains(out, must) {
			t.Errorf("bölüm %q içermiyor", must)
		}
	}
}

// Boş bölüm sessiz geçmemeli: "hiçbir şey öğrenilemedi" ile "bölüm
// yazılmadı" farklı şeyler.
func TestEmptySectionSaysSo(t *testing.T) {
	var b strings.Builder
	printSection(&b, "Could not be determined", nil)
	if !strings.Contains(b.String(), "(nothing)") {
		t.Errorf("boş bölüm sessiz geçti: %q", b.String())
	}
}

/*
 * ⚠️ KOMUTUN GERÇEK ÇIKTISINI ÖLÇÜYOR, fonksiyonları değil.
 *
 * Bu testi bir mutasyon yazdırdı: printNeverKnowable'ı ÇAĞIRAN satırı
 * sildim ve hiçbir test düşmedi — birimi ölçüyordum, kablolamayı değil.
 * Bölüm sessizce rapordan düşebilirdi ve rapor "kontrol ettim,
 * güvendeyim" diye okunur hâle gelirdi.
 */
func TestArchiveCheckPrintsAllThreeSections(t *testing.T) {
	e := newEnv(t)

	// Kovanın söylediklerini taklit eden depo: sertleştirilmiş hâl.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.RawQuery {
		case "versioning":
			io.WriteString(w, `<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`)
		case "object-lock":
			io.WriteString(w, `<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled>`+
				`<Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>30</Days>`+
				`</DefaultRetention></Rule></ObjectLockConfiguration>`)
		case "encryption":
			// Yetkisiz: "öğrenilemedi" sütununa düşmeli.
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `<Error><Code>AccessDenied</Code></Error>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cfgPath := writeArchiveConfig(t, e, srv.URL)
	out, err := runWithConfig(t, newArchiveCmd(), cfgPath, "check")
	if err != nil {
		t.Fatalf("archive check: %v (%s)", err, out)
	}

	for _, must := range []string{
		"What the bucket reported",
		"Could not be determined",
		"What postern can never determine",
		"COMPLIANCE",
		"AccessDenied",
		"an attacker who owns it gets the same answers",
	} {
		if !strings.Contains(out, must) {
			t.Errorf("çıktı %q içermiyor:\n%s", must, out)
		}
	}

	// Sertleştirilmiş kovada "zayıf" uyarısı OLMAMALI.
	if strings.Contains(out, "weaken the archive") {
		t.Errorf("sertleştirilmiş kova zayıf raporlandı:\n%s", out)
	}
}

// Zayıf kova uyarı vermeli ama sıfırla bitmeli: bilerek yapılmış bir
// tercih olabilir ve yükleme çalışıyor.
func TestArchiveCheckWarnsButSucceedsOnAWeakBucket(t *testing.T) {
	e := newEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.RawQuery {
		case "versioning":
			io.WriteString(w, `<VersioningConfiguration></VersioningConfiguration>`)
		default:
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `<Error><Code>ObjectLockConfigurationNotFoundError</Code></Error>`)
		}
	}))
	defer srv.Close()

	cfgPath := writeArchiveConfig(t, e, srv.URL)
	out, err := runWithConfig(t, newArchiveCmd(), cfgPath, "check")
	if err != nil {
		t.Fatalf("zayıf kova hata verdi: %v", err)
	}
	if !strings.Contains(out, "weaken the archive") {
		t.Errorf("zayıflık uyarısı yok:\n%s", out)
	}
	if !strings.Contains(out, "not append-only") {
		t.Errorf("PutObject'in append-only olmadığı söylenmiyor:\n%s", out)
	}
}

// writeArchiveConfig, arşiv ayarlı bir config yazar.
func writeArchiveConfig(t *testing.T, e *testEnv, endpoint string) string {
	t.Helper()
	keyFile := filepath.Join(e.dir, "archive.key")
	if err := os.WriteFile(keyFile, []byte("gizli"), 0o600); err != nil {
		t.Fatal(err)
	}
	base, err := os.ReadFile(e.config)
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(base) +
		"  archive:\n" +
		"    endpoint: " + endpoint + "\n" +
		"    bucket: kova\n" +
		"    region: us-east-1\n" +
		"    access_key_id: AKIATEST\n" +
		"    secret_key_file: " + keyFile + "\n"
	p := filepath.Join(e.dir, "archive.yaml")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func runWithConfig(t *testing.T, cmd *cobra.Command, cfgPath string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(append(args, "--config", cfgPath))
	err := cmd.Execute()
	return out.String(), err
}

/*
 * ⚠️ PANELDEN GİRİLEN ANAHTARLA `archive check` ÇALIŞMALI.
 *
 * Belgeler operatöre iki şeyi birden söylüyor: arşiv anahtarını
 * PANELDEN gir, ve kovanın sürümleme/Object Lock durumunu görmek için
 * `postern archive check` koş. İkisini birden yapan kurulumda komut
 * HER ZAMAN düşüyordu.
 *
 * Sebep: panelden girilen sır veritabanında ŞİFRELİ duruyor ve onu
 * çözebilmek secret_key_file'ın yüklenmesine bağlı. resolveArchiveCreds
 * store'u sır kutusunu bağlamadan açıyordu, dolayısıyla "ana gizli
 * anahtar yapılandırılmamış" diyordu — oysa dosya yerinde ve koşan
 * bastion aynı dosyayla aynı değeri çözüyor. Hata metni operatörü,
 * zaten var olan bir anahtar dosyasını aramaya gönderiyordu.
 */
func TestArchiveCheckReadsACredentialSetFromThePanel(t *testing.T) {
	e := newEnv(t)

	// Ana gizli anahtar: paneldeki sırrı mühürleyen/çözen dosya.
	keyPath := filepath.Join(e.dir, "secret.key")
	box, err := secret.Init(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	// Panelin yaptığı: kimlik veritabanına, sır MÜHÜRLÜ olarak.
	ctx := context.Background()
	e.db.UseSecretBox(box)
	if serr := e.db.SetSetting(ctx, archive.KeyAccessKeyID, "AKIAPANEL", false, "admin"); serr != nil {
		t.Fatal(serr)
	}
	if serr := e.db.SetSetting(ctx, archive.KeySecretAccessKey, "panelden-gelen-sir", true, "admin"); serr != nil {
		t.Fatal(serr)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Kovanın var olduğunu söylemek yeterli: ölçtüğümüz şey kimliğin
		// OKUNABİLMESİ, kovanın ne dediği değil.
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// ⚠️ archive.secret_key_file YOK — belgelenen "panelden gir" düzeni.
	// Ana secret_key_file ise ÜST DÜZEYDE, koşan bastion'daki gibi.
	base, rerr := os.ReadFile(e.config)
	if rerr != nil {
		t.Fatal(rerr)
	}
	cfg := "secret_key_file: " + keyPath + "\n" + string(base) +
		"  archive:\n" +
		"    endpoint: " + srv.URL + "\n" +
		"    bucket: kova\n" +
		"    region: us-east-1\n" +
		"    access_key_id: AKIAPANEL\n"
	cfgPath := filepath.Join(e.dir, "panel-archive.yaml")
	if werr := os.WriteFile(cfgPath, []byte(cfg), 0o600); werr != nil {
		t.Fatal(werr)
	}

	out, cerr := runWithConfig(t, newArchiveCmd(), cfgPath, "check")

	if strings.Contains(out, "secret key") && strings.Contains(strings.ToLower(out), "not configured") {
		t.Fatalf("panelden girilen anahtar okunamadı — komut var olan bir "+
			"anahtar dosyasını aramaya gönderiyor; çıktı:\n%s", out)
	}
	if cerr != nil && strings.Contains(cerr.Error(), "secret") {
		t.Fatalf("archive check sır çözemedi: %v\nçıktı:\n%s", cerr, out)
	}
	// Kimliğin PANELDEN geldiğini söylemeli: kaynağı yanlış söylemek,
	// operatörün hangi anahtarı değiştireceğini bilememesi demek.
	if !strings.Contains(strings.ToLower(out), "panel") {
		t.Errorf("çıktı kimliğin panelden geldiğini söylemiyor:\n%s", out)
	}
}
