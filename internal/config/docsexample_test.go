package config_test

import (
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"

	"github.com/warewave/postern/internal/config"
)

/*
 * ⚠️ BELGELERDEKİ CONFIG ÖRNEĞİNİ HİÇBİR ŞEY AYRIŞTIRMIYORDU.
 *
 * Kurulum sayfasının § Config reference bloğu `min_free: 5GB`
 * gönderiyordu ve ayrıştırıcı SI ekini tanımıyor — yalnızca KiB/MiB/
 * GiB/TiB. Yani sayfayı baştan sona izleyen bir operatör, veritabanını
 * göç ettirdikten ve acil durum hesabını açtıktan SONRA, EN SON adımda
 * açılmayan bir bastion'la kalıyordu. Hata metni iyi ama okuyucunun
 * kopyalayabileceği ÇALIŞAN bir örneği yoktu: belgelerdeki her
 * min_free bozuk olanıydı.
 *
 * Belgeler ürünün bir parçası. Bu test onları ürünün kendi
 * yükleyicisinden geçiriyor.
 */
func TestDocumentedConfigExamplesLoad(t *testing.T) {
	const docs = "../../site/docs/index.html"
	b, err := os.ReadFile(docs)
	if err != nil {
		t.Fatalf("belgeler okunamadı: %v", err)
	}

	pre := regexp.MustCompile(`(?s)<pre>(.*?)</pre>`)
	tags := regexp.MustCompile(`<[^>]+>`)

	found := 0
	for _, m := range pre.FindAllStringSubmatch(string(b), -1) {
		text := html.UnescapeString(tags.ReplaceAllString(m[1], ""))

		// Yalnızca postern config'i olan bloklar: kabuk komutları,
		// systemd birimleri ve SQL de <pre> içinde.
		if !strings.Contains(text, "recording:") || !strings.Contains(text, "min_free:") {
			continue
		}
		found++

		/*
		 * ⚠️ İKİ BLOK TÜRÜ, İKİ AYRI ÖLÇÜM.
		 *
		 * § Config reference TAM bir config: ürünün kendi yükleyicisinden
		 * geçmeli. § Retention'daki blok bir BÖLÜM ALINTISI: ona uydurma
		 * bir iskelet ekleyip "tam config" gibi doğrulamak, belgeyi değil
		 * testin kendi iskeletini ölçmek olurdu — orada ölçülen şey
		 * bloğun kendi DEĞERLERİNİN kabul edilip edilmediği.
		 */
		var cfg config.Config
		if strings.Contains(text, "listen:") {
			dir := t.TempDir()
			// Örnek yollar KURULUM yolları: testin makinesinde yok ve
			// olması da gerekmiyor.
			text = strings.ReplaceAll(text, "/etc/postern/", dir+"/")
			text = strings.ReplaceAll(text, "/var/lib/postern/", dir+"/")
			for _, f := range []string{"host_ed25519", "secret.key", "ca_ed25519"} {
				if werr := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); werr != nil {
					t.Fatal(werr)
				}
			}
			path := filepath.Join(dir, "postern.yaml")
			if werr := os.WriteFile(path, []byte(text), 0o600); werr != nil {
				t.Fatal(werr)
			}
			loaded, lerr := config.Load(path)
			if lerr != nil {
				t.Errorf("belgelerdeki tam config örneği yüklenemiyor — sayfayı "+
					"izleyen operatörün bastion'ı açılmıyor:\n%v", lerr)
				continue
			}
			cfg = *loaded
		} else if uerr := yaml.UnmarshalWithOptions([]byte(text), &cfg, yaml.Strict()); uerr != nil {
			t.Errorf("belgelerdeki config alıntısı ayrıştırılamıyor:\n%v", uerr)
			continue
		}

		// ⚠️ Load bunu ÇAĞIRMIYOR: bozuk bir min_free yüklemeyi geçip
		// `postern serve`'de düşüyor — yani belgeyi izleyen operatör
		// hatayı en son adımda görüyor.
		if _, merr := cfg.Recording.MinFreeBytes(); merr != nil {
			t.Errorf("belgelerdeki min_free değeri reddediliyor: %v", merr)
		}
	}

	if found == 0 {
		t.Fatal("belgelerde config örneği bulunamadı — test hiçbir şey " +
			"ölçmüyor (blok biçimi mi değişti?)")
	}
	t.Logf("ayrıştırılan config bloğu: %d", found)
}
