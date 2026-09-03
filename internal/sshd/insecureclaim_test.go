package sshd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

/*
 * ⚠️ AÇILIŞ SAYFASI MUTLAK BİR İDDİADA BULUNUYOR; BU TEST ONU TUTUYOR.
 *
 * site/index.html ve kurulum belgesi şunu yazıyor: "InsecureIgnoreHostKey
 * is called nowhere, tests included" ve okuru doğrulamaya davet ediyor.
 * Bir süre yanlıştı — tek bir `git grep` onu çürütüyordu ve bulunduğu yer
 * bir HOST ANAHTARI testiydi, yani görünebileceği en kötü dosya.
 *
 * Güvenlik iddiası, onu koruyan bir kontrol olmadan yazılmamalı: yoksa
 * bir sonraki "testte zaten önemli değil" kararı onu sessizce yalana
 * çevirir. Yorumda geçmesi serbest — yasağın kendisini anlatan satırlar
 * var; yasak olan ÇAĞRI.
 */
func TestInsecureIgnoreHostKeyIsCalledNowhere(t *testing.T) {
	root := repoRootFrom(t, ".")

	// ⚠️ Parçalardan kuruluyor: tek parça yazılsaydı bu dosya KENDİNİ
	// bulurdu ve test hiçbir zaman geçemezdi.
	needle := "InsecureIgnore" + "HostKey()"

	var hits []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, werr error) error {
		if werr != nil {
			return nil
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "node_modules", "dist", "bin", ".claude", "web":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, rerr := os.ReadFile(path) // #nosec G304 -- depo içi, test
		if rerr != nil {
			return nil
		}
		for i, line := range strings.Split(string(b), "\n") {
			t := strings.TrimSpace(line)
			// Yorumlar serbest: yasağı ANLATAN satırlar var.
			if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "*") ||
				strings.HasPrefix(t, "/*") {
				continue
			}
			if strings.Contains(line, needle) {
				rel, _ := filepath.Rel(root, path)
				hits = append(hits, rel+":"+itoa(i+1))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(hits) > 0 {
		t.Errorf("InsecureIgnoreHostKey çağrısı bulundu: %s\n"+
			"Açılış sayfası ve kurulum belgesi bunun HİÇBİR YERDE, "+
			"testler dahil, çağrılmadığını yazıyor ve okuru doğrulamaya "+
			"davet ediyor. Test dosyasında bile olsa iddia yalan oluyor — "+
			"ssh.FixedHostKey kullan.", strings.Join(hits, ", "))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// repoRootFrom, go.mod'un bulunduğu dizini bulur.
func repoRootFrom(t *testing.T, start string) string {
	t.Helper()
	dir, err := filepath.Abs(start)
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, serr := os.Stat(filepath.Join(dir, "go.mod")); serr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod bulunamadı")
		}
		dir = parent
	}
}
