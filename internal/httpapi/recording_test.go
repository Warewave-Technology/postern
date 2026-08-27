package httpapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// lastNewline, dosyanın son TAM satırının bittiği yeri bulmalı.
//
// Neden önemli: süren bir oturumun kayıt dosyasına başka bir goroutine
// tamponsuz yazıyor. Okuyucu satırın ortasına düşerse oynatıcıya yarım
// bir JSON dizisi gider ve kayıt "bozuk" görünür — oysa yalnızca henüz
// bitmemiştir.
func TestLastNewlineFindsCompletePrefix(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string // servis edilmesi gereken önek
	}{
		{
			name:    "yarim son satir kesilir",
			content: "{\"version\":2}\n[0.1,\"o\",\"a\"]\n[0.2,\"o\",\"yar",
			want:    "{\"version\":2}\n[0.1,\"o\",\"a\"]\n",
		},
		{
			name:    "tam dosya oldugu gibi",
			content: "{\"version\":2}\n[0.1,\"o\",\"a\"]\n",
			want:    "{\"version\":2}\n[0.1,\"o\",\"a\"]\n",
		},
		{
			name:    "yalniz baslik yazilmis",
			content: "{\"version\":2}\n",
			want:    "{\"version\":2}\n",
		},
		{
			name:    "hic satir sonu yok",
			content: "{\"versio",
			want:    "",
		},
		{
			name:    "bos dosya",
			content: "",
			want:    "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "x.cast")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()

			cut := lastNewline(f, int64(len(tc.content)))
			got := tc.content[:cut]

			if got != tc.want {
				t.Errorf("önek = %q, beklenen %q", got, tc.want)
			}
			// Servis edilen her şey ya boş ya satır sonuyla bitmeli:
			// oynatıcı tam satır varsayıyor.
			if got != "" && !strings.HasSuffix(got, "\n") {
				t.Errorf("önek satır sonuyla bitmiyor: %q", got)
			}
		})
	}
}

// Pencereden uzun bir son satır da doğru kesilmeli: lastNewline geriye
// doğru 8 KB'lik bloklar hâlinde tarıyor ve blok sınırına denk gelen bir
// satır sonu kaçırılmamalı.
func TestLastNewlineScansBeyondOneWindow(t *testing.T) {
	// Satır sonu ilk 8 KB'lik pencerenin DIŞINDA kalsın.
	head := "{\"version\":2}\n"
	tail := strings.Repeat("x", 20000)
	content := head + tail

	path := filepath.Join(t.TempDir(), "x.cast")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(path)
	defer f.Close()

	cut := lastNewline(f, int64(len(content)))
	if got := content[:cut]; got != head {
		t.Errorf("önek %d bayt, %d bekleniyordu (pencere sınırında satır sonu kaçırılmış)",
			len(got), len(head))
	}
}
