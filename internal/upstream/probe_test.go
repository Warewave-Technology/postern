package upstream

import (
	"strings"
	"testing"
)

// os-release, kabukta kaynak gösterilmeden ELLE ayrıştırılıyor: hedefin
// yazdığı metni bizim tarafta çalıştırmak olurdu. Ayrıştırıcının
// gerçek dosyalarda çalıştığını doğruluyoruz.
func TestPrettyName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "debian",
			in: `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"`,
			want: "Debian GNU/Linux 12 (bookworm)",
		},
		{
			// PRETTY_NAME her dağıtımda yok; NAME neredeyse hep var ve
			// hiç yoktan iyi.
			name: "pretty yok, NAME'e düşer",
			in:   "NAME=\"Alpine Linux\"\nVERSION_ID=3.20.10",
			want: "Alpine Linux",
		},
		{
			name: "tırnaksız değer",
			in:   "PRETTY_NAME=Fedora Linux 40",
			want: "Fedora Linux 40",
		},
		{
			// Boş satır, yorum ve '=' içermeyen satır ayrıştırıcıyı
			// düşürmemeli: gerçek dosyalarda hepsi var.
			name: "gürültülü dosya",
			in:   "# comment\n\nID=ubuntu\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\ngarbage line\n",
			want: "Ubuntu 24.04 LTS",
		},
		{name: "boş", in: "", want: ""},
		{name: "alakasız", in: "hello world", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := prettyName(tc.in); got != tc.want {
				t.Errorf("prettyName() = %q, beklenen %q", got, tc.want)
			}
		})
	}
}

// ⚠️ Sınırsız okuma, düşmanca bir hedefin belleği doldurmasına izin
// verirdi: /etc/os-release yerine sonsuz bir akış koymak yeterli.
func TestLimitWriterCaps(t *testing.T) {
	var b strings.Builder
	w := &limitWriter{w: &b, left: 10}

	n, err := w.Write([]byte("0123456789ABCDEF"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Yazılmış GİBİ davranmalı: kısa yazma döndürmek komutu erken
	// hataya düşürür ve elimizdeki kısmi çıktıyı da kaybederdik.
	if n != 16 {
		t.Errorf("n = %d, 16 bekleniyordu (kısa yazma komutu düşürür)", n)
	}
	if b.String() != "0123456789" {
		t.Errorf("tampon = %q, sınır aşıldı", b.String())
	}

	// Sınır dolduktan sonraki yazmalar da sessizce atılmalı.
	if _, err := w.Write([]byte("XYZ")); err != nil {
		t.Fatalf("ikinci Write: %v", err)
	}
	if b.String() != "0123456789" {
		t.Errorf("tampon = %q, sınırdan sonra büyüdü", b.String())
	}
}

// Komut listesi SABİT ve gözden geçirilebilir olmalı: yapılandırılabilir
// olsaydı config'e erişen herkes denetim altındaki her makinede uzaktan
// komut çalıştırabilirdi.
func TestProbeCommandsAreReadOnly(t *testing.T) {
	if len(ProbeCommands) == 0 {
		t.Fatal("komut listesi boş")
	}
	for _, c := range ProbeCommands {
		// Kabuk yorumuna açık hiçbir şey olmamalı: SSH exec dizeyi
		// hedefin kabuğuna veriyor.
		for _, bad := range []string{";", "|", "&", "$", "`", ">", "<", "\n"} {
			if strings.Contains(c, bad) {
				t.Errorf("komut %q kabuk metakarakteri içeriyor: %q", c, bad)
			}
		}
	}
}
