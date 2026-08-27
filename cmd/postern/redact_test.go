package main

import (
	"strings"
	"testing"
)

// DSN parolası log satırına GİRMEMELİ.
//
// Log dosyaya, konsola ve hata ayıklama paketlerine gider; oraya sızan
// bir veritabanı parolası, settings tablosundaki şifrelemenin tamamını
// anlamsız kılar (o parolayla veritabanına doğrudan bağlanılır).
func TestRedactDSNHidesPassword(t *testing.T) {
	cases := []struct {
		name string
		in   string
		must string // çıktıda GÖRÜNMESİ gereken
	}{
		{"url biciminde parola", "postgres://postern:s3cret@db.local:5432/postern?sslmode=verify-full", "db.local"},
		{"parolasiz url", "postgres://postern@db.local:5432/postern", "db.local"},
		{"anahtar=deger bicimi", "host=db.local user=postern password=s3cret", ""},
		{"bos", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactDSN(tc.in)

			if strings.Contains(got, "s3cret") {
				t.Errorf("parola sızdı: %q", got)
			}
			if tc.must != "" && !strings.Contains(got, tc.must) {
				t.Errorf("redactDSN(%q) = %q, %q içermeliydi (teşhis için host lazım)",
					tc.in, got, tc.must)
			}
		})
	}
}

// Ayrıştırılamayan biçim TAMAMEN gizlenmeli: tanımadığımız bir dizeyi
// "herhalde güvenlidir" diye olduğu gibi yazmak, gizlemenin amacını
// bozar.
func TestRedactDSNHidesUnparseableFormats(t *testing.T) {
	got := redactDSN("host=db.local user=postern password=s3cret sslmode=disable")
	if got != "[redacted]" {
		t.Errorf("anahtar=değer biçimi = %q, tamamen gizlenmeliydi", got)
	}
}

// ⚠️ cliActor BOŞ DÖNMEMELİ.
//
// Denetim satırının aktörü bu: boş kalırsa admin_log'daki CHECK
// (actor <> ”) yüzünden yazma DÜŞER — yani `user modify --admin` gibi
// en ayrıcalıklı işlem, denetim satırı yazılamadığı için tamamen
// başarısız olur. os/user.Current() konteynerlerde ve bazı statik
// derlemelerde hata verebiliyor, o yüzden yedek şart.
func TestCLIActorIsNeverEmpty(t *testing.T) {
	if got := cliActor(); got == "" {
		t.Error("cliActor boş döndü — denetim satırı yazılamaz")
	}
}
