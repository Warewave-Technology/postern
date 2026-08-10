package sshd

import (
	"strings"
	"testing"
)

// S1.3 tablosu — postern-PLAN.md'deki 8 senaryo. Hedef: tablo geçiyor ve
// username.go %100 kapsamada (go test ./internal/sshd/ -cover ile bak).
func TestParseUsername(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    Route
		wantErr bool
	}{
		{
			name: "basit hal",
			raw:  "yigit:web01",
			want: Route{User: "yigit", Target: "web01"},
		},
		{
			name:    "target yok",
			raw:     "yigit",
			wantErr: true,
		},
		{
			name:    "bos target",
			raw:     "yigit:",
			wantErr: true,
		},
		{
			name:    "bos user",
			raw:     ":web01",
			wantErr: true,
		},
		{
			// Ayraç İLK ':' — target'ın içinde ':' olabilir.
			name: "ilk iki noktadan boler",
			raw:  "yigit:web:01",
			want: Route{User: "yigit", Target: "web:01"},
		},
		{
			name: "fazla parcalar targata gider",
			raw:  "yigit:web01:extra",
			want: Route{User: "yigit", Target: "web01:extra"},
		},
		{
			name:    "bos girdi",
			raw:     "",
			wantErr: true,
		},
		{
			// Format geçerli, TEK sorun uzunluk (512 karakter) — böylece bu
			// case yalnızca uzunluk sınırını test ediyor.
			name:    "cok uzun girdi",
			raw:     "yigit:" + strings.Repeat("w", 506),
			wantErr: true,
		},
		{
			// İmplementasyon user ve target'ı ayrı ayrı sınırlıyor;
			// user tarafının sınırını da ayrıca pinle.
			name:    "cok uzun user",
			raw:     strings.Repeat("u", 256) + ":web01",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseUsername(tc.raw)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("hata bekleniyordu; gelen: %+v", got)
				}
				return
			}

			if err != nil {
				t.Fatalf("beklenmeyen hata: %v", err)
			}
			if got != tc.want {
				t.Fatalf("ParseUsername(%q) = %+v, beklenen %+v", tc.raw, got, tc.want)
			}
		})
	}
}
