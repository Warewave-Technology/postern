package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/warewave/postern/internal/discover"
)

func capture(t *testing.T, res []discover.Outcome, tagKey string) string {
	t.Helper()
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	printDiscovery(cmd, res, false, tagKey)
	return buf.String()
}

/*
 * ⚠️ YANLIŞ ETİKET ANAHTARI SESSİZ KALMAMALI.
 *
 * ÖLÇÜLEN ARIZA: ayrıştırıcı bir süre yalnızca "anahtar=değer" tanıyordu
 * ve Proxmox etiketlerine `=` yazılamıyor — dolayısıyla gerçek bir
 * kurulumda HER makine unknown'a düşüyordu. Çıktı satır satır
 * "untagged" diyordu ama hiçbir yerde "anahtarın hiçbir şeyle
 * eşleşmedi" yazmıyordu; operatör bunu ancak envantere şaşırarak fark
 * etti. Aynı sessizlik, anahtarı yanlış yazan herkes için de geçerli.
 */
func TestReportShoutsWhenNoTagMatched(t *testing.T) {
	res := []discover.Outcome{
		{Machine: discover.Machine{
			Name: "web-01", Host: "10.0.0.1",
			Tags: []string{"role-name_os-admins", "production"},
		}, Role: discover.UnknownRole, Tagged: false},
		{Machine: discover.Machine{
			Name: "db-01", Host: "10.0.0.2",
			Tags: []string{"role-name_dba", "linux"},
		}, Role: discover.UnknownRole, Tagged: false},
	}

	out := capture(t, res, "role")

	if !strings.Contains(out, "not one machine carried") {
		t.Fatalf("hiçbir eşleşme yokken uyarı yok:\n%s", out)
	}
	// ⚠️ GERÇEK ETİKETLER BASILMALI: yanlış anahtarı yazan kişi
	// doğrusunu ekranda görmeli, belgeye gitmek zorunda kalmamalı.
	if !strings.Contains(out, "role-name_os-admins") {
		t.Errorf("görülen etiketler basılmıyor:\n%s", out)
	}
	// Ve ne yazması gerektiği önerilmeli.
	if !strings.Contains(out, `--tag-key "role-name"`) {
		t.Errorf("doğru anahtar önerilmiyor:\n%s", out)
	}
}

// Eşleşme VARKEN uyarı çıkmamalı: her koşuda bağıran bir uyarı,
// okunmayan bir uyarıdır.
func TestReportStaysQuietWhenTagsMatch(t *testing.T) {
	res := []discover.Outcome{
		{Machine: discover.Machine{
			Name: "web-01", Host: "10.0.0.1", Tags: []string{"role_web"},
		}, Role: "web", Tagged: true},
		{Machine: discover.Machine{
			Name: "old-01", Host: "10.0.0.9", Tags: []string{"linux"},
		}, Role: discover.UnknownRole, Tagged: false},
	}

	out := capture(t, res, "role")
	if strings.Contains(out, "not one machine carried") {
		t.Errorf("eşleşme varken uyarı çıktı:\n%s", out)
	}
}

// Hiç etiketi olmayan envanterde de sebep söylenmeli, ama "şu etiketler
// görüldü" diye boş bir liste basılmamalı.
func TestReportSaysWhenThereAreNoTagsAtAll(t *testing.T) {
	res := []discover.Outcome{
		{Machine: discover.Machine{Name: "web-01", Host: "10.0.0.1"},
			Role: discover.UnknownRole, Tagged: false},
	}
	out := capture(t, res, "role")
	if !strings.Contains(out, "no tags at all") {
		t.Errorf("etiketsiz envanterde sebep yok:\n%s", out)
	}
	if strings.Contains(out, "tags actually seen") {
		t.Errorf("boş etiket listesi basıldı:\n%s", out)
	}
}
