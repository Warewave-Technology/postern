package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/Warewave-Technology/postern/v2/internal/discover"
)

func capture(t *testing.T, res []discover.Outcome, tagKey string) string {
	t.Helper()
	out, _ := captureApply(t, res, tagKey, false)
	return out
}

func captureApply(t *testing.T, res []discover.Outcome, tagKey string, apply bool) (string, error) {
	t.Helper()
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	err := printDiscovery(cmd, res, apply, tagKey)
	return buf.String(), err
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
			Tags: []string{"group-name_os-admins", "production"},
		}, Group: discover.UnknownGroup, Tagged: false},
		{Machine: discover.Machine{
			Name: "db-01", Host: "10.0.0.2",
			Tags: []string{"group-name_dba", "linux"},
		}, Group: discover.UnknownGroup, Tagged: false},
	}

	out := capture(t, res, "group")

	if !strings.Contains(out, "not one machine carried") {
		t.Fatalf("hiçbir eşleşme yokken uyarı yok:\n%s", out)
	}
	// ⚠️ GERÇEK ETİKETLER BASILMALI: yanlış anahtarı yazan kişi
	// doğrusunu ekranda görmeli, belgeye gitmek zorunda kalmamalı.
	if !strings.Contains(out, "group-name_os-admins") {
		t.Errorf("görülen etiketler basılmıyor:\n%s", out)
	}
	// Ve ne yazması gerektiği önerilmeli.
	if !strings.Contains(out, `--tag-key "group-name"`) {
		t.Errorf("doğru anahtar önerilmiyor:\n%s", out)
	}
}

// Eşleşme VARKEN uyarı çıkmamalı: her koşuda bağıran bir uyarı,
// okunmayan bir uyarıdır.
func TestReportStaysQuietWhenTagsMatch(t *testing.T) {
	res := []discover.Outcome{
		{Machine: discover.Machine{
			Name: "web-01", Host: "10.0.0.1", Tags: []string{"role_web"},
		}, Group: "web", Tagged: true},
		{Machine: discover.Machine{
			Name: "old-01", Host: "10.0.0.9", Tags: []string{"linux"},
		}, Group: discover.UnknownGroup, Tagged: false},
	}

	out := capture(t, res, "group")
	if strings.Contains(out, "not one machine carried") {
		t.Errorf("eşleşme varken uyarı çıktı:\n%s", out)
	}
}

// Hiç etiketi olmayan envanterde de sebep söylenmeli, ama "şu etiketler
// görüldü" diye boş bir liste basılmamalı.
func TestReportSaysWhenThereAreNoTagsAtAll(t *testing.T) {
	res := []discover.Outcome{
		{Machine: discover.Machine{Name: "web-01", Host: "10.0.0.1"},
			Group: discover.UnknownGroup, Tagged: false},
	}
	out := capture(t, res, "group")
	if !strings.Contains(out, "no tags at all") {
		t.Errorf("etiketsiz envanterde sebep yok:\n%s", out)
	}
	if strings.Contains(out, "tags actually seen") {
		t.Errorf("boş etiket listesi basıldı:\n%s", out)
	}
}

/*
 * ⚠️ HİÇBİR ŞEY YAZILMADIYSA ÇIKIŞ KODU BUNU SÖYLEMELİ.
 *
 * ÖLÇÜLEN ARIZA: komut her zaman 0 dönüyordu — bütün makineler atlanmış
 * olsa bile. Zamanlanmış bir keşif hiçbir şey yapmadan "başarılı"
 * raporluyor, envanterin donduğunu kimse fark etmiyordu. Kullanıcının
 * yaşadığı durum tam buydu: 24 makinenin 24'ü atlandı, komut 0 döndü.
 */
func TestApplyThatWroteNothingFails(t *testing.T) {
	res := []discover.Outcome{
		{Machine: discover.Machine{Name: "web-01"}, Group: "unknown",
			Skipped: "not running, so its host key cannot be read"},
		{Machine: discover.Machine{Name: "db-01"}, Group: "unknown",
			Skipped: "not running, so its host key cannot be read"},
	}
	_, err := captureApply(t, res, "group", true)
	if err == nil {
		t.Fatal("hiçbir şey yazılmadığı hâlde başarı döndü — betik bunu " +
			"fark edemez")
	}
	if !strings.Contains(err.Error(), "all 2 machine(s) were skipped") {
		t.Errorf("hata sebebi belirsiz: %v", err)
	}
}

// Bir şey yazıldıysa atlamalar olağandır (kapalı sanal makine) ve
// koşum başarılıdır: her atlamada bağıran bir çıkış kodu, betikte
// görmezden gelinen bir çıkış kodudur.
func TestApplyThatWroteSomethingSucceeds(t *testing.T) {
	res := []discover.Outcome{
		{Machine: discover.Machine{Name: "web-01"}, Group: "web",
			Tagged: true, CreatedTarget: true, Granted: true},
		{Machine: discover.Machine{Name: "db-01"}, Group: "unknown",
			Skipped: "not running, so its host key cannot be read"},
	}
	if _, err := captureApply(t, res, "group", true); err != nil {
		t.Fatalf("yazım olduğu hâlde hata döndü: %v", err)
	}
}

// Önizleme hiçbir şey yazmaz ve bu bir hata değildir.
func TestPreviewNeverFails(t *testing.T) {
	res := []discover.Outcome{
		{Machine: discover.Machine{Name: "web-01"}, Group: "unknown",
			Skipped: "not running, so its host key cannot be read"},
	}
	if _, err := captureApply(t, res, "group", false); err != nil {
		t.Fatalf("önizleme hata döndü: %v", err)
	}
}

/*
 * ⚠️ DOĞRULANAMAYAN ANAHTAR, DOĞRULANMIŞ GİBİ GÖSTERİLMEMELİ.
 *
 * Kayıtlı bir hedefte tarama başarısız olduğunda grup bağı yine
 * yenileniyor (grant ağ istemiyor), ama anahtarın kontrol EDİLEMEDİĞİ
 * raporda yazmalı. "already registered" demek, kontrol edilmiş gibi
 * göstermek olurdu.
 */
func TestReportSaysWhenTheKeyWasNotRechecked(t *testing.T) {
	res := []discover.Outcome{
		{Machine: discover.Machine{Name: "lab-01"}, Group: "developer", Tagged: true,
			Existing: true, Granted: true,
			KeyUnchecked: "host key not re-checked (dial tcp: no route to host)"},
	}
	out, err := captureApply(t, res, "team", true)
	if err != nil {
		t.Fatalf("grant yapıldığı hâlde hata: %v", err)
	}
	if !strings.Contains(out, "not re-checked") {
		t.Errorf("anahtarın doğrulanmadığı söylenmiyor:\n%s", out)
	}
	if !strings.Contains(out, "group granted") {
		t.Errorf("grup bağının yenilendiği söylenmiyor:\n%s", out)
	}
}
