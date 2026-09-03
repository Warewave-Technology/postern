package main

import (
	"os"
	"strings"
	"testing"
)

/*
 * ⚠️ GÖNDERDİĞİMİZ SYSTEMD BİRİMİ, KENDİ YORUMUNUN TERSİNİ YAPIYORDU.
 *
 * StartLimitBurst / StartLimitIntervalSec [Service] altında yazılıydı.
 * systemd v229'dan beri bu sayaç UNIT'e ait: [Service] altında yazılan
 * anahtarları systemd tanımıyor ve sessizce yok sayıyor. Ölçüldü —
 * Debian 12'de (systemd 252) shipped dosya üzerinde
 * `systemd-analyze verify`:
 *
 *   Unknown key 'StartLimitIntervalSec' in section [Service], ignoring.
 *
 * Yani dosyanın "sonsuz yeniden başlatma YOK" yorumunun tersi
 * oluyordu: açılamayan bir bastion — kötü DSN, reddedilen bir
 * min_free, geride kalmış şema — 5 saniyede bir sonsuza kadar yeniden
 * deneniyor, `systemctl status` "failed" yerine "activating"
 * gösteriyor ve failed unit arayan bir izleyici hiçbir şey görmüyordu.
 *
 * Bu dosya sürüm arşivinin içinde gidiyor ve deploy/README.md
 * operatöre onu `install` ile kurmasını söylüyor; yani hata her
 * kuruluma taşınıyordu.
 *
 * Test systemd istemiyor: bölüm başlıklarını okuyup anahtarın hangi
 * bölümde olduğunu söylüyor. systemd-analyze'ın gördüğü şeyi
 * görmüyor ama BU arızayı bir daha geri gelemez yapıyor.
 */
func TestUnitPutsStartLimitWhereSystemdReadsIt(t *testing.T) {
	const path = "../../deploy/systemd/postern.service"
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("birim dosyası okunamadı: %v", err)
	}

	// systemd'nin YALNIZCA [Unit] altında tanıdığı anahtarlar.
	unitOnly := map[string]bool{
		"StartLimitBurst":       true,
		"StartLimitIntervalSec": true,
		"StartLimitAction":      true,
	}

	section := ""
	seen := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}
		key, _, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if unitOnly[key] {
			seen[key] = section
		}
	}

	if len(seen) == 0 {
		t.Fatal("birimde hiç StartLimit* anahtarı yok — sonsuz yeniden " +
			"başlatma sınırı kaldırılmış")
	}
	for key, sec := range seen {
		if sec != "Unit" {
			t.Errorf("%s [%s] bölümünde; systemd onu YALNIZCA [Unit] altında "+
				"tanıyor ve orada değilse sessizce yok sayıyor — birim "+
				"sonsuza kadar yeniden başlar, 'failed' demez", key, sec)
		}
	}
}
