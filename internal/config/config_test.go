package config

import (
	"testing"
	"time"
)

/*
 * ⚠️ İKİ AYARIN SIFIR DEĞERLERİ AYRI ANLAMLARA GELİYOR.
 *
 * retain boş = "hiç silme" (kanıt silmek varsayılan olamaz).
 * min_free boş = VARSAYILANI kullan; açıkça "0" = kapat. İkisi aynı
 * değere düşseydi, eşiği kapatmak isteyen operatörle hiçbir şey
 * yazmamış operatör ayırt edilemezdi.
 */
func TestRecordingRetentionDefaults(t *testing.T) {
	var r RecordingConfig

	// retain: boş ve "0" → hiçbir şey silinmiyor.
	for _, v := range []string{"", "0"} {
		r.Retain = v
		d, err := r.RetainDuration()
		if err != nil || d != 0 {
			t.Errorf("retain=%q -> %v %v; kanıt silmek varsayılan olamaz", v, d, err)
		}
	}
	r.Retain = "90d"
	if d, err := r.RetainDuration(); err != nil || d != 90*24*time.Hour {
		t.Errorf("retain=90d -> %v %v", d, err)
	}
	r.Retain = "2160h"
	if d, err := r.RetainDuration(); err != nil || d != 2160*time.Hour {
		t.Errorf("retain=2160h -> %v %v", d, err)
	}
	// ⚠️ Çözülemeyen değer HATA, sessizce varsayılana düşmüyor:
	// "90gun" yazan operatör diskinin neden dolduğunu anlamalı.
	for _, bad := range []string{"90gun", "doksan", "-5d", "abc"} {
		if _, err := (RecordingConfig{Retain: bad}).RetainDuration(); err == nil {
			t.Errorf("retain=%q kabul edildi", bad)
		}
	}

	// min_free: boş → VARSAYILAN, "0" → kapalı.
	if n, err := (RecordingConfig{}).MinFreeBytes(); err != nil || n != DefaultRecordingMinFree {
		t.Errorf("min_free boş -> %d %v, varsayılan bekleniyordu", n, err)
	}
	if n, err := (RecordingConfig{MinFree: "0"}).MinFreeBytes(); err != nil || n != 0 {
		t.Errorf("min_free=0 -> %d %v, kapalı bekleniyordu", n, err)
	}
	for in, want := range map[string]uint64{
		"2GiB":   2 << 30,
		"500MiB": 500 << 20,
		"1024":   1024,
	} {
		if n, err := (RecordingConfig{MinFree: in}).MinFreeBytes(); err != nil || n != want {
			t.Errorf("min_free=%q -> %d %v, %d bekleniyordu", in, n, err, want)
		}
	}
	for _, bad := range []string{"iki gib", "-1", "2GB!"} {
		if _, err := (RecordingConfig{MinFree: bad}).MinFreeBytes(); err == nil {
			t.Errorf("min_free=%q kabul edildi", bad)
		}
	}
}

/*
 * ⚠️ KOPYALANAN KOMUT YAPIŞTIRILDIĞINDA ÇALIŞMALI.
 *
 * Panel "ssh kullanıcı:hedef@bastion" komutunu kopyalatıyor. <bastion>
 * yerine dinleme adresini koymak dışarıda anlamsız bir şey verirdi
 * (":2222", "0.0.0.0:2222"); yer tutucu bırakmak ise komutu
 * yapıştırıldığı anda bozuk yapardı. Sıra: açık external_addr, yoksa
 * host http.external_url'den + port listen.addr'dan.
 */
func TestSSHEndpoint(t *testing.T) {
	cases := []struct {
		name     string
		listen   string
		external string
		httpURL  string
		wantHost string
		wantPort int
	}{
		{
			name:     "http dis adresinden turetiliyor",
			listen:   "127.0.0.1:2299",
			httpURL:  "http://127.0.0.1:56188",
			wantHost: "127.0.0.1",
			wantPort: 2299,
		},
		{
			// ⚠️ ":2222" dış dünyada bir şey ifade etmiyor; host yine
			// beyan edilmiş dış kimlikten geliyor.
			name:     "dinleme adresi portsuz host icermiyor",
			listen:   ":2222",
			httpURL:  "https://bastion.warewave.io",
			wantHost: "bastion.warewave.io",
			wantPort: 2222,
		},
		{
			name:     "acik external_addr her seyi ezer",
			listen:   "127.0.0.1:2299",
			external: "ssh.warewave.io:22",
			httpURL:  "https://panel.warewave.io",
			wantHost: "ssh.warewave.io",
			wantPort: 22,
		},
		{
			// Portsuz yazılmış dış adres: port dinlemeden tamamlanıyor.
			name:     "external_addr portsuz",
			listen:   "0.0.0.0:2222",
			external: "ssh.warewave.io",
			httpURL:  "https://panel.warewave.io",
			wantHost: "ssh.warewave.io",
			wantPort: 2222,
		},
		{
			/*
			 * ⚠️ ÇÖZÜLEMİYORSA BOŞ HOST. Panel bunu görünce kopyalama
			 * seçeneğini hiç göstermiyor — çalışmayacak bir komut
			 * vermektense hiç vermemek.
			 */
			name:     "hicbir dis kimlik yok",
			listen:   ":2222",
			wantHost: "",
			wantPort: 2222,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := Config{
				Listen: ListenConfig{Addr: c.listen, ExternalAddr: c.external},
				HTTP:   HTTPConfig{ExternalURL: c.httpURL},
			}
			host, port := cfg.SSHEndpoint()
			if host != c.wantHost || port != c.wantPort {
				t.Errorf("SSHEndpoint() = (%q, %d), beklenen (%q, %d)",
					host, port, c.wantHost, c.wantPort)
			}
		})
	}
}
