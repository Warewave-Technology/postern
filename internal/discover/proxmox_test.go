package discover

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakePVE, Proxmox API'sinin ihtiyacımız olan iki ucunu taklit eder.
func fakePVE(t *testing.T, sawAuth *string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/cluster/resources", func(w http.ResponseWriter, r *http.Request) {
		if sawAuth != nil {
			*sawAuth = r.Header.Get("Authorization")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[
			{"vmid":101,"name":"web-01","node":"n1","type":"qemu","status":"running","tags":"env=prod;role=ops"},
			{"vmid":102,"name":"db-01","node":"n2","type":"lxc","status":"running","tags":"role=dba"},
			{"vmid":103,"name":"kapali","node":"n1","type":"qemu","status":"stopped","tags":"role=ops"},
			{"vmid":104,"name":"","node":"n1","type":"qemu","status":"running","tags":""}
		]}`))
	})
	mux.HandleFunc("/api2/json/nodes/n1/qemu/101/agent/network-get-interfaces",
		func(w http.ResponseWriter, _ *http.Request) {
			// ⚠️ lo VE bağlantı-yerel adres de dönüyor: gerçek konuk
			// aracısı böyle davranıyor ve ikisi de elenmeli.
			_, _ = w.Write([]byte(`{"data":{"result":[
				{"name":"lo","ip-addresses":[{"ip-address":"127.0.0.1","ip-address-type":"ipv4"}]},
				{"name":"eth0","ip-addresses":[
					{"ip-address":"169.254.1.9","ip-address-type":"ipv4"},
					{"ip-address":"10.0.0.5","ip-address-type":"ipv4"}]}
			]}}`))
		})
	mux.HandleFunc("/api2/json/nodes/n2/lxc/102/interfaces",
		func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"data":[{"name":"eth0","inet":"10.0.0.6/24"}]}`))
		})

	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// caFileFor, test sunucusunun sertifikasını bir dosyaya yazar.
func caFileFor(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	cert := srv.Certificate()
	p := filepath.Join(t.TempDir(), "ca.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	// Sertifikanın gerçekten ayrıştığını doğrula.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		t.Fatal("test sertifikası yazılamadı")
	}
	return p
}

func TestProxmoxMachines(t *testing.T) {
	var auth string
	srv := fakePVE(t, &auth)

	p, err := NewProxmox(ProxmoxConfig{
		BaseURL: srv.URL, TokenID: "root@pam!kesif", TokenSecret: "s3cret",
		CAFile: caFileFor(t, srv),
	})
	if err != nil {
		t.Fatal(err)
	}

	ms, err := p.Machines(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// ⚠️ ADSIZ MAKİNE DÜŞÜYOR: hedef adı benzersiz olmak zorunda ve
	// vmid bir insan adı değil.
	if len(ms) != 3 {
		t.Fatalf("%d makine, 3 bekleniyordu: %+v", len(ms), ms)
	}

	by := map[string]Machine{}
	for _, m := range ms {
		by[m.Name] = m
	}

	// ⚠️ Konuk aracısının döngü ve bağlantı-yerel adresleri ELENDİ.
	if by["web-01"].Host != "10.0.0.5" {
		t.Errorf("qemu adresi = %q, 10.0.0.5 bekleniyordu", by["web-01"].Host)
	}
	if by["db-01"].Host != "10.0.0.6" {
		t.Errorf("lxc adresi = %q", by["db-01"].Host)
	}
	// Kapalı makine adres SORULMADAN geliyor ve öyle işaretli.
	if by["kapali"].Running || by["kapali"].Host != "" {
		t.Errorf("kapalı makine = %+v", by["kapali"])
	}

	if role, tagged := RoleFromTags(by["web-01"].Tags, "role"); role != "ops" || !tagged {
		t.Errorf("etiketten rol = %q %v", role, tagged)
	}

	// ⚠️ JETON BAŞLIĞI PROXMOX'UN BEKLEDİĞİ BİÇİMDE.
	if !strings.HasPrefix(auth, "PVEAPIToken=root@pam!kesif=") {
		t.Errorf("yetki başlığı = %q", auth)
	}
}

/*
 * ⚠️ DÜZ HTTP REDDEDİLİYOR.
 *
 * Jeton her istekte başlıkta gidiyor; şifresiz bir bağlantıda onu
 * okuyan kişi hipervizörün envanterini okuyabilir hâle gelir.
 */
func TestProxmoxRefusesPlainHTTP(t *testing.T) {
	_, err := NewProxmox(ProxmoxConfig{
		BaseURL: "http://pve.example:8006", TokenID: "a!b", TokenSecret: "c",
	})
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("düz http kabul edildi: %v", err)
	}
}

// Eksik jeton sessizce geçmiyor: kimliksiz bir istek 401 alır ve
// "hipervizöre ulaşılamıyor" gibi görünürdü.
func TestProxmoxRequiresToken(t *testing.T) {
	for _, c := range []ProxmoxConfig{
		{BaseURL: "https://pve", TokenSecret: "x"},
		{BaseURL: "https://pve", TokenID: "a!b"},
		{TokenID: "a!b", TokenSecret: "x"},
	} {
		if _, err := NewProxmox(c); err == nil {
			t.Errorf("eksik alanla kabul edildi: %+v", c)
		}
	}
}

/*
 * ⚠️ DOĞRULAMA VARSAYILAN OLARAK AÇIK.
 *
 * Kendi imzaladığı sertifikaya --ca-file ya da --insecure olmadan
 * bağlanmak BAŞARISIZ olmalı: sessizce kabul etmek, araya giren birine
 * hangi makinenin hangi role gideceğini yazdırırdı.
 */
func TestProxmoxVerifiesTLSByDefault(t *testing.T) {
	srv := fakePVE(t, nil)

	p, err := NewProxmox(ProxmoxConfig{
		BaseURL: srv.URL, TokenID: "a!b", TokenSecret: "c",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Machines(context.Background()); err == nil {
		t.Fatal("kendi imzaladığı sertifika doğrulanmadan kabul edildi")
	}

	// --insecure ile geçiyor (bilinçli ve komut satırında istenmiş).
	p2, err := NewProxmox(ProxmoxConfig{
		BaseURL: srv.URL, TokenID: "a!b", TokenSecret: "c", Insecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p2.Machines(context.Background()); err != nil {
		t.Fatalf("--insecure ile de bağlanamadı: %v", err)
	}
	_ = tls.VersionTLS12
}

// Düğüm süzgeci: yalnızca istenen düğümün makineleri.
func TestProxmoxNodeFilter(t *testing.T) {
	srv := fakePVE(t, nil)
	p, err := NewProxmox(ProxmoxConfig{
		BaseURL: srv.URL, TokenID: "a!b", TokenSecret: "c",
		CAFile: caFileFor(t, srv), Node: "n2",
	})
	if err != nil {
		t.Fatal(err)
	}
	ms, err := p.Machines(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].Name != "db-01" {
		t.Fatalf("düğüm süzgeci çalışmadı: %+v", ms)
	}
}
