package discover

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

/*
 * Proxmox VE kaynağı.
 *
 * ⚠️ YALNIZCA OKUYOR. Kullanılan uçların hepsi GET ve hiçbiri makineyi
 * değiştirmiyor. Keşif, hipervizöre yazma yetkisi olan bir jetonla
 * çalıştırılmamalı ve bunu README'ye yazmak yerine gerçekten
 * kullanmamak daha iyi: buradaki kod bir PUT/POST içermiyor.
 */

// ProxmoxConfig, Proxmox'a bağlanmak için gerekenler.
type ProxmoxConfig struct {
	// BaseURL, "https://pve.example:8006" biçiminde.
	BaseURL string

	/*
	 * TokenID ve TokenSecret, API jetonu ("user@pam!keşif").
	 *
	 * ⚠️ PAROLA/TICKET YOLU BİLEREK YOK. Jeton kapsamı daraltılabiliyor
	 * ve iptali tek tıklık; kullanıcı parolası ise hipervizörün tamamına
	 * açılan bir anahtar. postern'in kendi kapısında verdiği kararın
	 * aynısı: makine işi için makine kimliği.
	 */
	TokenID     string
	TokenSecret string

	// CAFile, hipervizörün sertifikasını doğrulayacak kök. Boşsa
	// sistemin kök deposu.
	CAFile string

	/*
	 * Insecure, TLS doğrulamasını KAPATIR.
	 *
	 * ⚠️ VARSAYILAN DEĞİL VE OLMAYACAK. Proxmox kurulumlarının çoğu
	 * kendi imzaladığı sertifikayla geliyor, dolayısıyla bunu tamamen
	 * yasaklamak özelliği kullanılamaz yapardı. Ama açık olduğunda
	 * araya giren biri hipervizörün cevabını — yani hangi makinenin
	 * hangi role gideceğini — yazabilir. Bu yüzden açan kişi bunu
	 * komut satırında yazmak zorunda ve denetim kaydına düşüyor.
	 * Doğru yol CAFile.
	 */
	Insecure bool

	// Node boşsa küme genelinde arıyor.
	Node string

	Timeout time.Duration
}

// Proxmox, ProxmoxConfig ile konuşan Source.
type Proxmox struct {
	cfg    ProxmoxConfig
	client *http.Client
	base   *url.URL
}

// NewProxmox, yapılandırmayı doğrular ve istemciyi kurar.
func NewProxmox(cfg ProxmoxConfig) (*Proxmox, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, errors.New("discover: proxmox url is required")
	}
	u, err := url.Parse(strings.TrimRight(cfg.BaseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("discover: proxmox url: %w", err)
	}
	if u.Scheme != "https" {
		/*
		 * ⚠️ DÜZ HTTP KABUL EDİLMİYOR. Jeton her istekte başlıkta
		 * gidiyor; şifresiz bir bağlantıda onu okuyan kişi hipervizörün
		 * envanterini okuyabilir hâle gelir. Proxmox zaten HTTPS
		 * konuşuyor, dolayısıyla bunu esnetmenin bir kullanım gerekçesi
		 * de yok.
		 */
		return nil, errors.New("discover: proxmox url must be https://")
	}
	if strings.TrimSpace(cfg.TokenID) == "" || strings.TrimSpace(cfg.TokenSecret) == "" {
		return nil, errors.New("discover: proxmox api token id and secret are required")
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case cfg.CAFile != "":
		pem, rerr := os.ReadFile(cfg.CAFile)
		if rerr != nil {
			return nil, fmt.Errorf("discover: proxmox ca file: %w", rerr)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("discover: proxmox ca file %s: no certificate found", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	case cfg.Insecure:
		// #nosec G402 -- bilinçli ve komut satırında açıkça istenmiş;
		// gerekçesi ProxmoxConfig.Insecure'da yazılı.
		tlsCfg.InsecureSkipVerify = true
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	return &Proxmox{
		cfg:  cfg,
		base: u,
		client: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

// Name, Source arayüzü.
func (p *Proxmox) Name() string { return "proxmox" }

// get, API'den JSON okur ve `data` alanını hedefe çözer.
func (p *Proxmox) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.base.String()+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization",
		fmt.Sprintf("PVEAPIToken=%s=%s", p.cfg.TokenID, p.cfg.TokenSecret))

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		/*
		 * ⚠️ GÖVDE HATAYA KONMUYOR. Proxmox yetki hatalarında jetonun
		 * kimliğini cevaba yazabiliyor; onu hata metnine koymak,
		 * günlüğe ve kabuğun geçmişine düşürmek olurdu. Durum kodu
		 * teşhis için yeterli, 401/403 ayrımı zaten anlamlı.
		 */
		return fmt.Errorf("proxmox %s: http %d", path, resp.StatusCode)
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("proxmox %s: %w", path, err)
	}
	if len(envelope.Data) == 0 {
		return nil
	}
	return json.Unmarshal(envelope.Data, out)
}

// Machines, kümedeki sanal makineleri ve konteynerleri döner.
func (p *Proxmox) Machines(ctx context.Context) ([]Machine, error) {
	var rows []struct {
		VMID   int    `json:"vmid"`
		Name   string `json:"name"`
		Node   string `json:"node"`
		Type   string `json:"type"`
		Status string `json:"status"`
		Tags   string `json:"tags"`
	}
	if err := p.get(ctx, "/api2/json/cluster/resources?type=vm", &rows); err != nil {
		return nil, err
	}

	out := make([]Machine, 0, len(rows))
	for _, r := range rows {
		if p.cfg.Node != "" && r.Node != p.cfg.Node {
			continue
		}
		if r.Name == "" {
			// Adsız makineyi hedefe çeviremeyiz: hedef adı benzersiz
			// olmak zorunda ve vmid bir insan adı değil.
			continue
		}
		m := Machine{
			Name:    r.Name,
			Tags:    splitTags(r.Tags),
			Running: r.Status == "running",
			Ref:     fmt.Sprintf("%s/%d@%s", r.Type, r.VMID, r.Node),
		}
		if m.Running {
			m.Host = p.address(ctx, r.Node, r.Type, r.VMID)
		}
		out = append(out, m)
	}
	return out, nil
}

/*
 * splitTags, Proxmox'un etiket dizesini ayırır.
 *
 * ⚠️ ÜÇ AYRAÇ. Proxmox sürümüne ve arayüze göre noktalı virgül, virgül
 * ya da boşluk görülebiliyor. Tek ayraç varsaymak, kurulumun
 * etiketlerini sessizce TEK bir etiket gibi okuyup her makineyi
 * `unknown`a düşürürdü — hiçbir hata vermeden.
 */
func splitTags(s string) []string {
	f := strings.FieldsFunc(s, func(r rune) bool {
		return r == ';' || r == ',' || r == ' '
	})
	out := make([]string, 0, len(f))
	for _, t := range f {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

/*
 * address, konuk aracısından IP öğrenmeye çalışır.
 *
 * ⚠️ BAŞARISIZLIK SESSİZ VE KASITLI. Konuk aracısı çoğu kurulumda her
 * makinede yok; olmadığında makine ADIYLA denenecek (çağıran öyle
 * yapıyor). Buradaki hatayı yukarı taşımak, aracısı olmayan tek bir
 * makine yüzünden bütün keşfi düşürürdü.
 *
 * Yerel bağlantı adresleri ve döngü adresi atlanıyor: bastion'dan
 * çözülmüyorlar ve yazılırlarsa hedef "bağlanamıyor" diye kalır.
 */
func (p *Proxmox) address(ctx context.Context, node, kind string, vmid int) string {
	type iface struct {
		Name string `json:"name"`
		IPs  []struct {
			Address string `json:"ip-address"`
			Type    string `json:"ip-address-type"`
		} `json:"ip-addresses"`
	}

	var ifaces []iface
	switch kind {
	case "qemu":
		var wrap struct {
			Result []iface `json:"result"`
		}
		path := fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/agent/network-get-interfaces", node, vmid)
		if err := p.get(ctx, path, &wrap); err != nil {
			return ""
		}
		ifaces = wrap.Result
	case "lxc":
		path := fmt.Sprintf("/api2/json/nodes/%s/lxc/%d/interfaces", node, vmid)
		var rows []struct {
			Name string `json:"name"`
			Inet string `json:"inet"`
		}
		if err := p.get(ctx, path, &rows); err != nil {
			return ""
		}
		for _, r := range rows {
			if ip := usableIP(strings.SplitN(r.Inet, "/", 2)[0]); ip != "" {
				return ip
			}
		}
		return ""
	default:
		return ""
	}

	for _, i := range ifaces {
		if i.Name == "lo" {
			continue
		}
		for _, a := range i.IPs {
			if ip := usableIP(a.Address); ip != "" {
				return ip
			}
		}
	}
	return ""
}

// usableIP, bastion'dan gerçekten denenebilecek bir adres mi.
func usableIP(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return ""
	}
	return ip.String()
}
