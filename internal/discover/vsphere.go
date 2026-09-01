package discover

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

/*
 * vSphere (vCenter) kaynağı.
 *
 * ⚠️ govmomi EKLENMEDİ, REST API elle konuşuluyor.
 *
 * VMware'in resmî Go SDK'sı doğru ve kapsamlı, ama bu iş için
 * gereğinden çok büyük: keşfin ihtiyacı dört uç ve hepsi JSON. Bu
 * repoda yeni bir bağımlılık bilinçli bir karar (Makefile'daki nota
 * bakın) ve buradaki kazanç, Proxmox istemcisiyle AYNI şekli
 * korumak — iki kaynak yan yana okunabiliyor ve ikisi de aynı
 * güvenlik kararlarını veriyor.
 *
 * Bedeli: vCenter 7.0U2 ve sonrasının /api yolları varsayılıyor. Daha
 * eski sürümlerin /rest yolları farklı ve DESTEKLENMİYOR — sessizce
 * yanlış davranmak yerine bağlanırken düşüyor.
 *
 * ⚠️ ETİKET MODELİ TAM OTURUYOR. vSphere'de etiket gerçekten
 * anahtar/değer: KATEGORİ anahtar, ETİKET değer. Proxmox'ta anahtarı
 * etiketin içinde aramak zorundaydık; burada platformun kendi modeli.
 * Yine de aynı biçimde ("kategori=etiket") dışarı veriliyor ki
 * RoleFromTags tek bir kural uygulasın — iki kaynak için iki ayrı rol
 * çıkarma mantığı, ikisinin zamanla ayrışması demekti.
 */

// VSphereConfig, vCenter'a bağlanmak için gerekenler.
type VSphereConfig struct {
	// BaseURL, "https://vcenter.example" biçiminde.
	BaseURL string

	/*
	 * Username ve Password.
	 *
	 * ⚠️ PROXMOX'TAN FARKLI OLARAK JETON YOK ve bu bir tercih değil:
	 * vCenter'ın API jetonu diye ayrı bir kavramı yok, oturum kullanıcı
	 * kimliğiyle açılıyor. Karşılığında kullanılacak hesabın
	 * YALNIZCA OKUMA yetkisi olmalı — bu koddaki hiçbir çağrı
	 * değiştirmiyor, ama yetkiyi daraltmak koda değil operatöre bağlı.
	 */
	Username string
	Password string

	CAFile string
	// Insecure, TLS doğrulamasını kapatır. Gerekçesi ProxmoxConfig'te.
	Insecure bool

	Timeout time.Duration
}

// VSphere, VSphereConfig ile konuşan Source.
type VSphere struct {
	cfg    VSphereConfig
	client *http.Client
	base   string

	mu      sync.Mutex
	session string
}

// NewVSphere, yapılandırmayı doğrular ve istemciyi kurar.
func NewVSphere(cfg VSphereConfig) (*VSphere, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, errors.New("discover: vsphere url is required")
	}
	u, err := url.Parse(strings.TrimRight(cfg.BaseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("discover: vsphere url: %w", err)
	}
	if u.Scheme != "https" {
		// Oturum kimliği her istekte başlıkta gidiyor; şifresiz bir
		// bağlantıda onu okuyan kişi vCenter oturumunu devralır.
		return nil, errors.New("discover: vsphere url must be https://")
	}
	if strings.TrimSpace(cfg.Username) == "" || cfg.Password == "" {
		return nil, errors.New("discover: vsphere username and password are required")
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case cfg.CAFile != "":
		pem, rerr := os.ReadFile(cfg.CAFile)
		if rerr != nil {
			return nil, fmt.Errorf("discover: vsphere ca file: %w", rerr)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("discover: vsphere ca file %s: no certificate found", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	case cfg.Insecure:
		// #nosec G402 -- bilinçli ve komut satırında açıkça istenmiş
		tlsCfg.InsecureSkipVerify = true
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &VSphere{
		cfg:  cfg,
		base: u.String(),
		client: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

// Name, Source arayüzü.
func (v *VSphere) Name() string { return "vsphere" }

/*
 * login, oturum açar ve kimliği saklar.
 *
 * ⚠️ OTURUM BİR KEZ AÇILIYOR ve keşif bitince KAPATILIYOR (Close).
 * vCenter oturumları kendiliğinden zaman aşımına uğruyor ama her
 * koşuda bir tane bırakmak, sunucuda birikip yönetici konsolunu
 * kirletir — ve orada duran her oturum, süresi dolana kadar
 * kullanılabilir bir kimliktir.
 */
func (v *VSphere) login(ctx context.Context) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.session != "" {
		return v.session, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.base+"/api/session", nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(v.cfg.Username, v.cfg.Password)

	resp, err := v.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return "", errors.New("vsphere: /api/session not found — " +
				"this needs vCenter 7.0 U2 or newer")
		}
		// Gövde yazılmıyor: vCenter hata cevaplarına kullanıcı adını
		// koyabiliyor ve onu günlüğe düşürmek istemiyoruz.
		return "", fmt.Errorf("vsphere: session: http %d", resp.StatusCode)
	}

	var id string
	if err := json.NewDecoder(resp.Body).Decode(&id); err != nil {
		return "", fmt.Errorf("vsphere: session: %w", err)
	}
	if id == "" {
		return "", errors.New("vsphere: session: empty session id")
	}
	v.session = id
	return id, nil
}

// Close, vCenter oturumunu kapatır.
func (v *VSphere) Close(ctx context.Context) {
	v.mu.Lock()
	id := v.session
	v.session = ""
	v.mu.Unlock()
	if id == "" {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, v.base+"/api/session", nil)
	if err != nil {
		return
	}
	req.Header.Set("vmware-api-session-id", id)
	if resp, derr := v.client.Do(req); derr == nil {
		resp.Body.Close()
	}
}

// call, oturumlu bir istek atar ve cevabı çözer.
func (v *VSphere) call(ctx context.Context, method, path string, body, out any) error {
	id, err := v.login(ctx)
	if err != nil {
		return err
	}

	var rdr *bytes.Reader
	if body != nil {
		raw, merr := json.Marshal(body)
		if merr != nil {
			return merr
		}
		rdr = bytes.NewReader(raw)
	}
	var req *http.Request
	if rdr != nil {
		req, err = http.NewRequestWithContext(ctx, method, v.base+path, rdr)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, v.base+path, nil)
	}
	if err != nil {
		return err
	}
	req.Header.Set("vmware-api-session-id", id)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("vsphere %s: http %d", path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Machines, vCenter'daki sanal makineleri döner.
func (v *VSphere) Machines(ctx context.Context) ([]Machine, error) {
	defer v.Close(ctx)

	var vms []struct {
		VM         string `json:"vm"`
		Name       string `json:"name"`
		PowerState string `json:"power_state"`
	}
	if err := v.call(ctx, http.MethodGet, "/api/vcenter/vm", nil, &vms); err != nil {
		return nil, err
	}

	tags, terr := v.tagsByVM(ctx, vms)
	if terr != nil {
		/*
		 * ⚠️ ETİKET OKUNAMAZSA KEŞİF DÜŞMÜYOR.
		 *
		 * Etiketleme servisi ayrı bir yetki istiyor ve okuma yetkisi
		 * dar tutulmuş bir hesapta kapalı olabiliyor. Bütün keşfi
		 * düşürmek yerine makineler `unknown` rolüne gidiyor — ve
		 * sebep çağırana bildiriliyor, sessizce "hiç etiket yok"
		 * denmiyor.
		 */
		return nil, fmt.Errorf("vsphere: could not read tags (the account may lack "+
			"the tagging read privilege): %w", terr)
	}

	out := make([]Machine, 0, len(vms))
	for _, m := range vms {
		if m.Name == "" {
			continue
		}
		mm := Machine{
			Name:    m.Name,
			Tags:    tags[m.VM],
			Running: m.PowerState == "POWERED_ON",
			Ref:     "vsphere/" + m.VM,
		}
		if mm.Running {
			mm.Host = v.address(ctx, m.VM)
		}
		out = append(out, mm)
	}
	return out, nil
}

/*
 * tagsByVM, her makinenin etiketlerini "kategori=etiket" biçiminde
 * toplar.
 *
 * ⚠️ ÜÇ ÇAĞRI, MAKİNE BAŞINA DEĞİL. Etiketleri makine başına sormak
 * bin makinelik bir vCenter'da bin istek demekti;
 * list-attached-tags-on-objects hepsini tek turda veriyor.
 */
func (v *VSphere) tagsByVM(ctx context.Context, vms []struct {
	VM         string `json:"vm"`
	Name       string `json:"name"`
	PowerState string `json:"power_state"`
}) (map[string][]string, error) {
	out := map[string][]string{}
	if len(vms) == 0 {
		return out, nil
	}

	// 1) Etiket kimliği → (kategori kimliği, etiket adı)
	var tagIDs []string
	if err := v.call(ctx, http.MethodGet, "/api/cis/tagging/tag", nil, &tagIDs); err != nil {
		return nil, err
	}
	type tagInfo struct {
		Name       string `json:"name"`
		CategoryID string `json:"category_id"`
	}
	tagByID := make(map[string]tagInfo, len(tagIDs))
	cats := map[string]string{}
	for _, id := range tagIDs {
		var ti tagInfo
		if err := v.call(ctx, http.MethodGet,
			"/api/cis/tagging/tag/"+url.PathEscape(id), nil, &ti); err != nil {
			continue
		}
		tagByID[id] = ti
		if _, ok := cats[ti.CategoryID]; !ok {
			var ci struct {
				Name string `json:"name"`
			}
			if err := v.call(ctx, http.MethodGet,
				"/api/cis/tagging/category/"+url.PathEscape(ti.CategoryID), nil, &ci); err == nil {
				cats[ti.CategoryID] = ci.Name
			}
		}
	}

	// 2) Hangi makinede hangi etiketler var.
	objects := make([]map[string]string, 0, len(vms))
	for _, m := range vms {
		objects = append(objects, map[string]string{"id": m.VM, "type": "VirtualMachine"})
	}
	var assoc []struct {
		ObjectID struct {
			ID string `json:"id"`
		} `json:"object_id"`
		TagIDs []string `json:"tag_ids"`
	}
	if err := v.call(ctx, http.MethodPost,
		"/api/cis/tagging/tag-association?action=list-attached-tags-on-objects",
		map[string]any{"object_ids": objects}, &assoc); err != nil {
		return nil, err
	}

	for _, a := range assoc {
		for _, id := range a.TagIDs {
			ti, ok := tagByID[id]
			if !ok {
				continue
			}
			// ⚠️ "kategori=etiket": Proxmox'la AYNI biçim, dolayısıyla
			// rol çıkarma mantığı tek ve ortak.
			cat := cats[ti.CategoryID]
			if cat == "" {
				continue
			}
			out[a.ObjectID.ID] = append(out[a.ObjectID.ID], cat+"="+ti.Name)
		}
	}
	return out, nil
}

/*
 * address, VMware Tools'un bildirdiği adresi alır.
 *
 * Proxmox'taki konuk aracısının karşılığı ve aynı kural: yoksa sessizce
 * boş dönüyor, çağıran makine ADINA düşüyor. Kullanılamaz adresler
 * (döngü, bağlantı-yerel) aynı süzgeçten geçiyor.
 */
func (v *VSphere) address(ctx context.Context, vm string) string {
	var id struct {
		IPAddress string `json:"ip_address"`
	}
	path := "/api/vcenter/vm/" + url.PathEscape(vm) + "/guest/identity"
	if err := v.call(ctx, http.MethodGet, path, nil, &id); err != nil {
		return ""
	}
	return usableIP(id.IPAddress)
}
