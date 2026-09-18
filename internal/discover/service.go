package discover

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/sshalg"
	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/upstream"
)

/*
 * Service, panelden kaydedilen keşif kaynaklarını koşturur: zamanlayıcıyla
 * ya da elle, her koşu bir satır bırakarak.
 *
 * ⚠️ KOŞU HEDEF YAZMIYOR, ROL BAĞLAMIYOR. CLI'daki `--apply` bunu yapıyor,
 * çünkü orada önizlemeyi bir insan okuyup onaylıyor. Zamanlayıcının okuru
 * yok: Proxmox'ta `role_prod` etiketiyle VM açabilen biri, o group bağlı
 * insanların girebileceği bir makine yaratmış olurdu — sanallaştırma
 * platformu üzerinden yetki yükseltme. Koşu bulduğunu discovered_machines'e
 * yazıyor; makine hedef ancak bir yönetici Register dediğinde oluyor.
 * Otomasyon envanteri büyütebilir, insanların erişebildiği makineleri
 * genişletemez.
 */
type Service struct {
	db     *store.Store
	logger *slog.Logger

	// open ve scan testte değiştiriliyor: koşunun kararları gerçek bir
	// hipervizör ve gerçek bir sshd olmadan sınanabilsin.
	open func(store.DiscoverySource, string) (Source, error)
	scan func(ctx context.Context, host string, port int) (ssh.PublicKey, error)
	now  func() time.Time

	mu      sync.Mutex
	running map[string]bool
	base    context.Context
}

// Kaynak türleri.
const (
	KindProxmox = "proxmox"
	KindVSphere = "vsphere"
)

const (
	// MinInterval: bundan sık koşu hipervizörün API'sini ve her makinenin
	// sshd'sini boşuna yoruyor; envanter o hızda değişmiyor.
	MinInterval = 5 * time.Minute
	MaxInterval = 7 * 24 * time.Hour

	scanWorkers = 8
	listTimeout = 2 * time.Minute
)

// ErrRunning: kaynağın bir koşusu zaten sürüyor.
var ErrRunning = errors.New("discover: a run of this source is already in progress")

// Opener, kayıtlı kaynağı ve açılmış sırrını bir Source'a çevirir.
type Opener func(store.DiscoverySource, string) (Source, error)

// NewService kurar; open nil ise gerçek Proxmox/vSphere istemcileri
// (OpenSource). Host anahtarı taraması her zaman gerçek.
func NewService(db *store.Store, logger *slog.Logger, open Opener) *Service {
	if open == nil {
		open = OpenSource
	}
	return &Service{
		db: db, logger: logger,
		open: open, scan: upstream.ScanHostKey, now: time.Now,
		running: map[string]bool{},
	}
}

const (
	probeTimeout = 30 * time.Second
	probeSample  = 8
)

// Probe, "Test connection"ın cevabı: platformun ne bildirdiği.
type Probe struct {
	Machines    int `json:"machines"`
	Running     int `json:"running"`
	WithAddress int `json:"with_address"`
	// Matching, ad kalıbına uyan makine sayısı (kalıp boşsa hepsi).
	Matching int `json:"matching"`
	// Tagged, etiket anahtarını taşıyan makine sayısı; Groups onlardan
	// çıkan grup adlarının örneği, Tags görülen etiketlerin örneği.
	Tagged int      `json:"tagged"`
	Groups []string `json:"groups"`
	Tags   []string `json:"tags"`
	TookMS int64    `json:"took_ms"`
}

/*
 * Probe, formdaki değerlerle kaynağa bağlanıp makineleri sayar.
 *
 * ⚠️ HİÇBİR ŞEY YAZMIYOR — ne kaynak, ne makine satırı, ne koşu. Amaç
 * kaydetmeden önce adresin, sırrın ve ETİKET ANAHTARININ doğru olduğunu
 * görmek. CLI'da ölçülen arıza burada da geçerli: yanlış anahtar hata
 * vermiyor, her makineyi sessizce etiketsiz bırakıyor. "0 makine etiketli,
 * görülen etiketler şunlar" cümlesi bunu kaydetmeden önce söylüyor.
 */
func (s *Service) Probe(ctx context.Context, src store.DiscoverySource, secret string) (Probe, error) {
	source, err := s.open(src, secret)
	if err != nil {
		return Probe{}, err
	}
	start := time.Now()
	lctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	listed, err := source.Machines(lctx)
	if err != nil {
		return Probe{}, fmt.Errorf("%s: %w", src.Kind, err)
	}
	p := Probe{Groups: []string{}, Tags: []string{}}
	seenGroup, seenTag := map[string]bool{}, map[string]bool{}
	for _, m := range listed {
		p.Machines++
		if m.Running {
			p.Running++
		}
		if strings.TrimSpace(m.Host) != "" {
			p.WithAddress++
		}
		if matchesPattern(src.NamePattern, m.Name) {
			p.Matching++
		}
		if group, tagged := GroupFromTags(m.Tags, src.TagKey); tagged {
			p.Tagged++
			if !seenGroup[group] && len(p.Groups) < probeSample {
				seenGroup[group] = true
				p.Groups = append(p.Groups, group)
			}
		}
		for _, t := range m.Tags {
			if t = strings.TrimSpace(t); t != "" && !seenTag[t] && len(p.Tags) < probeSample {
				seenTag[t] = true
				p.Tags = append(p.Tags, t)
			}
		}
	}
	p.TookMS = time.Since(start).Milliseconds()
	return p, nil
}

// OpenSource, kayıtlı kaynağı ve açılmış sırrını bir Source'a çevirir.
func OpenSource(src store.DiscoverySource, secret string) (Source, error) {
	switch src.Kind {
	case KindProxmox:
		p, err := NewProxmox(ProxmoxConfig{
			BaseURL: src.URL, TokenID: src.Username, TokenSecret: secret,
			CAPEM: src.CAPEM, Insecure: src.Insecure, Node: src.Node,
		})
		if err != nil {
			return nil, err
		}
		return p, nil
	case KindVSphere:
		v, err := NewVSphere(VSphereConfig{
			BaseURL: src.URL, Username: src.Username, Password: secret,
			CAPEM: src.CAPEM, Insecure: src.Insecure,
		})
		if err != nil {
			return nil, err
		}
		return v, nil
	}
	return nil, fmt.Errorf("discover: unknown source kind %q", src.Kind)
}

/*
 * ValidateSource, kaynağı yazmadan önce denetler. creating=false iken
 * boş sır "değişmedi" demek.
 *
 * ⚠️ HEM CA HEM "DOĞRULAMA" OLMAZ. İkisi birden işaretliyse hangisinin
 * geçerli olduğu kodun sırasına kalırdı; operatör sertifikayı yapıştırıp
 * doğrulamanın açık olduğunu sanarken kapalı olabilirdi.
 */
func ValidateSource(src store.DiscoverySource, secret string, creating bool) error {
	name := strings.TrimSpace(src.Name)
	if name == "" || len(name) > 64 {
		return errors.New("name is required and at most 64 characters")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return errors.New("name contains a control character")
		}
	}
	secretName, userName := "token secret", "token id"
	switch src.Kind {
	case KindProxmox:
	case KindVSphere:
		secretName, userName = "password", "user name"
	default:
		return fmt.Errorf("kind must be %s or %s", KindProxmox, KindVSphere)
	}
	if u, err := url.Parse(strings.TrimSpace(src.URL)); err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("address must be an https:// URL")
	}
	if strings.TrimSpace(src.Username) == "" {
		return fmt.Errorf("%s is required", userName)
	}
	if creating && secret == "" {
		return fmt.Errorf("%s is required", secretName)
	}
	if key := strings.TrimSpace(src.TagKey); key == "" || strings.ContainsAny(key, " \t") {
		return errors.New("tag key is required and cannot contain spaces")
	}
	for _, p := range strings.Split(src.NamePattern, ",") {
		if _, err := path.Match(strings.TrimSpace(p), "probe"); err != nil {
			return fmt.Errorf("name pattern %q is not a valid pattern", strings.TrimSpace(p))
		}
	}
	if src.Port < 1 || src.Port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	if src.IntervalSeconds != 0 {
		d := time.Duration(src.IntervalSeconds) * time.Second
		if d < MinInterval || d > MaxInterval {
			return fmt.Errorf("schedule must be off or between %s and %s", MinInterval, MaxInterval)
		}
	}
	if strings.TrimSpace(src.CAPEM) != "" {
		if src.Insecure {
			return errors.New("give either a CA certificate or skip verification, not both")
		}
		if !x509.NewCertPool().AppendCertsFromPEM([]byte(src.CAPEM)) {
			return errors.New("the CA certificate is not a PEM certificate")
		}
	}
	return nil
}

/*
 * ValidTargetName, platformun verdiği adın hedef adı olabilmesi.
 *
 * ⚠️ AD GÜVENİLMEYEN GİRDİ ve SSH kullanıcı adının parçası oluyor
 * (`kişi:hedef`). vCenter'da "Web Server 01" ya da iki nokta taşıyan bir
 * ad yazılabiliyor; öyle bir hedef ya bağlanılamaz ya da ayrıştırıcıya
 * başka bir şey söyler. Rol adıyla aynı dar küme, biraz daha uzun.
 */
func ValidTargetName(name string) error {
	if name == "" {
		return errors.New("name is empty")
	}
	if len(name) > 128 {
		return errors.New("name is longer than 128 characters")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf("name contains %q; letters, digits, - _ . only", r)
		}
	}
	return nil
}

// Fingerprint, authorized_keys biçimindeki anahtarın SHA256 parmak izi;
// okunamıyorsa boş.
func Fingerprint(authorized string) string { return fingerprint(authorized) }

// matchesPattern, adın virgülle ayrılmış kalıplardan birine uyması; kalıp
// yoksa her ad uyuyor. Büyük-küçük harf duyarsız.
func matchesPattern(patterns, name string) bool {
	if strings.TrimSpace(patterns) == "" {
		return true
	}
	for _, p := range strings.Split(patterns, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if ok, _ := path.Match(p, strings.ToLower(name)); ok {
			return true
		}
	}
	return false
}

// address, taranacak adres: platformun bildirdiği ya da makinenin adı.
func address(m Machine) string {
	if h := strings.TrimSpace(m.Host); h != "" {
		return h
	}
	return m.Name
}

func (s *Service) claim(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running[id] {
		return false
	}
	s.running[id] = true
	return true
}

func (s *Service) release(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.running, id)
}

// Running, kaynağın bir koşusu bu süreçte sürüyor mu.
func (s *Service) Running(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running[id]
}

func (s *Service) baseContext() context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.base != nil {
		return s.base
	}
	return context.Background()
}

// Run, kaynağı bu goroutine'de koşturur ve koşunun satırını döner.
func (s *Service) Run(ctx context.Context, sourceID, trigger, actor string) (store.DiscoveryRun, error) {
	src, err := s.db.DiscoverySource(ctx, sourceID)
	if err != nil {
		return store.DiscoveryRun{}, err
	}
	if !s.claim(src.ID) {
		return store.DiscoveryRun{}, ErrRunning
	}
	defer s.release(src.ID)
	return s.run(ctx, src, trigger, actor)
}

/*
 * RunNow, kaynağı arka planda koşturur (panelin "Run now" düğmesi).
 *
 * ⚠️ İSTEĞİN BAĞLAMINDA DEĞİL. Yüz makinenin anahtarını taramak bir
 * dakikayı geçebiliyor; istek bağlamına bağlı bir koşu, sekmesini kapatan
 * yöneticiyle birlikte yarıda kesilir ve yarım bir rapor bırakırdı.
 */
func (s *Service) RunNow(ctx context.Context, sourceID, actor string) error {
	src, err := s.db.DiscoverySource(ctx, sourceID)
	if err != nil {
		return err
	}
	if !s.claim(src.ID) {
		return ErrRunning
	}
	if err := s.db.TouchDiscoverySource(ctx, src.ID, s.now()); err != nil {
		s.release(src.ID)
		return err
	}
	go func() {
		defer s.release(src.ID)
		if _, err := s.run(s.baseContext(), src, "web", actor); err != nil {
			s.logger.Warn("discovery run failed", "source", src.Name, "error", err)
		}
	}()
	return nil
}

// Loop, zamanı gelen kaynakları dakikada bir koşturur; ctx bitene kadar.
func (s *Service) Loop(ctx context.Context) {
	s.mu.Lock()
	s.base = ctx
	s.mu.Unlock()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Tick(ctx)
		}
	}
}

// Tick, zamanı gelmiş etkin kaynakları sırayla koşturur.
func (s *Service) Tick(ctx context.Context) {
	sources, err := s.db.DiscoverySources(ctx)
	if err != nil {
		s.logger.Error("discovery sources could not be read", "error", err)
		return
	}
	for _, src := range sources {
		interval := time.Duration(src.IntervalSeconds) * time.Second
		if !src.Enabled || interval <= 0 {
			continue
		}
		now := s.now()
		if !src.LastRunAt.IsZero() && now.Sub(src.LastRunAt) < interval {
			continue
		}
		claimed, err := s.db.ClaimDiscoverySource(ctx, src.ID, now, now.Add(-interval))
		if err != nil || !claimed || !s.claim(src.ID) {
			continue
		}
		_, rerr := s.run(ctx, src, "timer", "system")
		s.release(src.ID)
		if rerr != nil {
			s.logger.Warn("discovery run failed", "source", src.Name, "error", rerr)
		}
	}
}

// run, koşu satırını açar, koşuyu yapar ve satırı HER HÂLÜKÂRDA kapatır:
// yarıda kalan bir koşunun sebebi, olmayan bir koşudan daha değerli.
func (s *Service) run(ctx context.Context, src store.DiscoverySource, trigger, actor string) (store.DiscoveryRun, error) {
	rep := store.DiscoveryRun{
		SourceID: src.ID, Trigger: trigger, Actor: actor,
		StartedAt: s.now(), Outcome: store.DiscoveryOK,
	}
	id, err := s.db.StartDiscoveryRun(ctx, rep)
	if err != nil {
		return rep, err
	}
	rep.ID = id

	runErr := s.collect(ctx, src, &rep)
	if runErr != nil {
		rep.Outcome = store.DiscoveryFailed
		rep.Reason = runErr.Error()
	}
	rep.FinishedAt = s.now()

	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if ferr := s.db.FinishDiscoveryRun(fctx, rep); ferr != nil {
		s.logger.Error("discovery run bookkeeping failed", "source", src.Name, "run", id, "error", ferr)
	}
	return rep, runErr
}

type scanResult struct {
	key   ssh.PublicKey
	err   error
	tried bool
}

/*
 * collect, kaynağın makinelerini okuyup satırlara yazar.
 *
 * Üç değişmez burada:
 *   - Kimlik (kaynak, platform anahtarı); ad değil (bkz. Machine.Key).
 *   - Değişen host anahtarı bir BULGU: hedefe dokunulmuyor, satıra
 *     yazılıyor ve sayılıyor.
 *   - Platformun artık bildirmediği makine SİLİNMİYOR, işaretleniyor:
 *     hedefinin oturum geçmişi var.
 */
func (s *Service) collect(ctx context.Context, src store.DiscoverySource, rep *store.DiscoveryRun) error {
	secret, err := s.db.DiscoverySourceSecret(ctx, src.ID)
	if err != nil {
		return fmt.Errorf("the source's credentials could not be read: %w", err)
	}
	source, err := s.open(src, secret)
	if err != nil {
		return err
	}

	lctx, cancel := context.WithTimeout(ctx, listTimeout)
	listed, err := source.Machines(lctx)
	cancel()
	if err != nil {
		return fmt.Errorf("%s: %w", src.Kind, err)
	}

	machines := make([]Machine, 0, len(listed))
	for _, m := range listed {
		if m.Key == "" {
			m.Key = m.Ref
		}
		if m.Key != "" && matchesPattern(src.NamePattern, m.Name) {
			machines = append(machines, m)
		}
	}

	known, err := s.db.DiscoveredMachines(ctx, src.ID)
	if err != nil {
		return err
	}
	byKey := make(map[string]store.DiscoveredMachine, len(known))
	present := 0
	for _, k := range known {
		byKey[k.Ref] = k
		if k.MissingSince.IsZero() {
			present++
		}
	}

	/*
	 * ⚠️ BOŞ LİSTE "HEPSİ GİTTİ" DEĞİL. Yetkisi daraltılmış bir Proxmox
	 * jetonu hata vermiyor, BOŞ liste dönüyor (VM.Audit olmadan makineler
	 * görünmüyor). Bunu doğru sayıp bilinen her makineyi "kayıp"
	 * işaretlemek, panelin "platformda var" listesini bir jeton ayarıyla
	 * sıfırlardı. Koşu başarısız, hiçbir satıra dokunulmuyor.
	 */
	if len(machines) == 0 && present > 0 {
		return fmt.Errorf("the source reported no machines while %d were known; nothing was marked "+
			"missing — check the credentials' permissions and the name pattern", present)
	}

	targets, err := s.db.TargetKeys(ctx)
	if err != nil {
		return err
	}
	byID := make(map[string]store.TargetKey, len(targets))
	byName := make(map[string]store.TargetKey, len(targets))
	for _, t := range targets {
		byID[t.ID] = t
		byName[strings.ToLower(t.Name)] = t
	}

	results := make([]scanResult, len(machines))
	sem := make(chan struct{}, scanWorkers)
	var wg sync.WaitGroup
	for i, m := range machines {
		if prev, ok := byKey[m.Key]; (ok && prev.Ignored) || !m.Running {
			continue
		}
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			k, serr := s.scan(ctx, host, src.Port)
			results[i] = scanResult{key: k, err: serr, tried: true}
		}(i, address(m))
	}
	wg.Wait()
	// İptal edilen koşunun tarama hataları "ulaşılamadı" diye yazılmasın.
	if err := ctx.Err(); err != nil {
		return err
	}

	now := s.now()
	seen := map[string]bool{}
	for i, m := range machines {
		if seen[m.Key] {
			continue
		}
		seen[m.Key] = true
		rep.Seen++

		prev, isKnown := byKey[m.Key]
		row := store.DiscoveredMachine{
			SourceID: src.ID, Ref: m.Key, Name: m.Name, Host: strings.TrimSpace(m.Host),
			Tags: m.Tags, Running: m.Running, LastSeen: now,
		}
		row.Group, row.Tagged = GroupFromTags(m.Tags, src.TagKey)
		if !row.Tagged {
			row.Group = ""
		}
		if isKnown {
			row.TargetID, row.Ignored, row.HostKey = prev.TargetID, prev.Ignored, prev.HostKey
		} else {
			rep.NewMachines++
		}

		var problems []string
		if row.Tagged {
			if err := ValidGroupName(row.Group); err != nil {
				problems = append(problems, fmt.Sprintf("its tag names an unusable group (%v)", err))
			}
		}
		if err := ValidTargetName(m.Name); err != nil {
			problems = append(problems, fmt.Sprintf("its name cannot be a target name (%v)", err))
		}

		res := results[i]
		switch {
		case row.Ignored:
			// Yok sayılan makine taranmıyor; son bilinen anahtarı duruyor.
		case !m.Running:
			problems = append(problems, "not running, so its host key cannot be read")
		case res.err != nil:
			rep.Unreachable++
			problems = append(problems, fmt.Sprintf("no host key from %s:%d (%v)", address(m), src.Port, res.err))
		default:
			row.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(res.key)))
		}
		fresh := res.tried && res.err == nil

		if row.TargetID != "" {
			t, ok := byID[row.TargetID]
			if ok && fresh && t.HostKey != "" && fingerprint(t.HostKey) != ssh.FingerprintSHA256(res.key) {
				rep.KeyChanged++
				problems = append(problems, fmt.Sprintf(
					"its host key %s differs from %s pinned on target %s; the target was left untouched",
					ssh.FingerprintSHA256(res.key), fingerprint(t.HostKey), t.Name))
			}
		} else if t, ok := byName[strings.ToLower(m.Name)]; ok {
			/*
			 * ⚠️ AYNI AD KANIT DEĞİL, AYNI ANAHTAR KANIT. CLI'nin ya da elle
			 * kaydedilmiş bir hedef bu makine olabilir — ya da aynı adı
			 * taşıyan başka bir makine. Bağ yalnızca bu koşuda okunan
			 * anahtar hedefe sabitlenmiş anahtarla aynıysa kuruluyor.
			 */
			switch {
			case fresh && t.HostKey != "" && fingerprint(t.HostKey) == ssh.FingerprintSHA256(res.key):
				row.TargetID = t.ID
			case fresh:
				problems = append(problems, "a target named "+t.Name+" already exists with a different host key")
			default:
				problems = append(problems, "a target named "+t.Name+
					" already exists; its host key could not be compared in this run")
			}
		}

		row.Problem = strings.Join(problems, "; ")
		if err := s.db.SaveDiscoveredMachine(ctx, row); err != nil {
			return err
		}
	}

	for key, prev := range byKey {
		if seen[key] || !prev.MissingSince.IsZero() {
			continue
		}
		if err := s.db.MarkDiscoveredMachineMissing(ctx, src.ID, key, now); err != nil {
			return err
		}
		rep.Missing++
	}
	return nil
}

// MachineRef, paneldeki bir satırın kimliği.
type MachineRef struct {
	SourceID string `json:"source_id"`
	Ref      string `json:"ref"`
}

// RegisterRequest, seçili makineleri hedef yapma isteği.
type RegisterRequest struct {
	Machines []MachineRef
	// Groups, her makinenin bağlanacağı var olan gruplar.
	Groups []string
	// TagGroups: makinenin etiketinin söylediği group de bağla (yoksa aç).
	TagGroups bool
	Labels    map[string]string
	Actor     string
}

// Registered, tek makinenin kayıt sonucu.
type Registered struct {
	SourceID      string   `json:"source_id"`
	Ref           string   `json:"ref"`
	Name          string   `json:"name"`
	Target        string   `json:"target,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	CreatedGroups []string `json:"created_roles,omitempty"`
	Error         string   `json:"error,omitempty"`
}

/*
 * Register, seçili makineleri hedef yapar, gruplara bağlar ve etiketler.
 *
 * ⚠️ ANAHTAR YENİDEN TARANMIYOR, KOŞUNUN OKUDUĞU SABİTLENİYOR. Yönetici
 * özet ekranında o parmak izini gördü ve onu onayladı; tıklama anında
 * başka bir anahtar okuyup onu sabitlemek, onaylanmayanı yazmak olurdu.
 * Bayat bir anahtar en fazla bağlantının reddedilmesine yol açıyor —
 * sabitlenen anahtarı proxy her bağlantıda doğruluyor.
 *
 * Makine başına hatalar sonuca yazılıyor ve sıradakine geçiliyor; yalnızca
 * veritabanı ya da denetim defteri yazılamazsa parti duruyor — kaydı
 * düşmeyen bir erişim vermeye devam etmemek için.
 */
func (s *Service) Register(ctx context.Context, req RegisterRequest) ([]Registered, error) {
	if len(req.Machines) == 0 {
		return nil, fmt.Errorf("%w: no machine selected", store.ErrInvalid)
	}
	for k, v := range req.Labels {
		if err := store.ValidateLabel(k, v); err != nil {
			return nil, fmt.Errorf("%w: %v", store.ErrInvalid, err)
		}
	}
	groups, err := s.db.Groups(ctx)
	if err != nil {
		return nil, err
	}
	haveGroup := make(map[string]bool, len(groups))
	for _, r := range groups {
		haveGroup[r.Name] = true
	}
	var chosen []string
	for _, r := range req.Groups {
		r = strings.TrimSpace(r)
		if r == "" || hasString(chosen, r) {
			continue
		}
		if !haveGroup[r] {
			return nil, fmt.Errorf("%w: group %q does not exist", store.ErrInvalid, r)
		}
		chosen = append(chosen, r)
	}

	sources := map[string]store.DiscoverySource{}
	out := make([]Registered, 0, len(req.Machines))
	for _, key := range req.Machines {
		res, err := s.registerOne(ctx, key, chosen, req, haveGroup, sources)
		out = append(out, res)
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

func (s *Service) registerOne(ctx context.Context, key MachineRef, chosen []string, req RegisterRequest,
	haveGroup map[string]bool, sources map[string]store.DiscoverySource) (Registered, error) {
	res := Registered{SourceID: key.SourceID, Ref: key.Ref}
	m, err := s.db.DiscoveredMachine(ctx, key.SourceID, key.Ref)
	if errors.Is(err, store.ErrNotFound) {
		res.Error = "not found; it may have been removed with its source"
		return res, nil
	}
	if err != nil {
		return res, err
	}
	res.Name = m.Name
	src, ok := sources[m.SourceID]
	if !ok {
		if src, err = s.db.DiscoverySource(ctx, m.SourceID); err != nil {
			return res, err
		}
		sources[m.SourceID] = src
	}

	switch {
	case m.TargetID != "":
		res.Error = "already registered as target " + m.Target
		return res, nil
	case !m.MissingSince.IsZero():
		res.Error = "its source no longer reports it"
		return res, nil
	case m.HostKey == "":
		res.Error = "no host key has been read from it; it was not reachable when discovery last ran"
		return res, nil
	}
	if err := ValidTargetName(m.Name); err != nil {
		res.Error = fmt.Sprintf("its name cannot be a target name (%v)", err)
		return res, nil
	}
	pub, _, _, _, perr := ssh.ParseAuthorizedKey([]byte(m.HostKey))
	if perr != nil {
		res.Error = "the recorded host key cannot be read"
		return res, nil
	}
	if _, herr := sshalg.HostKeyAlgorithmsFor(pub.Type()); herr != nil {
		res.Error = herr.Error()
		return res, nil
	}

	grant := append([]string(nil), chosen...)
	createGroup := ""
	if req.TagGroups && m.Tagged && ValidGroupName(m.Group) == nil && !hasString(grant, m.Group) {
		grant = append(grant, m.Group)
		if !haveGroup[m.Group] {
			createGroup = m.Group
		}
	}

	host := m.Host
	if host == "" {
		host = m.Name
	}
	targetID, err := s.db.CreateTarget(ctx, model.Target{
		Name: m.Name, Host: host, Port: src.Port, HostKey: string(ssh.MarshalAuthorizedKey(pub)),
	})
	if errors.Is(err, store.ErrConflict) {
		res.Error = "a target named " + m.Name + " already exists"
		return res, nil
	}
	if err != nil {
		return res, err
	}
	res.Target = m.Name
	if err := s.audit(ctx, req.Actor, "target.create", m.Name, fmt.Sprintf(
		"%s:%d, host key %s, registered from discovery source %s (%s)",
		host, src.Port, ssh.FingerprintSHA256(pub), src.Name, m.Ref)); err != nil {
		return res, err
	}
	if err := s.db.LinkDiscoveredMachine(ctx, m.SourceID, m.Ref, targetID); err != nil {
		return res, err
	}
	for k, v := range req.Labels {
		// Etiket satırını store yazıyor (bkz. store.SetTargetLabel).
		if err := s.db.SetTargetLabel(ctx, m.Name, k, v, req.Actor, "web"); err != nil {
			return res, err
		}
	}
	if createGroup != "" {
		if _, err := s.db.CreateGroup(ctx, createGroup); err != nil && !errors.Is(err, store.ErrConflict) {
			return res, err
		}
		haveGroup[createGroup] = true
		res.CreatedGroups = append(res.CreatedGroups, createGroup)
		if err := s.audit(ctx, req.Actor, "group.create", createGroup,
			"from tag "+src.TagKey+" while registering "+m.Name); err != nil {
			return res, err
		}
	}
	for _, r := range grant {
		if err := s.db.GrantTarget(ctx, r, m.Name); err != nil && !errors.Is(err, store.ErrConflict) {
			return res, err
		}
		res.Groups = append(res.Groups, r)
		if err := s.audit(ctx, req.Actor, "group.grant", r,
			"target "+m.Name+" (registered from discovery)"); err != nil {
			return res, err
		}
	}
	return res, nil
}

// SetIgnored, makineleri yok sayar ya da yok saymayı kaldırır; kaç
// satırın değiştiğini döner.
func (s *Service) SetIgnored(ctx context.Context, keys []MachineRef, ignored bool, actor string) (int, error) {
	action := "discovery.ignore"
	if !ignored {
		action = "discovery.unignore"
	}
	n := 0
	for _, k := range keys {
		name, changed, err := s.db.SetDiscoveredMachineIgnored(ctx, k.SourceID, k.Ref, ignored)
		if err != nil {
			return n, err
		}
		if !changed {
			continue
		}
		n++
		if err := s.audit(ctx, actor, action, name, k.Ref); err != nil {
			return n, err
		}
	}
	return n, nil
}

/*
 * audit, keşfin panelden yaptığı değişikliği deftere yazar ve yazamazsa
 * HATA döner — Planner.audit ile aynı karar: erişim veren bir yazmanın
 * izi yoksa sıradakine devam edilmiyor. İstek bağlamından kopuk: yazma
 * olduysa satır da yazılmalı.
 */
func (s *Service) audit(ctx context.Context, actor, action, entity, details string) error {
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := s.db.LogAdmin(actx, store.AdminLogEntry{
		Actor: actor, Via: "web", Action: action, Entity: entity, Details: details,
	}); err != nil {
		return fmt.Errorf("audit %s %q: %w", action, entity, err)
	}
	return nil
}

func hasString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
