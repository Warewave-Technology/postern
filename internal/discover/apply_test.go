package discover

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/warewave/postern/internal/model"
	"github.com/warewave/postern/internal/store"
	"github.com/warewave/postern/internal/testdb"
)

// fakeSSH, host anahtarı taranabilen bir dinleyici açar.
//
// ⚠️ GERÇEK BİR EL SIKIŞMA: ScanHostKey ağdan anahtar okuyor ve keşfin
// bir makineyi atlamasının en sık sebebi tam olarak bunun başarısız
// olması. Taklit etmek, ölçmek istediğimiz şeyi ölçmemek olurdu.
func fakeSSH(t *testing.T) (host string, port int) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				_, _, _, _ = ssh.NewServerConn(c, cfg)
				c.Close()
			}()
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

// newStore, göçleri uygulanmış boş bir veritabanı.
func newStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), testdb.DSN(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s
}

/*
 * ⚠️ KEŞFİN SÖZLEŞMESİ, UÇTAN UCA.
 *
 * Etiketli makine kendi rolüne, etiketsiz makine `unknown`a gidiyor;
 * eksik roller yaratılıyor; hedefler açılıyor ve rollere bağlanıyor.
 * Ve erişim VERİLMİYOR: roller insansız kalıyor.
 */
func TestRunCreatesRolesAndTargets(t *testing.T) {
	ctx := context.Background()
	db := newStore(t)
	host, port := fakeSSH(t)

	machines := []Machine{
		{Name: "web-01", Host: host, Tags: []string{"env=prod", "role=ops"}, Running: true, Ref: "qemu/101@n1"},
		{Name: "db-01", Host: host, Tags: []string{"role=dba"}, Running: true, Ref: "qemu/102@n1"},
		{Name: "eski-01", Host: host, Tags: []string{"env=prod"}, Running: true, Ref: "lxc/200@n1"},
	}

	p := Planner{DB: db, TagKey: "role", Port: port, Actor: "test"}

	// ⚠️ ÖNCE ÖNİZLEME: hiçbir şey yazılmamalı.
	prev, err := p.Run(ctx, machines, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(prev) != 3 {
		t.Fatalf("önizleme %d satır", len(prev))
	}
	if tg, _ := db.Targets(ctx); len(tg) != 0 {
		t.Fatalf("önizleme hedef yazmış: %d", len(tg))
	}
	if rs, _ := db.Roles(ctx); len(rs) != 0 {
		t.Fatalf("önizleme rol yazmış: %d", len(rs))
	}

	// Şimdi uygula.
	res, err := p.Run(ctx, machines, true)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Outcome{}
	for _, o := range res {
		if o.Skipped != "" {
			t.Fatalf("%s atlandı: %s", o.Machine.Name, o.Skipped)
		}
		byName[o.Machine.Name] = o
	}

	if byName["web-01"].Role != "ops" || !byName["web-01"].Tagged {
		t.Errorf("web-01 = %+v", byName["web-01"])
	}
	// ⚠️ Etiketsiz makine DÜŞMÜYOR, unknown'a gidiyor.
	if byName["eski-01"].Role != UnknownRole || byName["eski-01"].Tagged {
		t.Errorf("etiketsiz makine unknown'a gitmedi: %+v", byName["eski-01"])
	}

	roles, _ := db.Roles(ctx)
	have := map[string]bool{}
	for _, r := range roles {
		have[r.Name] = true
	}
	for _, want := range []string{"ops", "dba", UnknownRole} {
		if !have[want] {
			t.Errorf("rol yaratılmamış: %s", want)
		}
	}

	// Hedefler rollere BAĞLI.
	for _, r := range roles {
		if len(r.Targets) == 0 {
			t.Errorf("rol %q hiçbir hedefe bağlanmamış", r.Name)
		}
	}

	/*
	 * ⚠️ EN ÖNEMLİ İDDİA: KEŞİF ERİŞİM VERMEDİ.
	 *
	 * Roller hedef tutuyor ama hiçbir İNSANA bağlı değil. Keşfin bir
	 * gün "kolaylık olsun" diye kullanıcı ataması yapmaya başlaması,
	 * toplu bir taramanın sessizce erişim dağıtması demek olurdu.
	 */
	users, err := db.Users(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if len(u.Roles) > 0 {
			t.Fatalf("keşif %q kullanıcısına rol atamış — erişim dağıtmamalı", u.Name)
		}
	}
}

/*
 * ⚠️ VAR OLAN HEDEFİN HOST ANAHTARI ÜZERİNE YAZILMIYOR.
 *
 * Keşif toplu ve otomatik. Kayıtlı bir anahtarı sessizce değiştirmek,
 * "makine değişti"yi "makine yenilendi" sanıp kabul etmek demek — ve bu,
 * host anahtarının var olma sebebini ortadan kaldırır.
 */
func TestRunRefusesToOverwriteADifferentHostKey(t *testing.T) {
	ctx := context.Background()
	db := newStore(t)
	host, port := fakeSSH(t)

	// Aynı adla, BAŞKA anahtarla kayıtlı bir hedef.
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(other.Public())
	if err != nil {
		t.Fatal(err)
	}
	stale := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	if _, err := db.CreateTarget(ctx, model.Target{
		Name: "web-01", Host: host, Port: port, HostKey: stale,
	}); err != nil {
		t.Fatal(err)
	}

	res, err := Planner{DB: db, TagKey: "role", Port: port, Actor: "test"}.
		Run(ctx, []Machine{{Name: "web-01", Host: host, Tags: []string{"role=ops"}, Running: true}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Skipped == "" {
		t.Fatalf("farklı anahtarlı hedef atlanmadı: %+v", res)
	}
	if !strings.Contains(res[0].Skipped, "DIFFERENT host key") {
		t.Errorf("sebep anlaşılmıyor: %q", res[0].Skipped)
	}

	// Kayıtlı anahtar DEĞİŞMEMİŞ olmalı.
	got, err := db.Target(ctx, "web-01")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(got.HostKey) != stale {
		t.Fatal("keşif kayıtlı host anahtarını üzerine yazdı")
	}
}

// Kapalı makine hedefe dönüşmüyor ve sebebi raporda: anahtarı
// taranamayan bir makineyi anahtarsız kaydetmek, ona ilk bağlanan
// kişiyi karşısındakini bilmeden bağlatmak olurdu.
func TestRunSkipsStoppedMachines(t *testing.T) {
	ctx := context.Background()
	db := newStore(t)

	res, err := Planner{DB: db, TagKey: "role", Port: 22, Actor: "test"}.
		Run(ctx, []Machine{{Name: "kapali", Tags: []string{"role=ops"}, Running: false}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Skipped == "" || !strings.Contains(res[0].Skipped, "not running") {
		t.Fatalf("kapalı makine atlanmadı: %+v", res[0])
	}
	if tg, _ := db.Targets(ctx); len(tg) != 0 {
		t.Fatal("kapalı makine için hedef yazılmış")
	}
}

// Etiketten gelen kabul edilemez bir ad makineyi unknown'a DÜŞÜRMÜYOR,
// atlıyor: yazım hatasını operatörün bir daha göremeyeceği bir yere
// süpürmek yerine raporda gösteriyor.
func TestRunSkipsUnusableRoleNames(t *testing.T) {
	ctx := context.Background()
	db := newStore(t)

	res, err := Planner{DB: db, TagKey: "role", Port: 22, Actor: "test"}.
		Run(ctx, []Machine{{Name: "m", Tags: []string{"role=iki kelime"}, Running: true}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Skipped == "" {
		t.Fatalf("kullanılamaz rol adı kabul edildi: %+v", res[0])
	}
	if rs, _ := db.Roles(ctx); len(rs) != 0 {
		t.Fatal("kullanılamaz addan rol yaratılmış")
	}
}
