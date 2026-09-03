package discover

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Warewave-Technology/postern/internal/model"
	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/testdb"
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
	s, _ := newStoreDSN(t)
	return s
}

// newStoreDSN, aynısını DSN'i de vererek döner: bir testin tek bir
// tabloyu düşürmek için ikinci bir bağlantı açması gerekebiliyor.
func newStoreDSN(t *testing.T) (*store.Store, string) {
	t.Helper()
	dsn := testdb.DSN(t)
	s, err := store.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s, dsn
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

/*
 * ⚠️ ULAŞILAMAYAN AMA KAYITLI HEDEFTE ROL BAĞI YİNE YENİLENİR.
 *
 * ÖLÇÜLEN ARIZA: tarama hatası makineyi koşulsuz atlıyordu ve atlanan
 * şeylerin arasında GrantTarget da vardı. Oysa grant HİÇ AĞ İSTEMİYOR —
 * rolle hedef arasında yerel bir bağ. Sonucu şuydu: etiketi değişmiş bir
 * makine, o anda ağda bir aksaklık olduğu için yeni rolüne geçmiyor ve
 * bir sonraki koşuma kadar ESKİ rolünde kalıyordu. apply.go'nun kendi
 * yorumu grant'ın her turda çalışması gerektiğini söylüyor; ağ hatası
 * onu sessizce erteliyordu.
 *
 * Kullanıcının yaşadığı durum bunun tam örneğiydi: yerel ağ izni
 * yüzünden bütün taramalar EHOSTUNREACH aldı.
 */
func TestRunStillGrantsWhenAnExistingTargetIsUnreachable(t *testing.T) {
	ctx := context.Background()
	db := newStore(t)

	// Kayıtlı hedef — adresi ULAŞILAMAZ (kapalı port).
	if _, err := db.CreateTarget(ctx, model.Target{
		Name: "lab-01", Host: "127.0.0.1", Port: 1,
		HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIcLUQM0UcoZdJVh2EokribDvFZyyNyAVURM/LrCugFM",
	}); err != nil {
		t.Fatal(err)
	}

	res, err := Planner{DB: db, TagKey: "team", Port: 1, Actor: "test"}.
		Run(ctx, []Machine{{
			Name: "lab-01", Host: "127.0.0.1",
			Tags: []string{"team_developer"}, Running: true,
		}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("sonuç sayısı = %d", len(res))
	}
	o := res[0]

	if o.Skipped != "" {
		t.Fatalf("kayıtlı hedef atlandı: %q — rol bağı ağ hatasına takıldı", o.Skipped)
	}
	if !o.Granted {
		t.Error("rol bağı yenilenmedi; grant ağ istemiyor, ertelenmemeliydi")
	}
	/*
	 * ⚠️ AMA ANAHTARIN DOĞRULANAMADIĞI SÖYLENMELİ. "Kontrol ettim ve
	 * aynıydı" ile "kontrol edemedim" farklı şeyler; ikincisini
	 * birincisi gibi göstermek, değişmiş bir makineyi değişmemiş
	 * sandırır.
	 */
	if o.KeyUnchecked == "" {
		t.Error("anahtarın doğrulanamadığı bildirilmedi")
	}

	// Rol gerçekten verilmiş olmalı.
	roles, rerr := db.Roles(ctx)
	if rerr != nil {
		t.Fatal(rerr)
	}
	var found bool
	for _, r := range roles {
		if r.Name != "developer" {
			continue
		}
		for _, n := range r.Targets {
			if n == "lab-01" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("rol hedefe bağlanmamış: %+v", roles)
	}
}

// Ulaşılamayan ve KAYITLI OLMAYAN makine hâlâ atlanmalı: anahtarsız
// hedef yazmak, ona ilk bağlanan kişiyi karşısındakini bilmeden
// bağlatmak olurdu.
func TestRunStillSkipsUnreachableNewMachines(t *testing.T) {
	ctx := context.Background()
	db := newStore(t)

	res, err := Planner{DB: db, TagKey: "team", Port: 1, Actor: "test"}.
		Run(ctx, []Machine{{
			Name: "yeni-01", Host: "127.0.0.1",
			Tags: []string{"team_developer"}, Running: true,
		}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Skipped == "" {
		t.Fatalf("ulaşılamayan YENİ makine atlanmadı: %+v", res)
	}
	if _, terr := db.Target(ctx, "yeni-01"); terr == nil {
		t.Fatal("anahtarsız hedef kaydedildi")
	}
}

/*
 * ⚠️ VERİLEN ERİŞİM DEFTERE YAZILMALI — YAZILMADIĞI HÂLİ ÖLÇÜLDÜ.
 *
 * `postern discover --apply`, hedefe erişim dağıtan TEK yol olarak
 * denetim defterinde iz bırakmıyordu. Rol ve hedef OLUŞTURMA
 * denetleniyordu; erişimi asıl veren GrantTarget denetlenmiyordu.
 *
 * Kaçırdığı durum, grant'ın her turda çalışmasının SEBEBİ olan durum:
 * etiketi değişen bir makine ikinci koşuda yeni rolüne bağlanıyor. Orada
 * ne rol ne hedef yaratılıyor — yani var olan iki denetim satırının
 * ikisi de yazılmıyor ve defter tamamen sessiz kalıyor.
 *
 * Test bu ikinci koşuyu ölçüyor, ilkini değil: ilk koşuda satırın
 * gelmesi, oluşturma denetimlerinin gölgesinde olabilirdi.
 */
func TestRetaggingAMachineWritesTheGrantToTheLedger(t *testing.T) {
	ctx := context.Background()
	db := newStore(t)
	host, port := fakeSSH(t)

	p := Planner{DB: db, TagKey: "role", Port: port, Actor: "yigit"}

	// İlk koşu: hedef ve "ops" rolü doğuyor.
	if _, err := p.Run(ctx, []Machine{
		{Name: "web-01", Host: host, Tags: []string{"role=ops"}, Running: true, Ref: "qemu/101@n1"},
	}, true); err != nil {
		t.Fatal(err)
	}

	before := grantRows(t, db)

	// İkinci koşu: AYNI makine yeni etiketle. Ne rol ne hedef yaratılıyor
	// — "dba" rolü yaratılıyor ama hedef zaten var ve asıl olay grant.
	if _, err := p.Run(ctx, []Machine{
		{Name: "web-01", Host: host, Tags: []string{"role=dba"}, Running: true, Ref: "qemu/101@n1"},
	}, true); err != nil {
		t.Fatal(err)
	}

	after := grantRows(t, db)
	if len(after) <= len(before) {
		t.Fatalf("role.grant satırı %d → %d; keşif erişim verdi ama defterde "+
			"iz yok — \"prod erişimini web01'e kim verdi?\" sorusu cevapsız",
			len(before), len(after))
	}

	last := after[0]
	if last.Actor != "yigit" {
		t.Errorf("actor = %q, komutu koşan kişi bekleniyordu", last.Actor)
	}
	if !strings.Contains(last.Details, "web-01") {
		t.Errorf("details = %q; hangi hedefin verildiğini söylemiyor", last.Details)
	}

	// ⚠️ Değişmeyen bir koşu defteri ŞİŞİRMEMELİ: aynı etiketle üçüncü
	// kez koşmak yeni bir erişim doğurmuyor.
	if _, err := p.Run(ctx, []Machine{
		{Name: "web-01", Host: host, Tags: []string{"role=dba"}, Running: true, Ref: "qemu/101@n1"},
	}, true); err != nil {
		t.Fatal(err)
	}
	if again := grantRows(t, db); len(again) != len(after) {
		t.Errorf("değişmeyen koşu %d yeni satır yazdı — her tarama defteri "+
			"aynı cümleyle doldurur", len(again)-len(after))
	}
}

func grantRows(t *testing.T, db *store.Store) []store.AdminLogEntry {
	t.Helper()
	all, err := db.AdminLog(context.Background(), 200)
	if err != nil {
		t.Fatalf("AdminLog: %v", err)
	}
	var out []store.AdminLogEntry
	for _, e := range all {
		if e.Action == "role.grant" {
			out = append(out, e)
		}
	}
	return out
}

/*
 * ⚠️ DENETİM YAZILAMIYORSA KEŞİF DEVAM ETMEZ.
 *
 * Hata bir süre yutuluyordu ve gerekçesi "yarım kalmış bir keşif,
 * kaydı olmayan bir keşiften daha kötü" idi. O tartışma yazılan
 * satırlar yalnızca oluşturma satırlarıyken savunulabilirdi; erişim
 * VEREN satır da oradan geçtiğine göre yutmak, "erişim verildi ve
 * defterde izi yok" demek.
 *
 * Yarım kalma endişesi de geçersiz: döngüdeki her yazma yeniden
 * çalıştırılabilir, yani duran koşum yeniden koşularak tamamlanıyor.
 *
 * Test admin_log tablosunu düşürerek LogAdmin'i gerçekten
 * başarısızlaştırıyor — hatayı taklit etmek, taşınıp taşınmadığını
 * değil taklidin kendisini ölçerdi.
 */
func TestDiscoveryStopsWhenTheLedgerCannotBeWritten(t *testing.T) {
	ctx := context.Background()
	db, dsn := newStoreDSN(t)
	host, port := fakeSSH(t)

	// ⚠️ Tabloyu GERÇEKTEN düşürüyoruz, ayrı bir bağlantıdan: tek bir
	// sorgunun çökmesini istiyoruz, bağlantının tamamının değil.
	raw, oerr := sql.Open("pgx", dsn)
	if oerr != nil {
		t.Fatal(oerr)
	}
	defer raw.Close()
	if _, derr := raw.Exec(`DROP TABLE admin_log;`); derr != nil {
		t.Fatalf("admin_log düşürülemedi: %v", derr)
	}

	p := Planner{DB: db, TagKey: "role", Port: port, Actor: "yigit"}
	_, err := p.Run(ctx, []Machine{
		{Name: "web-01", Host: host, Tags: []string{"role=ops"}, Running: true, Ref: "qemu/101@n1"},
	}, true)
	if err == nil {
		t.Fatal("denetim kaydı yazılamazken keşif sessizce devam etti — " +
			"erişim dağıtıyor ve defterde izi yok")
	}
	if !strings.Contains(err.Error(), "audit") {
		t.Errorf("hata denetimden bahsetmiyor: %v", err)
	}
}
