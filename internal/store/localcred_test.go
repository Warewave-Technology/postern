package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestLocalCredentialRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "ops", "ops@warewave.io", "ops"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddLocalCredential(ctx, "ops", "argon2id$deneme", "yigit"); err != nil {
		t.Fatal(err)
	}

	v, err := s.LocalCredential(ctx, "ops")
	if err != nil {
		t.Fatal(err)
	}
	if v != "argon2id$deneme" {
		t.Fatalf("doğrulayıcı = %q", v)
	}

	holders, err := s.LocalCredentialHolders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(holders) != 1 || holders[0].Username != "ops" || holders[0].CreatedBy != "yigit" {
		t.Fatalf("sahipler = %+v", holders)
	}
	if !holders[0].LastUsedAt.IsZero() {
		t.Error("hiç kullanılmamış kimlik bilgisi için son kullanım damgası var")
	}

	when := time.Now()
	if err := s.TouchLocalCredential(ctx, "ops", when); err != nil {
		t.Fatal(err)
	}
	holders, err = s.LocalCredentialHolders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if holders[0].LastUsedAt.IsZero() {
		t.Error("kullanımdan sonra damga yazılmamış")
	}
}

/*
 * ⚠️ İKİNCİ KEZ ÇALIŞTIRMAK MEVCUT SIRRI GEÇERSİZ KILMAMALI.
 *
 * Üstüne yazan bir uygulama, komutu tekrar çalıştıran operatörün
 * ELİNDEKİ sırrı sessizce çöpe atardı — üstelik o an ekranda yeni bir
 * sır gördüğü için fark etmeden. Daha kötüsü, veritabanına yazabilen
 * herkes kurulumun tek yöneticisinin kimlik bilgisini böylece
 * döndürebilirdi.
 */
func TestAddLocalCredentialRefusesToOverwrite(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "ops", "ops@warewave.io", "ops"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddLocalCredential(ctx, "ops", "birinci", "yigit"); err != nil {
		t.Fatal(err)
	}

	err := s.AddLocalCredential(ctx, "ops", "ikinci", "saldirgan")
	if !errors.Is(err, ErrCredentialExists) {
		t.Fatalf("hata = %v, ErrCredentialExists bekleniyordu", err)
	}

	v, err := s.LocalCredential(ctx, "ops")
	if err != nil {
		t.Fatal(err)
	}
	if v != "birinci" {
		t.Fatalf("doğrulayıcı ezilmiş: %q", v)
	}
}

func TestLocalCredentialRemoval(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "ops", "ops@warewave.io", "ops"); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveLocalCredential(ctx, "ops"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("olmayan kimlik bilgisi silinince: %v", err)
	}
	if err := s.AddLocalCredential(ctx, "ops", "v", "yigit"); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveLocalCredential(ctx, "ops"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LocalCredential(ctx, "ops"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("silindikten sonra: %v", err)
	}
	// Hesabın kendisi durmalı: kimlik bilgisi gitti, denetim izi değil.
	if _, err := s.User(ctx, "ops"); err != nil {
		t.Fatalf("kimlik bilgisiyle birlikte hesap da silinmiş: %v", err)
	}
}

// testPubKeyBlob, teste özgü bir açık anahtar üretir.
func testPubKeyBlob(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sshPub.Marshal()
}

/*
 * ⚠️ SİL-VE-EKLE KURALI ATLATAMAMALI.
 *
 * Kural "ilk anahtar serbest, sonrakiler yeniden kimlik doğrulama
 * ister" diye konuldu. Saf gerçekleştirme "şu an anahtarın var mı" diye
 * sorardı; o hâlde panel oturumunu ele geçiren biri mevcut anahtarı
 * siler, sayaç sıfıra döner ve kendi anahtarını bedavaya ekler — kural
 * tamamen delinir. Kapı bu yüzden SAYIYA değil, bir kez konan DAMGAYA
 * bakıyor. Test tam olarak o saldırı sırasını yürütüyor.
 */
func TestFirstKeyStampSurvivesRemoval(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "yigit", "yigit@warewave.io", "yigit"); err != nil {
		t.Fatal(err)
	}
	if stamped, err := s.FirstKeyAdded(ctx, "yigit"); err != nil {
		t.Fatal(err)
	} else if stamped {
		t.Fatal("yeni hesap damgalı geldi: ilk anahtar serbest olmalıydı")
	}

	blob := testPubKeyBlob(t)
	if err := s.AddPublicKey(ctx, "yigit", blob, "ilk"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkFirstKeyAdded(ctx, "yigit", time.Now()); err != nil {
		t.Fatal(err)
	}

	// Saldırı sırası: sil, sayaç sıfırlansın, yeniden ekle.
	if err := s.RemovePublicKey(ctx, "yigit", blob); err != nil {
		t.Fatal(err)
	}
	keys, err := s.PublicKeys(ctx, "yigit")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("anahtar silinmemiş: %d", len(keys))
	}

	stamped, err := s.FirstKeyAdded(ctx, "yigit")
	if err != nil {
		t.Fatal(err)
	}
	if !stamped {
		t.Fatal("silme damgayı kaldırdı — sil-ve-ekle kuralı atlatır")
	}
}

// Damga bir kez konuyor: sonraki çağrılar ilk anın üstüne yazmamalı.
func TestFirstKeyStampIsNotMoved(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "ayse", "ayse@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := s.MarkFirstKeyAdded(ctx, "ayse", old); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkFirstKeyAdded(ctx, "ayse", time.Now()); err != nil {
		t.Fatal(err)
	}

	var at sql.NullInt64
	if err := s.db.QueryRowContext(ctx,
		`SELECT first_key_added_at FROM users WHERE username = 'ayse';`).Scan(&at); err != nil {
		t.Fatal(err)
	}
	if !at.Valid || at.Int64 != old.Unix() {
		t.Fatalf("damga kaymış: %v (beklenen %d)", at, old.Unix())
	}
}

/*
 * ⚠️ GRUP MANTIĞI, CLI'IN VERDİĞİ YÖNETİCİLİĞİ GERİ ALAMAZ.
 *
 * Acil durum için elle açılmış bir yöneticinin, dizinde o grubu
 * görülmediği için sessizce yetkisini kaybetmesi tam olarak kaçınılması
 * gereken şey — ve kaybettiği an, yetkiyi geri verecek kişinin de kapısı
 * kapanmış olurdu. Rol modelindeki source='manual' korumasının aynısı.
 */
func TestGroupAdminCannotRevokeCLIAdmin(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "ops", "ops@warewave.io", "ops"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserAdmin(ctx, "ops", true); err != nil {
		t.Fatal(err)
	}
	if via, err := s.AdminVia(ctx, "ops"); err != nil || via != "cli" {
		t.Fatalf("kaynak = %q (%v), \"cli\" bekleniyordu", via, err)
	}

	// Dizin "bu kişi admin grubunda değil" diyor.
	if err := s.SetGroupAdmin(ctx, "ops", false); err != nil {
		t.Fatal(err)
	}

	u, err := s.User(ctx, "ops")
	if err != nil {
		t.Fatal(err)
	}
	if !u.Admin {
		t.Fatal("grup mantığı CLI'ın verdiği yöneticiliği kaldırdı — " +
			"acil durum hesabı dizindeki bir eksiklik yüzünden kapanır")
	}
}

// Buna karşılık grup, KENDİ verdiğini geri alabilmeli: dizinden
// çıkarılan kişi yönetici kalmamalı.
func TestGroupAdminRevokesItsOwnGrant(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "ayse", "ayse@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupAdmin(ctx, "ayse", true); err != nil {
		t.Fatal(err)
	}
	u, err := s.User(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if !u.Admin {
		t.Fatal("grup yöneticiliği uygulanmadı")
	}
	if via, _ := s.AdminVia(ctx, "ayse"); via != "group" {
		t.Fatalf("kaynak = %q, \"group\" bekleniyordu", via)
	}

	if err := s.SetGroupAdmin(ctx, "ayse", false); err != nil {
		t.Fatal(err)
	}
	u, err = s.User(ctx, "ayse")
	if err != nil {
		t.Fatal(err)
	}
	if u.Admin {
		t.Fatal("gruptan çıkarılan kişi hâlâ yönetici")
	}
	if via, _ := s.AdminVia(ctx, "ayse"); via != "" {
		t.Fatalf("kaynak = %q, boş bekleniyordu", via)
	}
}

/*
 * ApplyAdminGroup, kümeyi EŞİTLER: yeni gruptakine verir, eskiden kalana
 * geri alır — ve CLI'ınkine dokunmaz.
 *
 * Bu testin asıl kapattığı sızıntı, "revoke" tarafı: yetki yalnızca
 * girişte güncellenseydi, yönetici grubu değiştiğinde eski gruptan gelen
 * kişi bir daha hiç giriş yapmasa da yönetici KALIRDI. "Grubu
 * değiştirdim" ile "yetki değişti" arasındaki fark, kimsenin bakmadığı
 * bir yerde süresiz açık kalırdı.
 */
func TestApplyAdminGroupSyncsTheSet(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	for _, name := range []string{"ayse", "mehmet", "ops"} {
		if _, err := s.CreateUser(ctx, name, name+"@warewave.io", name); err != nil {
			t.Fatal(err)
		}
	}
	// ops acil durum yöneticisi, ayse eski gruptan geliyor.
	if err := s.SetUserAdmin(ctx, "ops", true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupAdmin(ctx, "ayse", true); err != nil {
		t.Fatal(err)
	}

	// Yeni grup: mehmet içeride, ayse dışarıda. Dizin adı FARKLI YAZIMLA
	// dönüyor — eşleştirme harf duyarsız olmak zorunda.
	granted, revoked, err := s.ApplyAdminGroup(ctx, []string{"Mehmet", "hiç-yok"})
	if err != nil {
		t.Fatal(err)
	}

	if len(granted) != 1 || granted[0] != "mehmet" {
		t.Fatalf("verilenler = %v, [mehmet] bekleniyordu", granted)
	}
	if len(revoked) != 1 || revoked[0] != "ayse" {
		t.Fatalf("alınanlar = %v, [ayse] bekleniyordu", revoked)
	}

	want := map[string]bool{"mehmet": true, "ops": true, "ayse": false}
	for name, admin := range want {
		u, err := s.User(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		if u.Admin != admin {
			t.Fatalf("%s admin = %v, %v bekleniyordu", name, u.Admin, admin)
		}
	}
	// ⚠️ ops'un kaynağı 'cli' KALMALI: 'group'a düşseydi, bir sonraki
	// eşitlemede acil durum hesabı da kapanırdı.
	if via, _ := s.AdminVia(ctx, "ops"); via != "cli" {
		t.Fatalf("ops kaynağı = %q, \"cli\" bekleniyordu", via)
	}
	if via, _ := s.AdminVia(ctx, "ayse"); via != "" {
		t.Fatalf("ayse kaynağı = %q, boş bekleniyordu", via)
	}
}

// Boş küme = grup ayarının temizlenmesi: gruptan gelen herkes düşer,
// CLI'ınki yerinde kalır.
func TestApplyAdminGroupWithNoMembersRevokesOnlyGroupGrants(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	for _, name := range []string{"ayse", "ops"} {
		if _, err := s.CreateUser(ctx, name, name+"@warewave.io", name); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetUserAdmin(ctx, "ops", true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupAdmin(ctx, "ayse", true); err != nil {
		t.Fatal(err)
	}

	if _, revoked, err := s.ApplyAdminGroup(ctx, nil); err != nil {
		t.Fatal(err)
	} else if len(revoked) != 1 || revoked[0] != "ayse" {
		t.Fatalf("alınanlar = %v, [ayse] bekleniyordu", revoked)
	}

	if u, _ := s.User(ctx, "ayse"); u.Admin {
		t.Fatal("grup temizlendi ama gruptan gelen yönetici yerinde kaldı")
	}
	if u, _ := s.User(ctx, "ops"); !u.Admin {
		t.Fatal("grup temizliği CLI'ın verdiği yöneticiliği de aldı")
	}
}

// Admins, yetkinin KAYNAĞINI da söylemeli: panel "bunu kaldırabilir
// miyim" sorusunu ancak öyle cevaplayabilir.
func TestAdminsReportsSource(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	for _, name := range []string{"ayse", "ops", "sade"} {
		if _, err := s.CreateUser(ctx, name, name+"@warewave.io", name); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetUserAdmin(ctx, "ops", true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupAdmin(ctx, "ayse", true); err != nil {
		t.Fatal(err)
	}

	got, err := s.Admins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	via := map[string]string{}
	for _, h := range got {
		via[h.Username] = h.Via
	}
	if len(got) != 2 {
		t.Fatalf("yönetici sayısı = %d (%v), 2 bekleniyordu", len(got), got)
	}
	if via["ops"] != "cli" || via["ayse"] != "group" {
		t.Fatalf("kaynaklar = %v", via)
	}
	if _, ok := via["sade"]; ok {
		t.Fatal("yönetici olmayan kişi listede")
	}
}

/*
 * ⚠️ ACİL DURUM HESABI GRUBA GİRERSE, KAYNAĞI DÜŞMEMELİ.
 *
 * CLI ile açılmış yönetici yönetici grubunda da yer alıyorsa, yetkisinin
 * kaynağı sessizce 'group'a dönebilirdi. Görünürde hiçbir şey değişmez —
 * ta ki o kişi gruptan çıkarılana kadar: o gün, hiç kaybetmemesi gereken
 * acil durum yetkisini de kaybeder ve geri verecek kimse kalmaz.
 */
func TestApplyAdminGroupDoesNotDowngradeCLIAdmin(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "ops", "ops@warewave.io", "ops"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserAdmin(ctx, "ops", true); err != nil {
		t.Fatal(err)
	}

	// ops yönetici grubunda.
	granted, _, err := s.ApplyAdminGroup(ctx, []string{"ops"})
	if err != nil {
		t.Fatal(err)
	}
	if len(granted) != 0 {
		t.Fatalf("verilenler = %v, boş bekleniyordu (zaten CLI yöneticisi)", granted)
	}
	if via, _ := s.AdminVia(ctx, "ops"); via != "cli" {
		t.Fatalf("kaynak = %q — CLI yöneticisi gruba girince kaynağı düştü", via)
	}

	// Ve gruptan çıkınca yetkisini KAYBETMEMELİ.
	if _, revoked, err := s.ApplyAdminGroup(ctx, nil); err != nil {
		t.Fatal(err)
	} else if len(revoked) != 0 {
		t.Fatalf("alınanlar = %v — gruptan çıkan acil durum hesabı kapandı", revoked)
	}
	if u, _ := s.User(ctx, "ops"); !u.Admin {
		t.Fatal("acil durum hesabı, grup üyeliği üzerinden kapatıldı")
	}
}

/*
 * Göç 018: eski `ldap.auth_enabled` bayrağı, yeni tek değere TAŞINIR.
 *
 * Taşınmasaydı, dizin parolasıyla girişi açmış bir kurulum yükseltmeden
 * sonra o kapıyı kapalı bulurdu: kimse giremezdi ve sebebi hiçbir yerde
 * yazmazdı.
 *
 * ⚠️ Anahtar adları BURADA ELLE YAZILI, sabitlerden okunmuyor. Bir göç,
 * veritabanında DURAN adlarla ilgilenir; sabit yeniden adlandırılırsa
 * test onu takip edip sessizce başka bir şeyi doğrulamaya başlamamalı.
 */
func TestMigration018MovesDirectoryFlagIntoSource(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	// 018'in ALTINA in, eski dünyayı kur, sonra tekrar uygula.
	//
	// ⚠️ Tek bir Rollback YETMEZ ve bunu varsaymak testi kırılgan
	// yapıyordu: 019 eklenince bu test "018'i geri aldım" sanarak
	// 019'u geri alıyordu. Hedef sürüme kadar iniyoruz.
	rollbackBelow(ctx, t, s, 18)
	if err := s.SetSetting(ctx, "ldap.auth_enabled", "true", false, "test"); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	got, err := s.Setting(ctx, "auth.source")
	if err != nil {
		t.Fatalf("auth.source okunamadı: %v", err)
	}
	if got != "ldap" {
		t.Fatalf("auth.source = %q, \"ldap\" bekleniyordu", got)
	}

	// ⚠️ Eski bayrak SİLİNMİŞ olmalı: iki ayar aynı soruya cevap
	// veriyor olsaydı, çeliştiklerinde anlamı tanımsız kalırdı.
	if _, err := s.Setting(ctx, "ldap.auth_enabled"); !errors.Is(err, ErrNotFound) {
		t.Fatal("eski bayrak duruyor — aynı soruya iki ayar cevap veriyor")
	}
}

// Bayrak KAPALIYSA kaynak dizine çevrilmemeli: kapalı bir kapıyı
// yükseltme sırasında açmak, tam tersi yönde bir hata olurdu.
func TestMigration018LeavesSourceUnsetWhenFlagWasOff(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	rollbackBelow(ctx, t, s, 18)
	if err := s.SetSetting(ctx, "ldap.auth_enabled", "false", false, "test"); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	if v, err := s.Setting(ctx, "auth.source"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("auth.source = %q (%v) — kapalı bayrak dizin kapısını açtı", v, err)
	}
}

/*
 * ⚠️ 019: YALNIZCA HARF YAZIMIYLA AYRILAN İKİ HESAP OLAMAZ.
 *
 * Olabilseydi, "hangi Bob" sorusunun cevabı veritabanının sıralamasına
 * kalırdı — ve o cevabı UserByNameFold ile ApplyAdminGroup kullanıyor,
 * yani yönetici yetkisinin kime yazılacağını belirleyebilirdi.
 */
func TestUsernameIsUniqueRegardlessOfCase(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "bob", "bob@warewave.io", "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, "Bob", "bob2@warewave.io", "bob"); err == nil {
		t.Fatal("yalnızca harf yazımıyla ayrılan ikinci hesap açıldı — " +
			"dizinin tek kişi gördüğü yerde postern iki hesap tutuyor")
	}

	// Ve fold araması tek ve KESİN bir cevap veriyor.
	got, err := s.UserByNameFold(ctx, "BOB")
	if err != nil || got != "bob" {
		t.Fatalf("UserByNameFold(BOB) = %q, %v", got, err)
	}
}

/*
 * ⚠️ ÇAKIŞMALI VERİDE GÖÇ, ANLAŞILIR BİR MESAJLA DURMALI.
 *
 * Düz bir CREATE UNIQUE INDEX, hangi hesapların soruna yol açtığını
 * söylemeyen bir hata verirdi ve operatör yükseltmeyi karanlıkta
 * ararken bırakırdı.
 */
func TestMigration019StopsOnCaseCollisions(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	rollbackBelow(ctx, t, s, 19)
	// 019 geri alındı: artık çakışma yaratılabilir.
	if _, err := s.CreateUser(ctx, "bob", "bob@warewave.io", "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, "Bob", "bob2@warewave.io", "bob"); err != nil {
		t.Fatalf("019 öncesi ikinci hesap açılamadı: %v", err)
	}

	err := s.Migrate(ctx)
	if err == nil {
		t.Fatal("çakışmalı veride göç geçti — indeks sessizce oluşmuş olamaz")
	}
	if !strings.Contains(err.Error(), "differ only in letter case") ||
		!strings.Contains(err.Error(), "bob") {
		t.Fatalf("mesaj ne olduğunu ve hangi hesapları söylemiyor: %v", err)
	}
}

/*
 * ⚠️ ÖLÇÜLEN SALDIRININ REGRESYON TESTİ.
 *
 * Demo ortamında uçtan uca çalıştırıldı: "developers" grubundaki sıradan
 * bir çalışan, IdP'de kendi preferred_username'ini "ops" yaptı ve OOB
 * girişini çalıştırdı. postern'in CLI yönetici hesabı — is_admin=true,
 * admin_via='cli' — saldırganın kimliğine geçti.
 *
 * Rol eşlemesi bunu durdurmuyor ve durdurması da beklenmemeli:
 * saldırgan kendi rollerini alıyor, ama hesabın is_admin bayrağı
 * hiçbir eşlemeden gelmiyor.
 */
func TestAdminAccountCannotBeClaimedByUsername(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	// Host'ta açılmış acil durum yöneticisi: SSO'ya hiç girmemiş.
	if _, err := s.CreateUser(ctx, "ops", "ops@warewave.io", "ops"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserAdmin(ctx, "ops", true); err != nil {
		t.Fatal(err)
	}

	// Rol eşlemesi olan bir grup: saldırgan MEŞRU bir çalışan, kendi
	// rolleri var. Onu durduran şey rol eşlemesi olmamalı.
	if _, err := s.CreateRole(ctx, "developer"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddGroupMapping(ctx, "developers", "developer", "test"); err != nil {
		t.Fatal(err)
	}

	_, err := s.ProvisionUser(ctx, ProvisionRequest{
		Username:       "ops",
		Email:          "sizan@warewave.io",
		Groups:         []string{"developers"},
		GroupsResolved: true,
		Issuer:         "https://idp.example/realms/x",
		Subject:        "f4b15fbf-04c0-4c95-8905-ed8c674eb1ff",
	})
	if !errors.Is(err, ErrAdminBindRefused) {
		t.Fatalf("yönetici hesabı ad eşleşmesiyle devralındı (hata: %v)", err)
	}

	// Hesap DOKUNULMAMIŞ olmalı: ne bağlandı, ne yöneticiliği düştü.
	var issuer, subject sql.NullString
	if err := s.db.QueryRowContext(ctx,
		`SELECT idp_issuer, idp_subject FROM users WHERE username='ops';`).
		Scan(&issuer, &subject); err != nil {
		t.Fatal(err)
	}
	if issuer.Valid || subject.Valid {
		t.Fatalf("hesap yine de bağlandı: issuer=%v subject=%v", issuer, subject)
	}
	if u, _ := s.User(ctx, "ops"); !u.Admin {
		t.Fatal("reddedilen deneme hesabın yöneticiliğini düşürdü")
	}
}

/*
 * Ama SIRADAN bir hesabın ilk bağlanması hâlâ çalışmalı.
 *
 * Onboarding'in dayandığı yol bu: CLI ile ya da başka bir yoldan açılmış
 * yetkisiz bir hesap, adı eşleşen ilk kimliğe bağlanıyor. Kapatsaydık
 * her kullanıcı için host'ta bir işlem gerekirdi — ürünün kaçındığı şey.
 */
func TestOrdinaryAccountStillBindsOnFirstSignIn(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "suheda", "suheda@warewave.io", "suheda"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateRole(ctx, "developer"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddGroupMapping(ctx, "developers", "developer", "test"); err != nil {
		t.Fatal(err)
	}

	u, err := s.ProvisionUser(ctx, ProvisionRequest{
		Username:       "suheda",
		Groups:         []string{"developers"},
		GroupsResolved: true,
		Issuer:         "https://idp.example/realms/x",
		Subject:        "11111111-2222-3333-4444-555555555555",
	})
	if err != nil {
		t.Fatalf("sıradan hesabın ilk bağlanması reddedildi: %v", err)
	}
	if u.Name != "suheda" {
		t.Fatalf("kullanıcı = %q", u.Name)
	}
	if via, _ := s.AdminVia(ctx, "suheda"); via != "" {
		t.Fatalf("sıradan hesap yönetici oldu: %q", via)
	}
}

// rollbackBelow, şema sürümü hedefin ALTINA inene kadar geri alır.
//
// Göç testleri "son göç benimki" varsayımına dayanamaz: bir sonraki göç
// eklendiğinde test sessizce BAŞKA bir şeyi geri alır ve yanlış şeyi
// doğrulamaya başlar.
func rollbackBelow(ctx context.Context, t *testing.T, s *Store, target int) {
	t.Helper()
	for {
		v, err := s.SchemaVersion(ctx)
		if err != nil {
			t.Fatalf("SchemaVersion: %v", err)
		}
		if v < target {
			return
		}
		if err := s.Rollback(ctx); err != nil {
			t.Fatalf("Rollback (sürüm %d): %v", v, err)
		}
	}
}

/*
 * ⚠️ AÇIK İZİN, MEŞRU YÖNETİCİNİN YOLUNU AÇMALI — ve TEK KULLANIMLIK.
 *
 * Düz bir red, CLI ile açılmış bir yöneticinin IdP'den ilk girişini
 * tamamen kapatıyordu (beş entegrasyon testi bunu gösterdi). İzin o
 * yolu açıyor; kalıcı olsaydı bir kez açılan ve kimsenin kapatmayı
 * hatırlamadığı bir pencere olurdu.
 */
func TestAllowBindOpensExactlyOneWindow(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "ops", "ops@warewave.io", "ops"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserAdmin(ctx, "ops", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateRole(ctx, "developer"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddGroupMapping(ctx, "developers", "developer", "test"); err != nil {
		t.Fatal(err)
	}

	req := func(subject string) ProvisionRequest {
		return ProvisionRequest{
			Username: "ops", Groups: []string{"developers"}, GroupsResolved: true,
			Issuer: "https://idp.example/realms/x", Subject: subject,
		}
	}

	// İzin yokken: red.
	if _, err := s.ProvisionUser(ctx, req("sub-1")); !errors.Is(err, ErrAdminBindRefused) {
		t.Fatalf("izinsiz bağlama reddedilmedi: %v", err)
	}

	if err := s.AllowIdentityBind(ctx, "ops", time.Now()); err != nil {
		t.Fatal(err)
	}

	// İzinliyken: geçiyor.
	if _, err := s.ProvisionUser(ctx, req("sub-1")); err != nil {
		t.Fatalf("izin verilmiş bağlama reddedildi: %v", err)
	}
	if via, _ := s.AdminVia(ctx, "ops"); via != "cli" {
		t.Fatalf("bağlama yöneticiliğin kaynağını değiştirdi: %q", via)
	}

	// ⚠️ VE PENCERE KAPANDI: ikinci bir kimlik aynı izni kullanamaz.
	// Zaten bağlı olduğu için burada çatışma hatası bekleniyor.
	_, err := s.ProvisionUser(ctx, req("sub-2"))
	if err == nil {
		t.Fatal("ikinci kimlik de hesabı aldı — izin tek kullanımlık değil")
	}
	if !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("hata = %v, ErrIdentityConflict bekleniyordu", err)
	}
}

// Sıradan hesap için izin ANLAMSIZ: onların ilk bağlaması zaten serbest
// ve "izin verdim" demek yanlış bir güvenlik hissi verirdi.
func TestAllowBindIsRefusedForOrdinaryAccounts(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if _, err := s.CreateUser(ctx, "suheda", "s@warewave.io", "suheda"); err != nil {
		t.Fatal(err)
	}
	// Store katmanı izni yazabilir (kısıt CLI'da), ama bağlama zaten
	// izinsiz de çalışıyor olmalı — asıl doğrulanan bu.
	if _, err := s.CreateRole(ctx, "developer"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddGroupMapping(ctx, "developers", "developer", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ProvisionUser(ctx, ProvisionRequest{
		Username: "suheda", Groups: []string{"developers"}, GroupsResolved: true,
		Issuer: "https://idp.example/realms/x", Subject: "sub-ordinary",
	}); err != nil {
		t.Fatalf("sıradan hesabın ilk bağlanması izin istedi: %v", err)
	}
}

/*
 * ⚠️ E-POSTA YOLU DA AYNI KAPIDAN GEÇMELİ.
 *
 * ÖLÇÜLEN AÇIK: IdP kullanıcı adı göndermediğinde giriş yolu
 * doğrulanmış e-postayla hesap buluyor ve hesabı DOĞRUDAN döndürüyordu —
 * ne (issuer, subject) bağına ne yönetici korumasına bakılarak. Yani
 * 011'in ve 020'nin kapattığı iki kapı aynı anda atlanıyordu.
 *
 * Düzeltme ayrı bir kural yazmadı: e-postayla bulunan hesap da
 * ProvisionUser'dan geçiyor. Bu test o kapının gerçekten kapalı
 * olduğunu, yani AYNI çağrının aynı cevabı verdiğini gösteriyor —
 * kullanıcı adı yerine e-postayla bulunmuş olması bir şeyi
 * değiştirmiyor.
 */
func TestEmailMatchedAdminGoesThroughTheSameGate(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "ops", "ops@warewave.io", "ops"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserAdmin(ctx, "ops", true); err != nil {
		t.Fatal(err)
	}

	// Giriş yolunun e-posta dalının yaptığı çağrı.
	_, err := s.ClaimByVerifiedEmail(ctx, "ops@warewave.io",
		"https://idp.example/realms/x", "saldirgan-sub", false)
	if !errors.Is(err, ErrAdminBindRefused) {
		t.Fatalf("e-postayla bulunan yönetici hesabı devralındı: %v", err)
	}

	var subject sql.NullString
	if err := s.db.QueryRowContext(ctx,
		`SELECT idp_subject FROM users WHERE username='ops';`).Scan(&subject); err != nil {
		t.Fatal(err)
	}
	if subject.Valid {
		t.Fatalf("reddedilen deneme yine de bağladı: %q", subject.String)
	}
}

/*
 * ⚠️ AMA E-POSTA YOLU SIRADAN HESAPLAR İÇİN ÇALIŞMAYA DEVAM ETMELİ.
 *
 * İlk taslakta bu dal ProvisionUser'a bağlanmıştı; ProvisionUser
 * grupları çözülemediğinde reddettiği için e-posta yolu HERKES için
 * kapanmıştı — kullanıcı adı göndermeyen IdP'lerde tek giriş yolu.
 * Testin yakaladığı gerileme buydu.
 */
func TestEmailMatchedOrdinaryAccountStillWorks(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.CreateUser(ctx, "suheda", "suheda@warewave.io", "suheda"); err != nil {
		t.Fatal(err)
	}

	u, err := s.ClaimByVerifiedEmail(ctx, "suheda@warewave.io",
		"https://idp.example/realms/x", "sub-suheda", false)
	if err != nil {
		t.Fatalf("sıradan hesap e-postayla giremedi: %v", err)
	}
	if u.Name != "suheda" {
		t.Fatalf("kullanıcı = %q", u.Name)
	}

	// Ve BAĞLANDI: bir dahaki sefere ad ya da e-posta değil, kimlik
	// eşleşecek.
	var subject sql.NullString
	if err := s.db.QueryRowContext(ctx,
		`SELECT idp_subject FROM users WHERE username='suheda';`).Scan(&subject); err != nil {
		t.Fatal(err)
	}
	if subject.String != "sub-suheda" {
		t.Fatalf("bağlanmadı: %q", subject.String)
	}

	// ⚠️ İkinci bir kimlik aynı e-postayla gelemez: hesap artık bağlı.
	if _, err := s.ClaimByVerifiedEmail(ctx, "suheda@warewave.io",
		"https://idp.example/realms/x", "sub-baskasi", false); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("bağlı hesap ikinci kimliğe verildi: %v", err)
	}
}
