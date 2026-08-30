package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
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

	// 018'i geri al, eski dünyayı kur, sonra tekrar uygula.
	if err := s.Rollback(ctx); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
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

	if err := s.Rollback(ctx); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
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
