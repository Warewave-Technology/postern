package accountlife

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"golang.org/x/crypto/ssh"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/Warewave-Technology/postern/internal/auth"
	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/testdb"
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), testdb.DSN(t))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s
}

func newRunner(t *testing.T, db *store.Store) *Runner {
	t.Helper()
	r := New(db, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	return r
}

// seed, kaynaktan gelen bir hesap açar ve doğrulama damgasını geriye alır.
func seed(t *testing.T, db *store.Store, name string, confirmedAgo time.Duration, ssoOnly bool) {
	t.Helper()
	ctx := context.Background()
	if _, err := db.CreateUser(ctx, name, name+"@warewave.io", name); err != nil {
		t.Fatal(err)
	}
	if ssoOnly {
		if err := db.SetUserSSOOnly(ctx, name, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.ConfirmAccount(ctx, name, time.Now().Add(-confirmedAgo)); err != nil {
		t.Fatal(err)
	}
}

/*
 * ⚠️ ÇÖZÜLEN BOŞLUK: OIDC'de hiçbir iptal yolu olmaması.
 *
 * Kaynağa "bu kişi hâlâ var mı" diye sorulamıyor, dolayısıyla IdP'de
 * kapatılmış bir hesap kişi bir daha girmezse süresiz ayakta kalıyordu.
 * Elimizdeki tek ölçüt, kaynağın onu en son ne zaman doğruladığı.
 */
func TestStaleSourceAccountIsDeactivated(t *testing.T) {
	ctx := context.Background()
	db := newStore(t)

	seed(t, db, "ayrilan", 60*24*time.Hour, true)
	seed(t, db, "calisan", 1*time.Hour, true)

	rep := newRunner(t, db).RunOnce(ctx)
	if rep.Skipped != "" {
		t.Fatalf("koşu atlandı: %s", rep.Skipped)
	}

	if st, _, _ := db.AccountState(ctx, "ayrilan"); st != store.StateInactive {
		t.Fatalf("süresi dolmuş hesap = %q, inactive bekleniyordu", st)
	}
	if st, _, _ := db.AccountState(ctx, "calisan"); st != store.StateActive {
		t.Fatalf("taze hesap = %q, active bekleniyordu", st)
	}
}

/*
 * ⚠️ YEREL (OTOMASYON) HESAPLARI KAPSAM DIŞI.
 *
 * CI ve servis hesapları hiçbir kaynağa sorulamıyor; "doğrulanmamış
 * olmaları" normal. Onları da sayan bir sayaç, her otomasyon hattını
 * süre dolunca keserdi — ve o kesinti, kimsenin giriş yapmadığı için
 * fark edilmesi en zor olan.
 */
func TestLocalAccountsAreNeverDeactivated(t *testing.T) {
	ctx := context.Background()
	db := newStore(t)

	// sso_only DEĞİL ve dizine bağlı değil: yerel otomasyon hesabı.
	seed(t, db, "ci-bot", 365*24*time.Hour, false)

	newRunner(t, db).RunOnce(ctx)

	if st, _, _ := db.AccountState(ctx, "ci-bot"); st != store.StateActive {
		t.Fatalf("yerel otomasyon hesabı = %q — kaynağa sorulamayan hesap "+
			"süre dolduğu için kapatıldı", st)
	}
}

/*
 * ⚠️ TEK GİRİŞ HESABI GERİ AÇIYOR.
 *
 * Pasifleşme "kaynak bir süredir doğrulamadı" demek; kaynak yeniden
 * doğruladığı anda sebep ortadan kalkıyor. Elle müdahale gerektirseydi
 * tatilden dönen herkes yöneticiye başvururdu — ve o yük, korumanın
 * kapatılmasıyla sonuçlanırdı.
 */
func TestSigningInReactivates(t *testing.T) {
	ctx := context.Background()
	db := newStore(t)
	seed(t, db, "donen", 60*24*time.Hour, true)

	newRunner(t, db).RunOnce(ctx)
	if st, _, _ := db.AccountState(ctx, "donen"); st != store.StateInactive {
		t.Fatalf("kurulum: %q", st)
	}

	if err := db.ConfirmAccount(ctx, "donen", time.Now()); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := db.AccountState(ctx, "donen"); st != store.StateActive {
		t.Fatalf("giriş sonrası = %q, active bekleniyordu", st)
	}
}

/*
 * ⚠️ SİLİNMİŞ HESAP GİRİŞLE GERİ GELMEZ.
 *
 * Orada uzun bir sessizlik (ya da bir insan kararı) var; onu bir girişin
 * sessizce bozması, "silindi" demenin anlamını yok ederdi. Geri dönüş
 * elle ve görünür.
 */
func TestDeletedAccountDoesNotComeBackOnItsOwn(t *testing.T) {
	ctx := context.Background()
	db := newStore(t)
	seed(t, db, "cok-eski", 400*24*time.Hour, true)

	newRunner(t, db).RunOnce(ctx) // aktif → pasif
	newRunner(t, db).RunOnce(ctx) // pasif → silinmiş

	if st, _, _ := db.AccountState(ctx, "cok-eski"); st != store.StateDeleted {
		t.Fatalf("durum = %q, deleted bekleniyordu", st)
	}
	if err := db.ConfirmAccount(ctx, "cok-eski", time.Now()); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := db.AccountState(ctx, "cok-eski"); st != store.StateDeleted {
		t.Fatalf("giriş silinmiş hesabı geri açtı: %q", st)
	}
}

/*
 * ⚠️ PATLAMA YARIÇAPI: TOPLU KAPATMA HİÇ YAPILMAZ.
 *
 * Sistem saati ileri kayarsa ya da bir göç damgaları boşaltırsa herkes
 * bir anda "süresi dolmuş" görünür. Yarısını uygulamak, hem hasarı
 * verip hem sebebi gizlemek olurdu.
 */
func TestBlastRadiusGuardStopsMassDeactivation(t *testing.T) {
	ctx := context.Background()
	db := newStore(t)

	for i := 0; i < 10; i++ {
		seed(t, db, "kisi"+string(rune('a'+i)), 60*24*time.Hour, true)
	}

	rep := newRunner(t, db).RunOnce(ctx)
	if rep.Skipped == "" {
		t.Fatalf("koruma devreye girmedi: %d hesap kapatıldı", len(rep.Deactivated))
	}
	if len(rep.Deactivated) != 0 {
		t.Fatalf("koruma devredeyken yine de %d hesap kapatıldı", len(rep.Deactivated))
	}
	for i := 0; i < 10; i++ {
		name := "kisi" + string(rune('a'+i))
		if st, _, _ := db.AccountState(ctx, name); st != store.StateActive {
			t.Fatalf("%s = %q", name, st)
		}
	}
}

// TTL "0" yazılarak KAPATILABİLMELİ: bilinçli bir karar olarak.
func TestZeroTTLDisablesTheLoop(t *testing.T) {
	ctx := context.Background()
	db := newStore(t)
	seed(t, db, "eski", 400*24*time.Hour, true)

	if err := db.SetSetting(ctx, auth.KeyConfirmTTL, "0", false, "test"); err != nil {
		t.Fatal(err)
	}
	newRunner(t, db).RunOnce(ctx)

	if st, _, _ := db.AccountState(ctx, "eski"); st != store.StateActive {
		t.Fatalf("TTL kapalıyken hesap kapatıldı: %q", st)
	}
}

/*
 * ⚠️ PURGE ADI SERBEST BIRAKIR AMA SATIRI SİLMEZ.
 *
 * Satır silinseydi, denetim kaydındaki "ayse.yilmaz" metinlerinin kime
 * ait olduğu cevapsız kalırdı — ve aynı adı alan yeni kişiyle
 * karışırdı. Kalan satır, "o ad şu tarihte boşaltıldı" sorusunun cevabı.
 */
func TestPurgeFreesTheNameAndKeepsTheRecord(t *testing.T) {
	ctx := context.Background()
	db := newStore(t)

	seed(t, db, "ayse.yilmaz", time.Hour, true)
	if err := db.SetAccountState(ctx, "ayse.yilmaz", store.StateDeleted); err != nil {
		t.Fatal(err)
	}

	res, err := db.PurgeAccount(ctx, "ayse.yilmaz", time.Now())
	if err != nil {
		t.Fatalf("PurgeAccount: %v", err)
	}
	if res.FormerUsername != "ayse.yilmaz" {
		t.Fatalf("eski ad kaydedilmedi: %q", res.FormerUsername)
	}

	// ⚠️ AD ARTIK SERBEST: aynı adla yeni bir kişi açılabilmeli.
	if _, err := db.CreateUser(ctx, "ayse.yilmaz", "yeni@warewave.io", "ayse"); err != nil {
		t.Fatalf("purge sonrası ad hâlâ dolu: %v", err)
	}

	// ⚠️ VE ESKİ SATIR DURUYOR: geçmiş okunabilir kalmalı.
	purged, err := db.PurgedAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(purged) != 1 || purged[0].FormerUsername != "ayse.yilmaz" {
		t.Fatalf("purge izi kaybolmuş: %+v", purged)
	}
	if purged[0].PurgedAt.IsZero() {
		t.Fatal("purge tarihi yazılmamış — 'ne zaman boşaltıldı' cevapsız")
	}
}

/*
 * ⚠️ YALNIZCA 'deleted' HESAPLAR PURGE EDİLEBİLİR.
 *
 * Aktif bir hesabın adını serbest bırakmak, o kişi hâlâ kullanıyorken
 * kimliğini elinden almak olurdu. Purge yaşam döngüsünün son adımı,
 * bir kısayol değil.
 */
func TestPurgeRefusesLiveAccounts(t *testing.T) {
	ctx := context.Background()
	db := newStore(t)
	seed(t, db, "calisan", time.Hour, true)

	if _, err := db.PurgeAccount(ctx, "calisan", time.Now()); err == nil {
		t.Fatal("aktif hesap purge edildi")
	}
	if err := db.SetAccountState(ctx, "calisan", store.StateInactive); err != nil {
		t.Fatal(err)
	}
	if _, err := db.PurgeAccount(ctx, "calisan", time.Now()); err == nil {
		t.Fatal("pasif hesap purge edildi — önce silinmiş olmalı")
	}
}

/*
 * ⚠️ PURGE TANIMLAYICILARIN HEPSİNİ SERBEST BIRAKMALI.
 *
 * Biri kalırsa geri dönen kişi kendi hesabını açamaz: anahtarı
 * (key_blob küresel PRIMARY KEY), kimlik bağı (benzersiz indeks) ya da
 * e-postası (benzersiz) ölü bir satırda takılı kalır.
 */
func TestPurgeReleasesEveryIdentifier(t *testing.T) {
	ctx := context.Background()
	db := newStore(t)

	seed(t, db, "donen", time.Hour, true)
	if err := db.BindDirIdentity(ctx, "donen",
		"f74a3e90-373a-1041-92eb-dbd441920715"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetAccountState(ctx, "donen", store.StateDeleted); err != nil {
		t.Fatal(err)
	}
	if _, err := db.PurgeAccount(ctx, "donen", time.Now()); err != nil {
		t.Fatal(err)
	}

	/*
	 * Ad, E-POSTA ve kimlik bağı birlikte serbest kalmalı: üçü de
	 * benzersizlik taşıyor ve biri takılı kalırsa geri dönen kişi kendi
	 * hesabını açamaz.
	 *
	 * Tek bir CreateUser üçünü birden sınıyor — aynı ad, aynı e-posta.
	 */
	if _, err := db.CreateUser(ctx, "donen", "donen@warewave.io", "donen"); err != nil {
		t.Fatalf("ad ya da e-posta ölü satırda takılı kaldı: %v", err)
	}
	if err := db.BindDirIdentity(ctx, "donen",
		"f74a3e90-373a-1041-92eb-dbd441920715"); err != nil {
		t.Fatalf("kimlik ölü satırda takılı kaldı: %v", err)
	}

}

/*
 * ⚠️ ANAHTAR DA SERBEST KALMALI.
 *
 * key_blob KÜRESEL PRIMARY KEY: bir anahtar yalnızca tek bir hesapta
 * olabilir. Purge edilmiş bir satırda kalan anahtar, aynı anahtarı
 * KİMSENİN bir daha ekleyememesi demek — geri dönen kişi kendi
 * anahtarını bile kullanamaz.
 */
func TestPurgeReleasesTheKey(t *testing.T) {
	ctx := context.Background()
	db := newStore(t)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	seed(t, db, "giden", time.Hour, true)
	if err := db.AddPublicKey(ctx, "giden", sshKey.Marshal(), "laptop"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetAccountState(ctx, "giden", store.StateDeleted); err != nil {
		t.Fatal(err)
	}

	res, err := db.PurgeAccount(ctx, "giden", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if res.Keys != 1 {
		t.Fatalf("serbest bırakılan anahtar = %d, 1 bekleniyordu", res.Keys)
	}

	// Aynı anahtar yeni bir hesaba eklenebilmeli.
	if _, err := db.CreateUser(ctx, "yeni", "yeni@warewave.io", "yeni"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddPublicKey(ctx, "yeni", sshKey.Marshal(), "laptop"); err != nil {
		t.Fatalf("anahtar ölü satırda takılı kaldı: %v", err)
	}
}

/*
 * ⚠️ PURGE EDİLMİŞ SATIR KULLANICI LİSTESİNDE OLMAMALI.
 *
 * O bir KAYIT, bir kullanıcı değil: adı serbest bırakılmış, anahtarları
 * ve rolleri alınmış, giriş yapamayan bir iz. Listede durması hem
 * gürültü hem yanıltıcı — "purged:9bf1…" diye bir hesap yok. İzin
 * kendisi PurgedAccounts'tan okunuyor.
 */
func TestPurgedRowsAreNotUsers(t *testing.T) {
	ctx := context.Background()
	db := newStore(t)

	seed(t, db, "giden", time.Hour, true)
	seed(t, db, "kalan", time.Hour, true)
	if err := db.SetAccountState(ctx, "giden", store.StateDeleted); err != nil {
		t.Fatal(err)
	}
	if _, err := db.PurgeAccount(ctx, "giden", time.Now()); err != nil {
		t.Fatal(err)
	}

	users, err := db.Users(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if u.Name == "giden" || len(u.Name) > 7 && u.Name[:7] == "purged:" {
			t.Fatalf("purge edilmiş satır kullanıcı listesinde: %q", u.Name)
		}
	}
	if len(users) != 1 || users[0].Name != "kalan" {
		t.Fatalf("liste = %v", users)
	}

	// ⚠️ Ama İZ DURUYOR: denetimin cevabı oradan geliyor.
	purged, err := db.PurgedAccounts(ctx)
	if err != nil || len(purged) != 1 || purged[0].FormerUsername != "giden" {
		t.Fatalf("purge izi kaybolmuş: %+v (%v)", purged, err)
	}
}

/*
 * ⚠️ SİLME GEÇİŞİNİN DE TAVANI OLMALI.
 *
 * Pasifleştirme guard'dan geçiyordu, "silindi" damgası hiç sormuyordu.
 * Oysa ikisi aynı arızanın iki adımı: yanlış bir saat ya da yanlış bir
 * TTL önce herkesi pasifleştirir, bir sonraki koşuda hepsini silinmiş
 * işaretler. Korumayı yalnızca ilk adıma koymak, ikinciyi serbest
 * bırakıyordu — ve ikincisi hesabın adını da kullanılamaz hâle getiren
 * adım.
 */
func TestBlastRadiusGuardStopsMassDeletion(t *testing.T) {
	ctx := context.Background()
	db := newStore(t)

	// Hepsi ZATEN pasif ve silme eşiğini aşmış: pasifleştirme geçişi
	// bu koşuda hiçbir şey yapmayacak, sıra doğrudan silmede.
	for i := range 10 {
		name := "kisi" + string(rune('a'+i))
		seed(t, db, name, 400*24*time.Hour, true)
		if err := db.SetAccountState(ctx, name, store.StateInactive); err != nil {
			t.Fatal(err)
		}
	}

	rep := newRunner(t, db).RunOnce(ctx)
	if rep.Skipped == "" {
		t.Fatalf("koruma devreye girmedi: %d hesap silinmiş işaretlendi", len(rep.Deleted))
	}
	if len(rep.Deleted) != 0 {
		t.Fatalf("koruma devredeyken %d hesap silinmiş işaretlendi", len(rep.Deleted))
	}
	for i := range 10 {
		name := "kisi" + string(rune('a'+i))
		if st, _, _ := db.AccountState(ctx, name); st != store.StateInactive {
			t.Fatalf("%s = %q — silme geçişi tavanı aşarak çalıştı", name, st)
		}
	}
}

/*
 * ⚠️ SAYAMAYAN GUARD "SINIR İÇİNDE" DEMEMELİ.
 *
 * Koşul `if err != nil || total == 0 { return true, "" }` idi: sayım
 * başarısız olduğunda koruma kendini kapatıyordu — tam da bir şeylerin
 * ters gittiği anda, yani var olma sebebi olan durumda.
 */
func TestBlastRadiusGuardRefusesWhenItCannotCount(t *testing.T) {
	db := newStore(t)
	r := newRunner(t, db)

	// Kapalı bir bağlantı üzerinden sayım yapılamaz.
	db.Close()

	ok, why := r.withinBlastRadius(context.Background(), 5)
	if ok {
		t.Fatal("SAYIM ÇÖKTÜ AMA GUARD 'SINIR İÇİNDE' DEDİ")
	}
	if why == "" {
		t.Error("sebep söylenmiyor")
	}
}
