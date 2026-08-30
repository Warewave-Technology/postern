package accountlife

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/store"
	"github.com/warewave/postern/internal/testdb"
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
