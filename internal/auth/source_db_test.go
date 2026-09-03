package auth_test

// ⚠️ AYRI PAKET (auth_test): internal/auth artık internal/store'u
// kullanıyor, dolayısıyla store'un kendi testlerinden auth'a bakmak
// döngü olurdu. Bu testler DIŞARIDAN, ikisini birlikte kullanan bir
// çağıranın gördüğü yerden bakıyor.

import (
	"context"
	"testing"

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

/*
 * ⚠️ auth.source SAKLANMAMIŞSA TÜRETİLİR — ve türetme, yükseltmenin
 * çalışan bir kurulumu kapatmamasını sağlıyor.
 *
 * Bu ayar yokken kurulmuş, OIDC yapılandırılmış bir dağıtımda kapı zaten
 * OIDC'ydi. Körlemesine "local" demek, yükseltmeden sonra kimsenin
 * giremediği bir panel bırakmak olurdu.
 */
func TestActiveLoginSourceDerivesWhenUnset(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	src, stored, err := auth.ActiveLoginSource(ctx, s, true)
	if err != nil || stored || src != auth.SourceOIDC {
		t.Fatalf("OIDC kurulu, ayar yok → (%q, stored=%v, %v); oidc bekleniyordu",
			src, stored, err)
	}

	src, stored, err = auth.ActiveLoginSource(ctx, s, false)
	if err != nil || stored || src != auth.SourceLocal {
		t.Fatalf("OIDC yok, ayar yok → (%q, stored=%v, %v); local bekleniyordu",
			src, stored, err)
	}

	// Saklanan değer türetmeyi EZER: operatörün seçimi, config
	// dosyasından yapılan bir çıkarımdan önce gelir.
	if err := s.SetSetting(ctx, auth.KeyLoginSource, "local", false, "test"); err != nil {
		t.Fatal(err)
	}
	src, stored, err = auth.ActiveLoginSource(ctx, s, true)
	if err != nil || !stored || src != auth.SourceLocal {
		t.Fatalf("saklanan 'local', OIDC kurulu → (%q, stored=%v, %v)", src, stored, err)
	}
}

/*
 * ⚠️ SAKLANAN DEĞER BOZUKSA HATA — sessiz bir varsayılan DEĞİL.
 *
 * Varsayılana düşmek, operatörün seçtiğini sandığı kapıdan BAŞKA birini
 * açardı ve bunu hiçbir yerde söylemezdi.
 */
func TestActiveLoginSourceRefusesGarbage(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	if err := s.SetSetting(ctx, auth.KeyLoginSource, "odic", false, "test"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := auth.ActiveLoginSource(ctx, s, true); err == nil {
		t.Fatal("bozuk kaynak adı kabul edildi — kapı sessizce başkası olurdu")
	}
}
