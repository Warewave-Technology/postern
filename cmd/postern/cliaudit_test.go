package main

import (
	"context"
	"strings"
	"testing"

	"github.com/warewave/postern/internal/ldap"
	"github.com/warewave/postern/internal/store"
)

// ledger, deftere düşmüş eylemleri döner.
func ledger(t *testing.T, e *testEnv) []store.AdminLogEntry {
	t.Helper()
	rows, err := e.db.AdminLog(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func hasAction(rows []store.AdminLogEntry, action string) *store.AdminLogEntry {
	for i, r := range rows {
		if r.Action == action {
			return &rows[i]
		}
	}
	return nil
}

/*
 * ⚠️ CLI'IN YÖNETİCİ VERME KOLU DEFTERE HİÇBİR ŞEY YAZMIYORDU.
 *
 * audit.go'nun kendi gerekçesi şu: "CLI'dan yapılan HİÇBİR değişiklik
 * admin_log'a düşmüyordu ... Panelden yapılan her değişiklik
 * denetlenirken, EN AYRICALIKLI OLANI denetlenmiyordu." O düzeltme
 * user/role/target'a ulaşmış ve orada durmuş.
 *
 * `settings set --key ldap.admin_group` ise tam olarak o kol: eski
 * gruptan gelen bütün yönetici yetkilerini düşürüyor, yeni grubun
 * üyeleri bir sonraki girişte yönetici oluyor.
 *
 * ÖLÇÜLDÜ: meşru yöneticiyi düşürüp saldırganın grubunu yönetici yapan
 * ve sonra ayarı geri alan zincir, hiçbir yerde tek satır iz
 * bırakmıyordu — üstelik `postern log` ardından "the audit trail is
 * empty" diyor. settings.updated_by yalnızca ŞU ANKİ değeri taşıyor;
 * geri alma onu da üzerine yazıyor.
 */
func TestAdminGroupChangeReachesTheLedger(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	if _, err := e.db.CreateUser(ctx, "ayse", "ayse@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}
	if err := e.db.SetSetting(ctx, ldap.KeyAdminGroup, "sysadmins", false, "test"); err != nil {
		t.Fatal(err)
	}
	// Ayşe yöneticiliğini GRUPTAN almış olsun.
	if _, _, err := e.db.ApplyAdminGroup(ctx, []string{"ayse"}); err != nil {
		t.Fatal(err)
	}

	out, err := e.run(t, newRootCmd(), "settings", "set",
		"--key", ldap.KeyAdminGroup, "--value", "yeni-grup")
	if err != nil {
		t.Fatalf("komut düştü: %v\n%s", err, out)
	}
	if !strings.Contains(out, "lost administrator") {
		t.Fatalf("kurgu tutmadı: kimse yöneticiliğini kaybetmemiş\n%s", out)
	}

	rows := ledger(t, e)

	if hasAction(rows, "setting.set") == nil {
		t.Errorf("ayar değişikliği deftere düşmedi; defter: %+v", rows)
	}

	/*
	 * ⚠️ İKİNCİ SATIR AYRI BİR SORUYA CEVAP VERİYOR: "ayar değişti"
	 * ile "kimin yöneticiliği düştü" farklı şeyler ve olay
	 * incelemesinde ikincisi aranıyor. Liste eskiden yalnızca komutu
	 * koşanın terminaline yazılıyordu.
	 */
	grp := hasAction(rows, "admin_group.set")
	if grp == nil {
		t.Fatalf("yönetici grubu değişimi deftere düşmedi; defter: %+v", rows)
	}
	if !strings.Contains(grp.Details, "ayse") {
		t.Errorf("defter kimin yöneticiliğinin düştüğünü söylemiyor: %q", grp.Details)
	}
	if grp.Via != "cli" {
		t.Errorf("kapı %q yazılmış, cli bekleniyordu", grp.Via)
	}
}

/*
 * ⚠️ EŞLEME EKLEME VE KALDIRMA DA DEFTERE DÜŞMELİ.
 *
 * Bir eşleme, koca bir IdP grubuna rol vermek demek. Panelden
 * yapıldığında deftere düşüyor; CLI'dan hiçbir iz kalmıyordu.
 * Kaldırma daha kötüsü: satır silindiği için created_by kalıntısı da
 * yok oluyor, yani eşlemenin var olduğuna dair hiçbir kayıt kalmıyor.
 */
func TestMappingChangesReachTheLedger(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	if _, err := e.db.CreateRole(ctx, "ops"); err != nil {
		t.Fatal(err)
	}

	if out, err := e.run(t, newRootCmd(), "mapping", "add",
		"--group", "developers", "--role", "ops"); err != nil {
		t.Fatalf("mapping add düştü: %v\n%s", err, out)
	}
	if r := hasAction(ledger(t, e), "mapping.create"); r == nil {
		t.Errorf("eşleme ekleme deftere düşmedi; defter: %+v", ledger(t, e))
	} else if !strings.Contains(r.Details, "ops") {
		t.Errorf("hangi rol verildiği yazılmamış: %q", r.Details)
	}

	if out, err := e.run(t, newRootCmd(), "mapping", "remove",
		"--group", "developers", "--role", "ops"); err != nil {
		t.Fatalf("mapping remove düştü: %v\n%s", err, out)
	}
	if r := hasAction(ledger(t, e), "mapping.delete"); r == nil {
		t.Errorf("eşleme KALDIRMA deftere düşmedi; satır silindiği için "+
			"başka hiçbir iz kalmıyor. defter: %+v", ledger(t, e))
	}
}

/*
 * ⚠️ AYARIN DEĞERİ DEFTERE YAZILMAMALI, ANAHTARI YAZILMALI.
 *
 * Bu komuttan sırlar da geçiyor (oidc.client_secret gibi) ve defter
 * panelde okunuyor: değeri oraya koymak, şifrelenmiş tutulan şeyi düz
 * metne çevirmek olurdu. Kural sır olmayan anahtarlar için de aynı —
 * ayrım kodda bir `if`e bağlı kalırsa, yeni bir sır anahtarı eklendiği
 * gün sessizce sızardı.
 */
func TestSettingValueStaysOutOfTheLedger(t *testing.T) {
	e := newEnv(t)

	const value = "AYIRT-EDICI-DEGER-42"
	out, err := e.run(t, newRootCmd(), "settings", "set",
		"--key", "sync.interval", "--value", value)
	// Değer geçersiz olabilir; ölçtüğümüz şey deftere ne yazıldığı.
	_ = err
	_ = out

	rows := ledger(t, e)
	for _, r := range rows {
		if strings.Contains(r.Details, value) || strings.Contains(r.Entity, value) {
			t.Fatalf("ayarın DEĞERİ deftere yazıldı: %+v", r)
		}
	}
	if r := hasAction(rows, "setting.set"); r == nil {
		t.Error("ayar değişikliği hiç deftere düşmedi")
	} else if r.Entity != "sync.interval" {
		t.Errorf("hangi anahtarın değiştiği yazılmamış: entity=%q", r.Entity)
	}
}
