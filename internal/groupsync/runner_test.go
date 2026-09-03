package groupsync

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/warewave/postern/internal/auth"
	"github.com/warewave/postern/internal/ldap"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

/*
 * ⚠️ VARLIK DAMGASI YAZILAMADIĞINDA BUNU ÖĞRENEBİLMELİYİZ.
 *
 * Runner, MarkDirectorySeen ve MarkDirectoryMissing'i çıplak
 * çağırıyordu; ikisi de hata döndürüyor ve ikisi de atılıyordu. Bedeli
 * sessiz ve gecikmeli, ama bir YETKİ kararına dönüşüyor:
 *
 *   missing_since yazılamazsa bir sonraki koşu kişiyi "az önce
 *   kayboldu" sanıyor — grace penceresi her koşuda baştan başlıyor ve
 *   iptal hiç gelmiyor.
 *
 *   last_seen yazılamazsa dizinde DURAN biri doğrulanmamış sayılıp
 *   hesap yaşam döngüsü tarafından pasifleştirilebiliyor.
 *
 * Düzeltmenin dayandığı ön kabul bu testin ölçtüğü şey: depo bu
 * arızayı gerçekten BİLDİRİYOR. Bildirmeseydi runner'ın saymasının
 * hiçbir anlamı olmazdı — sessiz bir hatayı sayamazsın.
 */
func TestPresenceStampsReportFailure(t *testing.T) {
	ctx := context.Background()
	db := syncStore(t)

	// Kapalı bir bağlantı üzerinden yazılamaz.
	db.Close()

	if err := db.MarkDirectorySeen(ctx, "ayse", time.Now()); err == nil {
		t.Error("MarkDirectorySeen arızayı yuttu: runner onu sayamaz")
	}
	if err := db.MarkDirectoryMissing(ctx, "ayse", time.Now()); err == nil {
		t.Error("MarkDirectoryMissing arızayı yuttu: runner onu sayamaz")
	}
}

/*
 * ⚠️ SAYI SÜREÇTEN ÇIKMALI — ve çıkmıyordu.
 *
 * Buradaki test bir struct alanına 3 yazıp 3 okuyordu: alanın VAR
 * olduğunu ölçüyordu, işe yaradığını değil. Ölçüldü — üç damga
 * yazılamazken rapor, sync_runs satırı, `postern sync run` çıktısı ve
 * panel, dördü de koşuyu tertemiz "ok" gösteriyordu. Sayıyı yalnızca
 * log satırı taşıyordu ve log, "dün gece sync sağlıklı mıydı"
 * sorusunun sorulduğu yer değil.
 *
 * Bu test onun yerine kabloyu ölçüyor: damga yazılamadığında koşunun
 * SEBEBİ sayıyı söylüyor mu, ve o sebep sync_runs satırına düşüyor mu.
 *
 * Damgalar, yazdıkları sütun düşürülerek bozuluyor: bağlantıyı
 * kapatmak koşunun tamamını düşürürdü ve test ölçmek istediği yola
 * hiç gelmezdi.
 */
func TestStampFailuresReachTheRunRecord(t *testing.T) {
	ctx := context.Background()
	db, dsn := syncStoreDSN(t)

	if _, err := db.CreateUser(ctx, "ayse", "ayse@warewave.io", "ayse"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetUserSSOOnly(ctx, "ayse", true); err != nil {
		t.Fatal(err)
	}

	dropColumn(t, dsn, "users", "dir_last_seen_at")

	r := NewRunner(db, func(context.Context) (Directory, error) {
		return presentDirectory{}, nil
	}, Config{}, testLogger())

	rep, err := r.RunOnce(ctx, "test")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	if rep.StampErrors == 0 {
		t.Fatal("damga yazılamadı ama sayılmadı — testin kurduğu arıza oluşmamış")
	}
	if !strings.Contains(rep.Reason, "presence stamp") {
		t.Errorf("koşunun sebebi damga arızasını söylemiyor: %q — "+
			"operatör `sync run` çıktısında ve panelde tertemiz bir "+
			"koşu görür", rep.Reason)
	}

	// ⚠️ ASIL KABLO: sebep SAKLANMALI. Yalnızca dönen raporda olsaydı,
	// koşuyu başlatan kişi görürdü ve ertesi sabah bakan kimse görmezdi.
	runs, err := db.SyncRuns(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) == 0 {
		t.Fatal("koşu satırı yazılmamış")
	}
	if !strings.Contains(runs[0].Reason, "presence stamp") {
		t.Errorf("sync_runs satırı sebebi taşımıyor: %q", runs[0].Reason)
	}
}

// presentDirectory, herkesi dizinde DURUYOR diye bildirir: damga yolu
// ancak PresencePresent'ta MarkDirectorySeen'e giriyor.
type presentDirectory struct{}

func (presentDirectory) Probe(context.Context) error { return nil }
func (presentDirectory) Lookup(context.Context, auth.Identity) (ldap.LookupResult, error) {
	return ldap.LookupResult{Presence: ldap.PresencePresent}, nil
}

// dropColumn, tek bir yazmanın çökmesini sağlar. Ayrı bir bağlantı
// açıyor: Store ham SQL yüzeyi vermiyor ve vermemeli.
func dropColumn(t *testing.T, dsn, table, col string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("ALTER TABLE " + table + " DROP COLUMN " + col + ";"); err != nil {
		t.Fatalf("DROP COLUMN %s.%s: %v", table, col, err)
	}
}
