package groupsync

import (
	"context"
	"testing"
	"time"
)

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
 * Rapor, yazılamayan damga sayısını taşıyabilmeli.
 *
 * ⚠️ Alan olmadan koşu "ok" derken eksik olduğunu söyleyemezdi: bir
 * senkronizasyon koşusunun "yaptım" ile "bir kısmını kaydedemedim"i
 * ayırması gerekiyor.
 */
func TestReportCarriesStampErrors(t *testing.T) {
	var rep Report
	if rep.StampErrors != 0 {
		t.Fatalf("sıfır değer bozuk: %d", rep.StampErrors)
	}
	rep.StampErrors = 3
	if rep.StampErrors != 3 {
		t.Fatal("alan taşımıyor")
	}
}
