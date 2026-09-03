package record

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"
)

/*
 * ⚠️ SİLİNEN KAYIT, ARŞİVLEME KAPALIYKEN DE DENETİM GERİ ÇAĞRISINA
 * ULAŞMALI.
 *
 * ÖLÇÜLEN ARIZA: silme geri çağrısı yalnızca WithArchive ile takılıyordu,
 * yani arşivleyici varsa. Arşivleme varsayılan KAPALI olduğu için
 * sıradan kurulumda budayıcı kanıt siliyor ve denetim defterine hiçbir
 * şey yazmıyordu — oysa panel kayıp bir kaydın sebebini "admin log
 * söyler" diye anlatıyor. WithAuditLog artık arşivlemeden bağımsız.
 */
func TestPrunerAuditLogFiresWithoutArchiver(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "2020-01-01", "silinecek.cast", 200*24*time.Hour, 40)

	p := NewPruner(dir, 90*24*time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.now = func() time.Time { return time.Now() }

	var logged []string
	// ⚠️ WithArchive HİÇ ÇAĞRILMIYOR: arşivleme kapalı senaryosu tam
	// olarak bu. Eskiden geri çağrı buraya hiç takılamıyordu.
	p = p.WithAuditLog(func(_ context.Context, ids []string) {
		logged = append(logged, ids...)
	})

	res := p.RunOnce(context.Background())
	if res.Files != 1 {
		t.Fatalf("silinen dosya = %d, 1 bekleniyordu", res.Files)
	}
	if len(logged) != 1 || logged[0] != "silinecek" {
		t.Errorf("denetim geri çağrısına ulaşan = %v; [silinecek] bekleniyordu — "+
			"arşivleme kapalıyken silme deftere yazılmıyor", logged)
	}
	if _, err := os.Stat(dir + "/2020-01-01/silinecek.cast"); !os.IsNotExist(err) {
		t.Errorf("dosya gerçekten silinmemiş: %v", err)
	}
}
