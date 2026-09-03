package httpapi

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/Warewave-Technology/postern/internal/auth"
	"github.com/Warewave-Technology/postern/internal/store"
	"github.com/Warewave-Technology/postern/internal/testdb"
)

/*
 * ⚠️ BU PAKETTE GERÇEK BİR VERİTABANI KOŞUM TAKIMI YOKTU — VE EKSİKLİĞİ
 * ÖLÇÜLDÜ.
 *
 * httpapi testlerinin hepsi quietServer üzerinden koşuyordu: store nil,
 * yani veritabanına dokunan HER uç sınanamıyordu. Sonucu, bir uç
 * gövdesindeki alanın elle yanlış bir sabite çevrilip bütün Go
 * paketinin yeşil kalması: `truncated` alanı `false`'a sabitlendiğinde
 * httpapi, store ve cmd testlerinin tamamı geçiyordu.
 *
 * Panel testleri bu boşluğu kapatmıyor: onlar `api` katmanını mock'layıp
 * kendi mock'larını doğruluyor, yani sunucunun gerçekten ne döndürdüğünü
 * hiç görmüyorlar.
 *
 * Docker gerekiyor (testdb testcontainers kullanıyor) ve bu paketin
 * geri kalanı için gerekmiyor — o yüzden yardımcı ayrı dosyada duruyor
 * ve yalnızca ona ihtiyaç duyan testler çağırıyor.
 */
// migratedStore, göç edilmiş boş bir Store döner — üretim New yapıcısını
// kendi kuran testler için.
func migratedStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, testdb.DSN(t))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("store.Migrate: %v", err)
	}
	return db
}

func dbServer(t *testing.T) (*Server, *store.Store) {
	s, db, _ := dbServerDSN(t)
	return s, db
}

// dbServerDSN, aynısını DSN'i de vererek döner: bir testin tek bir
// sorguyu düşürmek için ikinci bir bağlantı açması gerekebiliyor.
func dbServerDSN(t *testing.T) (*Server, *store.Store, string) {
	t.Helper()

	ctx := context.Background()
	dsn := testdb.DSN(t)
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("store.Migrate: %v", err)
	}

	s := &Server{
		store:  db,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		// loginSource OIDC yapılandırmasının VARLIĞINI soruyor; boş bir
		// holder "yapılandırılmamış" demek ve testlerin çoğu için
		// doğru başlangıç.
		oidc:        auth.NewOIDCHolder(),
		webSessions: auth.NewWebSessions(),
	}
	return s, db, dsn
}
