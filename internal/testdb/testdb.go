// Package testdb, testler için gerçek bir PostgreSQL örneği sağlar.
//
// NEDEN GERÇEK VERİTABANI: postern'in tek motoru PostgreSQL. Sahte bir
// katmana ya da başka bir motora karşı test etmek, YANLIŞ ŞEYİ test
// etmek olurdu — bu paketin kurulma sebebi olan hataların çoğu
// (ON CONFLICT hedefi, kısıt ihlali kodları, harf duyarsız indeksler)
// yalnızca gerçek sunucuda ortaya çıkar.
//
// MALİYET: testler Docker ister. Karşılığında `go test ./...` yeşil
// yandığında bunun bir anlamı oluyor.
//
// YALITIM: süreç başına TEK konteyner, test başına AYRI ŞEMA. Ayrı
// veritabanı da olurdu ama CREATE DATABASE çok daha pahalı; şema
// yalıtımı aynı garantiyi ucuza veriyor.
package testdb

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

const image = "postgres:17-alpine"

var (
	once      sync.Once
	sharedDSN string
	startErr  error
	counter   struct {
		sync.Mutex
		n int
	}
)

// start, süreçteki İLK çağrıda konteyneri ayağa kaldırır.
//
// Konteyner bilerek TERMINATE EDİLMİYOR: hangi testin sonuncu olduğunu
// bilmenin yolu yok ve ilk testin cleanup'ında kapatmak sonrakileri
// kırardı. Temizliği testcontainers'ın reaper'ı (Ryuk) yapıyor —
// test süreci bittiğinde konteyneri o siliyor.
func start(ctx context.Context) (string, error) {
	once.Do(func() {
		container, err := postgres.Run(ctx, image,
			postgres.WithDatabase("postern_test"),
			postgres.WithUsername("postern"),
			postgres.WithPassword("postern"),
			testcontainers.WithWaitStrategy(
				wait.ForLog("database system is ready to accept connections").
					WithOccurrence(2).
					WithStartupTimeout(90*time.Second)),
		)
		if err != nil {
			startErr = fmt.Errorf("PostgreSQL konteyneri başlatılamadı: %w", err)
			return
		}

		// sslmode=disable: konteyner localhost'ta ve TLS kurulu değil.
		// Üretim varsayılanı verify-full (bkz. store.dsn); test burada
		// AÇIKÇA aksini söylüyor, sessizce düşmüyor.
		sharedDSN, startErr = container.ConnectionString(ctx, "sslmode=disable")
	})
	return sharedDSN, startErr
}

// DSN, teste özel BOŞ bir şemaya bağlanan bağlantı dizesi döner.
//
// Şema test bitiminde düşürülür; konteyner ayakta kalır.
func DSN(t *testing.T) string {
	t.Helper()

	if testing.Short() {
		t.Skip("-short: PostgreSQL konteyneri gerektiren test atlandı")
	}

	ctx := context.Background()

	base, err := start(ctx)
	if err != nil {
		// Skip DEĞİL Fatal: Docker yoksa testler sessizce "geçmiş"
		// görünmemeli. Yeşil bir koşu, deponun gerçekten sınandığı
		// anlamına gelmeli.
		t.Fatalf("%v\n\nDocker gerekiyor. Konteynersiz koşmak için: go test -short ./...", err)
	}

	schema := nextSchema()

	admin, err := openRaw(base)
	if err != nil {
		t.Fatalf("yönetim bağlantısı: %v", err)
	}
	defer admin.Close()

	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA "`+schema+`";`); err != nil {
		t.Fatalf("CREATE SCHEMA %s: %v", schema, err)
	}

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		db, err := openRaw(base)
		if err != nil {
			return
		}
		defer db.Close()
		db.ExecContext(cleanupCtx, `DROP SCHEMA "`+schema+`" CASCADE;`)
	})

	return withSchema(base, schema)
}

// nextSchema, süreç içinde benzersiz bir şema adı üretir.
//
// Rastgelelik değil sayaç: aynı konteyneri paylaşan testler tek süreçte
// koşuyor, dolayısıyla artan sayı yeterli ve çakışma ihtimali yok.
// Ad, bir testin şemasını hata mesajında tanımayı kolaylaştırıyor.
func nextSchema() string {
	counter.Lock()
	defer counter.Unlock()
	counter.n++
	return fmt.Sprintf("test_%03d", counter.n)
}

// withSchema, DSN'e search_path ekler.
func withSchema(base, schema string) string {
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + "search_path=" + schema
}
