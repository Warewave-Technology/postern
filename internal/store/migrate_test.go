package store

import (
	"context"
	"path/filepath"
	"testing"
)

// newTestStore, boş bir dosyada açılmış ve migrate edilmiş bir Store döner.
//
// Bellek içi (":memory:") DEĞİL, gerçek dosya: WAL ve busy_timeout gibi
// pragma'ların davranışı bellekte farklıdır ve testin ürettiği güven
// üretimdeki davranışa dayanmalı.
func newTestStore(t *testing.T) *Store {
	t.Helper()

	s := newEmptyStore(t)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s
}

// newEmptyStore, açılmış ama HENÜZ migrate EDİLMEMİŞ bir Store döner.
func newEmptyStore(t *testing.T) *Store {
	t.Helper()

	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "postern.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// tableExists, şemada verilen adda bir tablo var mı diye sorar.
func tableExists(t *testing.T, s *Store, name string) bool {
	t.Helper()

	var n int
	err := s.db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name,
	).Scan(&n)
	if err != nil {
		t.Fatalf("sqlite_master sorgusu: %v", err)
	}
	return n > 0
}

func TestLoadMigrations(t *testing.T) {
	migs, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if len(migs) == 0 {
		t.Fatal("hiç migration yüklenmedi — embed çalışmıyor olabilir")
	}

	prev := 0
	for i, m := range migs {
		// Sıra ARTAN olmalı ve versiyonlar benzersiz olmalı.
		if m.version <= prev {
			t.Fatalf("migrations[%d]: versiyon %d, öncekinden (%d) büyük değil — sıralama sayısal mı?", i, m.version, prev)
		}
		prev = m.version

		if m.name == "" {
			t.Errorf("migrations[%d]: ad boş", i)
		}
		// Down'ı olmayan migration = geri alınamayan dağıtım.
		if m.up == "" {
			t.Errorf("migrations[%d] (%d_%s): up boş", i, m.version, m.name)
		}
		if m.down == "" {
			t.Errorf("migrations[%d] (%d_%s): down boş", i, m.version, m.name)
		}
	}

	if migs[0].version != 1 || migs[0].name != "init" {
		t.Errorf("ilk migration = %d_%s, beklenen 1_init", migs[0].version, migs[0].name)
	}
}

func TestMigrateCreatesSchema(t *testing.T) {
	ctx := context.Background()
	s := newEmptyStore(t)

	// Migrate ÖNCESİ: boş veritabanı geçerli bir durum, hata değil.
	v, err := s.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("boş veritabanında SchemaVersion: %v", err)
	}
	if v != 0 {
		t.Fatalf("boş veritabanında versiyon = %d, beklenen 0", v)
	}

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// Beklenen versiyon SABİT DEĞİL: migrations/ klasörüne yeni bir dosya
	// eklendiğinde bu testin de düzeltilmesi gerekmesin.
	want := lastMigrationVersion(t)

	v, err = s.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if v != want {
		t.Fatalf("migrate sonrası versiyon = %d, beklenen %d", v, want)
	}

	for _, table := range []string{"users", "roles", "targets", "user_roles", "role_targets", "sessions", "user_public_keys"} {
		if !tableExists(t, s, table) {
			t.Errorf("%q tablosu oluşmadı", table)
		}
	}
}

// serve her açılışta Migrate çağıracak; ikinci çağrı hiçbir şey yapmamalı.
func TestMigrateIsIdempotent(t *testing.T) {
	ctx := context.Background()
	s := newEmptyStore(t)

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("ilk Migrate: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("ikinci Migrate hata verdi — uygulanmışları atlamıyor: %v", err)
	}

	v, err := s.SchemaVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := lastMigrationVersion(t); v != want {
		t.Fatalf("iki Migrate sonrası versiyon = %d, beklenen %d", v, want)
	}
}

// lastMigrationVersion, gömülü migration'ların en yüksek versiyonu.
func lastMigrationVersion(t *testing.T) int {
	t.Helper()

	migs, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if len(migs) == 0 {
		t.Fatal("hiç migration yok")
	}
	return migs[len(migs)-1].version
}

func TestRollback(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	// Rollback TEK adım geri alır; sıfıra inmek için tekrar tekrar çağrılır.
	// Her çağrının versiyonu gerçekten DÜŞÜRDÜĞÜNÜ de doğruluyoruz: aynı
	// versiyonda takılan bir Rollback burada sonsuz döngü yerine hata verir.
	prev := lastMigrationVersion(t)
	for i := 0; prev > 0; i++ {
		if i > len(migrationsForTest(t)) {
			t.Fatalf("Rollback ilerlemiyor, versiyon %d'de takıldı", prev)
		}
		if err := s.Rollback(ctx); err != nil {
			t.Fatalf("Rollback: %v", err)
		}
		v, err := s.SchemaVersion(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if v >= prev {
			t.Fatalf("Rollback sonrası versiyon %d -> %d, düşmesi gerekirdi", prev, v)
		}
		prev = v
	}

	if tableExists(t, s, "users") {
		t.Error("rollback sonrası users tablosu duruyor — down SQL çalışmadı")
	}

	// Geri alınacak bir şey kalmadığında Rollback hata DEĞİL, no-op.
	if err := s.Rollback(ctx); err != nil {
		t.Fatalf("boş veritabanında Rollback hata verdi: %v", err)
	}

	// Ve tekrar ileri gidebilmeli: down gerçekten temiz bıraktıysa
	// aynı up ikinci kez sorunsuz çalışır.
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("rollback sonrası tekrar Migrate: %v", err)
	}
	if !tableExists(t, s, "users") {
		t.Error("tekrar migrate sonrası users tablosu yok")
	}
}

// migrationsForTest, döngü sınırı için migration sayısını verir.
func migrationsForTest(t *testing.T) []migration {
	t.Helper()

	migs, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	return migs
}

func TestPendingMigrations(t *testing.T) {
	ctx := context.Background()
	s := newEmptyStore(t)

	// Boş veritabanı: her şey bekliyor.
	n, err := s.PendingMigrations(ctx)
	if err != nil {
		t.Fatalf("boş veritabanında PendingMigrations: %v", err)
	}
	if want := len(migrationsForTest(t)); n != want {
		t.Fatalf("bekleyen = %d, beklenen %d", n, want)
	}

	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	// Migrate sonrası: sıfır. serve'ün "başlayabilir miyim" sorusu bu.
	n, err = s.PendingMigrations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("migrate sonrası bekleyen = %d, beklenen 0", n)
	}

	// Bir adım geri al: tam olarak 1 beklemeli.
	if err := s.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	n, err = s.PendingMigrations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("rollback sonrası bekleyen = %d, beklenen 1", n)
	}
}
