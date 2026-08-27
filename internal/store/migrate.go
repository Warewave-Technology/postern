package store

import (
	"cmp"
	"context"
	"database/sql"
	"embed"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

const migrationsDir = "migrations"

type migration struct {
	version int
	name    string
	up      string
	down    string
}

func loadMigrations() ([]migration, error) {
	entries, err := migrationFS.ReadDir(migrationsDir)
	if err != nil {
		return nil, err
	}

	var migrations []migration
	var directionDownCounter int
	var directionUpCounter int

	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".down.sql") {
			directionDownCounter++
			continue
		}

		directionUpCounter++

		parts := strings.Split(entry.Name(), ".")
		if len(parts) < 3 {
			return nil, fmt.Errorf("store.migrate.loadMigrations[%s]: file name format error", entry.Name())
		}

		if !slices.Contains([]string{"up", "down"}, parts[1]) {
			return nil, fmt.Errorf("store.migrate.loadMigrations[%s]: unknown direction %s", entry.Name(), parts[1])
		}

		vnParts := strings.Split(parts[0], "_")
		name := strings.Join(vnParts[1:], "_")
		if name == "" {
			return nil, fmt.Errorf("store.migrate.loadMigrations[%s]: name cannot be empty", entry.Name())
		}

		version, err := strconv.Atoi(vnParts[0])
		if err != nil {
			return nil, fmt.Errorf("store.migrate.loadMigrations[%s]: %w", entry.Name(), err)
		}

		upSql, err := migrationFS.ReadFile(migrationsDir + "/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("store.migrate.loadMigrations[%s]: %w", entry.Name(), err)
		}

		downSql, err := migrationFS.ReadFile(migrationsDir + "/" + strings.ReplaceAll(entry.Name(), ".up.sql", ".down.sql"))
		if err != nil {
			return nil, fmt.Errorf("store.migrate.loadMigrations[%s]: %w", entry.Name(), err)
		}

		migrations = append(migrations, migration{
			version: version,
			name:    name,
			up:      string(upSql),
			down:    string(downSql),
		})
	}

	if directionDownCounter != directionUpCounter {
		return nil, fmt.Errorf("store.migrate.loadMigrations[up=%d,down=%d]: orphan down/up migration file(s) detected", directionUpCounter, directionDownCounter)
	}

	slices.SortFunc(migrations, func(a, b migration) int {
		return cmp.Compare(a.version, b.version)
	})

	return migrations, nil
}

func (s *Store) ensureMigrationsTable(ctx context.Context) error {
	queryStr := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			name       TEXT NOT NULL,
			applied_at INTEGER NOT NULL
		);
	`
	_, err := s.db.ExecContext(ctx, queryStr)
	return err
}

func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	ok, err := s.tableExists(ctx, "schema_migrations")
	if err != nil {
		return 0, fmt.Errorf("store.migrate.SchemaVersion: %w", err)
	}

	if !ok {
		return 0, nil
	}

	queryStr := `
		SELECT COALESCE(MAX(version), 0)
		FROM schema_migrations;
	`

	var schemaVersion int

	err = s.db.QueryRowContext(ctx, queryStr).Scan(&schemaVersion)
	if err != nil {
		return 0, fmt.Errorf("store.migrate.SchemaVersion: %w", err)
	}

	return schemaVersion, nil
}

func (s *Store) Migrate(ctx context.Context) error {
	// Göç boyunca danışma kilidi tut.
	//
	// SQLite döneminde buna gerek yoktu: veritabanı tek bir dosyaydı ve
	// aynı anda tek yazar olabiliyordu. PostgreSQL paylaşılan bir sunucu,
	// yani "iki operatör aynı anda db migrate çalıştırır" artık mümkün.
	// Kilitsiz hâlde ikisi de aynı sürümü eksik görür, ikisi de uygular
	// ve biri PostgreSQL'in KENDİ kataloğunda çakışır:
	//
	//	duplicate key value violates unique constraint
	//	"pg_type_typname_nsp_index" (SQLSTATE 23505)
	//
	// Operatöre hiçbir şey anlatmayan bir mesaj, ve arkasında yarım
	// kalmış bir şema. (Ölçüldü: TestConcurrentMigrateIsSerialized
	// kilit kaldırılınca 4 koşucudan 3'ünde bu hatayı veriyor.)
	//
	// Danışma kilidi tabloya değil, uygulamanın seçtiği bir sayıya
	// takılır; şemadan bağımsız olduğu için ensureMigrationsTable'dan
	// ÖNCE alınabiliyor — bu tablonun kendisi de yarışa açık.
	unlock, err := s.lockForMigration(ctx)
	if err != nil {
		return fmt.Errorf("store.migrate.Migrate: %w", err)
	}
	defer unlock()

	err = s.ensureMigrationsTable(ctx)
	if err != nil {
		return fmt.Errorf("store.migrate.Migrate: %w", err)
	}

	schemaVersion, err := s.SchemaVersion(ctx)
	if err != nil {
		return fmt.Errorf("store.migrate.Migrate: %w", err)
	}

	migrations, err := loadMigrations()
	if err != nil {
		return fmt.Errorf("store.migrate.Migrate: %w", err)
	}

	for _, migration := range migrations {
		if migration.version > schemaVersion {
			err := s.applySingleMigration(ctx, migration, migration.up, "up")
			if err != nil {
				return fmt.Errorf("migration sequence halted at version %d: %w", migration.version, err)
			}
		}
	}

	return nil
}

func (s *Store) PendingMigrations(ctx context.Context) (int, error) {
	var pendingMigration int

	migrations, err := loadMigrations()
	if err != nil {
		return pendingMigration, fmt.Errorf("store.migrate.PendingMigrations: %w", err)
	}

	schemaVersion, err := s.SchemaVersion(ctx)
	if err != nil {
		return pendingMigration, fmt.Errorf("store.migrate.PendingMigrations: %w", err)
	}

	for _, migration := range migrations {
		if migration.version > schemaVersion {
			pendingMigration++
		}
	}

	return pendingMigration, nil
}

func (s *Store) Rollback(ctx context.Context) error {
	migrations, err := loadMigrations()
	if err != nil {
		return fmt.Errorf("store.migrate.Rollback: %w", err)
	}

	schemaVersion, err := s.SchemaVersion(ctx)
	if err != nil {
		return fmt.Errorf("store.migrate.Rollback: %w", err)
	}

	for _, migration := range migrations {
		if migration.version == schemaVersion {
			err := s.applySingleMigration(ctx, migration, migration.down, "down")
			if err != nil {
				return fmt.Errorf("rollback sequence halted at version %d: %w", migration.version, err)
			}

			return nil
		}
	}

	return nil
}

func (s *Store) applySingleMigration(ctx context.Context, migration migration, sqlQuery string, qType string) error {
	txCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	tx, err := s.db.BeginTx(txCtx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("store.migrate.Migrate[%s]: failed to begin: %w", migration.name, err)
	}

	defer tx.Rollback()

	if _, err = tx.ExecContext(txCtx, sqlQuery); err != nil {
		return fmt.Errorf("store.migrate.Migrate[%s]: %w", migration.name, err)
	}

	if qType == "up" {
		if _, err = tx.ExecContext(txCtx, `INSERT INTO schema_migrations (version, name, applied_at) VALUES ($1, $2, $3);`, migration.version, migration.name, time.Now().Unix()); err != nil {
			return fmt.Errorf("store.migrate.Migrate[%s]: %w", migration.name, err)
		}
	} else {
		if _, err = tx.ExecContext(txCtx, `DELETE FROM schema_migrations WHERE version=$1;`, migration.version); err != nil {
			return fmt.Errorf("store.migrate.Migrate[%s]: %w", migration.name, err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("store.migrate.Migrate[%s]: commit failed: %w", migration.name, err)
	}

	return nil
}

func (s *Store) tableExists(ctx context.Context, tableName string) (bool, error) {
	var count int

	err := s.db.QueryRowContext(ctx, tableExistsQuery, tableName).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("store.migrate.tableExists[%s]: failed: %w", tableName, err)
	}

	return count > 0, nil
}

// migrationLockID, göç danışma kilidinin anahtarı.
//
// Rastgele seçilmiş bir sabit: PostgreSQL danışma kilitleri tek bir
// küresel ad alanı paylaşır, dolayısıyla aynı veritabanını kullanan başka
// bir uygulamanın 1 ya da 42 gibi bir sayı seçme ihtimaline karşı sıra
// dışı bir değer.
const migrationLockID int64 = 0x504f5354 // "POST"

// lockForMigration, göç kilidini alır ve bırakma fonksiyonunu döner.
//
// Kilit BAĞLANTI ömürlüdür (transaction değil): göçler ayrı
// transaction'larda uygulanıyor ve kilidin hepsini kapsaması gerekiyor.
// Bu yüzden havuzdan tek bir bağlantı ayrılıyor — havuzdaki başka bir
// bağlantıda unlock çağırmak sessizce hiçbir şey yapmazdı.
//
// pg_advisory_lock BEKLER, hata vermez: eşzamanlı ikinci çalıştırma
// düşmek yerine sırasını bekler ve sonra "uygulanacak göç yok" görür.
func (s *Store) lockForMigration(ctx context.Context) (func(), error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire connection for migration lock: %w", err)
	}

	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1);`, migrationLockID); err != nil {
		conn.Close()
		return nil, fmt.Errorf("acquire migration lock: %w", err)
	}

	return func() {
		// Bağlantı kapanınca kilit zaten düşer; açıkça bırakmak
		// bağlantının havuza SAĞLAM dönmesini sağlıyor.
		unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()

		conn.ExecContext(unlockCtx, `SELECT pg_advisory_unlock($1);`, migrationLockID)
		conn.Close()
	}, nil
}
