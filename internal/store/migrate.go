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
	err := s.ensureMigrationsTable(ctx)
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
		if _, err = tx.ExecContext(txCtx, `INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?);`, migration.version, migration.name, time.Now().Unix()); err != nil {
			return fmt.Errorf("store.migrate.Migrate[%s]: %w", migration.name, err)
		}
	} else {
		if _, err = tx.ExecContext(txCtx, `DELETE FROM schema_migrations WHERE version=?;`, migration.version); err != nil {
			return fmt.Errorf("store.migrate.Migrate[%s]: %w", migration.name, err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("store.migrate.Migrate[%s]: commit failed: %w", migration.name, err)
	}

	return nil
}

func (s *Store) tableExists(ctx context.Context, tableName string) (bool, error) {
	query := `
		SELECT COUNT(*)
		FROM sqlite_master
		WHERE type = 'table'
		  AND name = ?;
	`

	var count int

	err := s.db.QueryRowContext(ctx, query, tableName).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("store.migrate.tableExists[%s]: failed: %w", tableName, err)
	}

	return count > 0, nil
}
