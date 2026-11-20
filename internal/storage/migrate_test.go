package storage

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func TestApplyAndRollbackMigrationsFromDir(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "homepki-test.db")

	db, err := OpenSQLite(ctx, SQLiteOptions{Path: dbPath})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	migrationsDir := filepath.Join("..", "..", "migrations")
	if err := ApplyMigrationsFromDir(ctx, db, migrationsDir); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	if err := ApplyMigrationsFromDir(ctx, db, migrationsDir); err != nil {
		t.Fatalf("re-apply migrations should be idempotent: %v", err)
	}

	assertTableExists(t, db, "admin_credentials")
	assertTableExists(t, db, "audit_events")
	assertTableExists(t, db, "step_ca_provision_state")

	if err := RollbackMigrationsFromDir(ctx, db, migrationsDir, 1); err != nil {
		t.Fatalf("rollback migrations: %v", err)
	}

	assertTableMissing(t, db, "step_ca_provision_state")
	assertTableExists(t, db, "admin_credentials")
}

func assertTableExists(t *testing.T, db *sql.DB, table string) {
	t.Helper()

	var name string
	err := db.QueryRow(
		"SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
		table,
	).Scan(&name)
	if err != nil {
		t.Fatalf("expected table %q to exist: %v", table, err)
	}
}

func assertTableMissing(t *testing.T, db *sql.DB, table string) {
	t.Helper()

	var name string
	err := db.QueryRow(
		"SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
		table,
	).Scan(&name)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected table %q to be missing, got name=%q err=%v", table, name, err)
	}
}
