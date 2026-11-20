package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateAdminCredential(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db, err := OpenSQLite(ctx, SQLiteOptions{Path: filepath.Join(t.TempDir(), "admin.db")})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	migrationsDir := filepath.Join("..", "..", "migrations")
	if err := ApplyMigrationsFromDir(ctx, db, migrationsDir); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	credential, err := CreateAdminCredential(ctx, db, "admin", "hash", time.Now().UTC())
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if credential.Username != "admin" {
		t.Fatalf("unexpected username: %s", credential.Username)
	}

	_, err = CreateAdminCredential(ctx, db, "admin2", "hash2", time.Now().UTC())
	if !errors.Is(err, ErrAdminAlreadyCreated) {
		t.Fatalf("expected ErrAdminAlreadyCreated, got %v", err)
	}
}
