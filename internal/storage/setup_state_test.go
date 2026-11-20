package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestSetupStateTransitions(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "setup-state.db")
	db, err := OpenSQLite(ctx, SQLiteOptions{Path: dbPath})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	migrationsDir := filepath.Join("..", "..", "migrations")
	if err := ApplyMigrationsFromDir(ctx, db, migrationsDir); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	state, reason, err := GetSetupState(ctx, db)
	if err != nil {
		t.Fatalf("get default setup state: %v", err)
	}
	if state != SetupStateNotInitialized {
		t.Fatalf("unexpected default setup state: %s", state)
	}
	if reason != "" {
		t.Fatalf("expected empty default reason, got %q", reason)
	}

	now := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	if err := TransitionSetupState(ctx, db, SetupStatePrerequisites, "", now); err != nil {
		t.Fatalf("transition to prerequisites: %v", err)
	}

	if err := TransitionSetupState(ctx, db, SetupStateCAProvisioning, "", now.Add(time.Minute)); err != nil {
		t.Fatalf("transition to ca_provisioning: %v", err)
	}

	if err := TransitionSetupState(ctx, db, SetupStateRecoverableError, "missing yubikey", now.Add(2*time.Minute)); err != nil {
		t.Fatalf("transition to recoverable_failure: %v", err)
	}

	state, reason, err = GetSetupState(ctx, db)
	if err != nil {
		t.Fatalf("get setup state after transitions: %v", err)
	}
	if state != SetupStateRecoverableError {
		t.Fatalf("unexpected setup state: %s", state)
	}
	if reason != "missing yubikey" {
		t.Fatalf("unexpected setup reason: %s", reason)
	}
}

func TestSetupStateRejectsInvalidTransition(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "invalid-transition.db")
	db, err := OpenSQLite(ctx, SQLiteOptions{Path: dbPath})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	migrationsDir := filepath.Join("..", "..", "migrations")
	if err := ApplyMigrationsFromDir(ctx, db, migrationsDir); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	err = TransitionSetupState(
		ctx,
		db,
		SetupStateComplete,
		"",
		time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC),
	)
	if !errors.Is(err, ErrInvalidSetupTransition) {
		t.Fatalf("expected ErrInvalidSetupTransition, got %v", err)
	}
}
