package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestStepCAProvisionStateLifecycle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "step-ca-state.db")
	db, err := OpenSQLite(ctx, SQLiteOptions{Path: dbPath})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	migrationsDir := filepath.Join("..", "..", "migrations")
	if err := ApplyMigrationsFromDir(ctx, db, migrationsDir); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	state, err := GetStepCAProvisionState(ctx, db)
	if err != nil {
		t.Fatalf("get default step ca state: %v", err)
	}
	if state.Status != "not_provisioned" {
		t.Fatalf("unexpected default status: %s", state.Status)
	}

	now := time.Date(2026, 11, 19, 13, 0, 0, 0, time.UTC)
	err = SaveStepCAProvisionState(ctx, db, StepCAProvisionState{
		Status:                  "provisioned",
		CAID:                    "ca-1",
		RootFingerprint:         "root-fp",
		IntermediateFingerprint: "int-fp",
		LastError:               "",
	}, now)
	if err != nil {
		t.Fatalf("save step ca state: %v", err)
	}

	loaded, err := GetStepCAProvisionState(ctx, db)
	if err != nil {
		t.Fatalf("get step ca state: %v", err)
	}
	if loaded.Status != "provisioned" || loaded.CAID != "ca-1" {
		t.Fatalf("unexpected loaded state: %+v", loaded)
	}
}
