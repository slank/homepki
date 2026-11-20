package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestAppendAuditEvent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	db, err := OpenSQLite(ctx, SQLiteOptions{Path: dbPath})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	migrationsDir := filepath.Join("..", "..", "migrations")
	if err := ApplyMigrationsFromDir(ctx, db, migrationsDir); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	now := time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC)
	err = AppendAuditEvent(ctx, db, AppendAuditEventParams{
		ActorType:  "admin",
		ActorID:    "1",
		Action:     "auth.login",
		TargetType: "session",
		TargetID:   "session-1",
		Outcome:    "success",
		Details: map[string]string{
			"remote_addr": "127.0.0.1",
		},
		Now: now,
	})
	if err != nil {
		t.Fatalf("append audit event: %v", err)
	}

	var (
		action  string
		outcome string
		details string
	)

	err = db.QueryRowContext(
		ctx,
		`SELECT action, outcome, details_json
		 FROM audit_events
		 ORDER BY id DESC
		 LIMIT 1`,
	).Scan(&action, &outcome, &details)
	if err != nil {
		t.Fatalf("query audit event: %v", err)
	}

	if action != "auth.login" {
		t.Fatalf("unexpected action: %s", action)
	}
	if outcome != "success" {
		t.Fatalf("unexpected outcome: %s", outcome)
	}
	if details == "" {
		t.Fatalf("expected non-empty details")
	}
}
