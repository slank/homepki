package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestAuthSessionLifecycle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "auth-session.db")
	db, err := OpenSQLite(ctx, SQLiteOptions{Path: dbPath})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	migrationsDir := filepath.Join("..", "..", "migrations")
	if err := ApplyMigrationsFromDir(ctx, db, migrationsDir); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	now := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)

	_, err = db.ExecContext(
		ctx,
		`INSERT INTO admin_credentials(id, username, password_hash, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)`,
		1,
		"admin",
		"hash",
		now.Format(time.RFC3339Nano),
		now.Format(time.RFC3339Nano),
	)
	if err != nil {
		t.Fatalf("seed admin: %v", err)
	}

	session, err := CreateAuthSession(ctx, db, CreateAuthSessionParams{
		ID:            "session-1",
		AdminID:       1,
		CSRFTokenHash: "csrf-hash",
		ExpiresAt:     now.Add(30 * time.Minute),
		RemoteAddr:    "127.0.0.1",
		UserAgent:     "test",
		Now:           now,
	})
	if err != nil {
		t.Fatalf("create auth session: %v", err)
	}

	if session.ID != "session-1" {
		t.Fatalf("unexpected session id: %s", session.ID)
	}
	if session.CSRFTokenHash != "csrf-hash" {
		t.Fatalf("unexpected csrf hash: %s", session.CSRFTokenHash)
	}

	if err := TouchAuthSession(ctx, db, session.ID, now.Add(5*time.Minute)); err != nil {
		t.Fatalf("touch auth session: %v", err)
	}

	loaded, err := GetAuthSession(ctx, db, session.ID, now.Add(10*time.Minute))
	if err != nil {
		t.Fatalf("get auth session: %v", err)
	}

	if loaded.LastSeenAt.Before(now.Add(5 * time.Minute)) {
		t.Fatalf("expected last_seen_at to advance, got %s", loaded.LastSeenAt)
	}

	if err := RevokeAuthSession(ctx, db, session.ID, now.Add(12*time.Minute)); err != nil {
		t.Fatalf("revoke auth session: %v", err)
	}

	_, err = GetAuthSession(ctx, db, session.ID, now.Add(13*time.Minute))
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound after revoke, got %v", err)
	}
}

func TestExpiredSessionIsRejected(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "expired-session.db")
	db, err := OpenSQLite(ctx, SQLiteOptions{Path: dbPath})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	migrationsDir := filepath.Join("..", "..", "migrations")
	if err := ApplyMigrationsFromDir(ctx, db, migrationsDir); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	now := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)

	_, err = db.ExecContext(
		ctx,
		`INSERT INTO admin_credentials(id, username, password_hash, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)`,
		1,
		"admin",
		"hash",
		now.Format(time.RFC3339Nano),
		now.Format(time.RFC3339Nano),
	)
	if err != nil {
		t.Fatalf("seed admin: %v", err)
	}

	_, err = CreateAuthSession(ctx, db, CreateAuthSessionParams{
		ID:            "expired-session",
		AdminID:       1,
		CSRFTokenHash: "csrf-hash",
		ExpiresAt:     now.Add(1 * time.Minute),
		Now:           now,
	})
	if err != nil {
		t.Fatalf("create auth session: %v", err)
	}

	_, err = GetAuthSession(ctx, db, "expired-session", now.Add(2*time.Minute))
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound for expired session, got %v", err)
	}
}
