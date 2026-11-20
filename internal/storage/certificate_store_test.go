package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestCertificateStoreLifecycle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db, err := OpenSQLite(ctx, SQLiteOptions{Path: filepath.Join(t.TempDir(), "certs.db")})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	migrationsDir := filepath.Join("..", "..", "migrations")
	if err := ApplyMigrationsFromDir(ctx, db, migrationsDir); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	now := time.Date(2026, 11, 19, 14, 0, 0, 0, time.UTC)
	created, err := CreateCertificate(ctx, db, CreateCertificateParams{
		SerialNumber: "abc123",
		CommonName:   "service.home",
		SANs:         []string{"service.home", "service.local"},
		NotBefore:    now,
		NotAfter:     now.Add(24 * time.Hour),
		Now:          now,
	})
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	if created.SerialNumber != "abc123" {
		t.Fatalf("unexpected serial: %s", created.SerialNumber)
	}

	list, err := ListCertificates(ctx, db)
	if err != nil {
		t.Fatalf("list certificates: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected one certificate, got %d", len(list))
	}

	if err := RevokeCertificate(ctx, db, "abc123", now.Add(2*time.Hour)); err != nil {
		t.Fatalf("revoke certificate: %v", err)
	}
	revoked, err := GetCertificateBySerial(ctx, db, "ABC123")
	if err != nil {
		t.Fatalf("get revoked certificate: %v", err)
	}
	if revoked.Status != "revoked" {
		t.Fatalf("expected revoked status, got %s", revoked.Status)
	}

	if err := DeleteCertificate(ctx, db, "abc123"); err != nil {
		t.Fatalf("delete certificate: %v", err)
	}
	if _, err := GetCertificateBySerial(ctx, db, "abc123"); !errors.Is(err, ErrCertificateNotFound) {
		t.Fatalf("expected ErrCertificateNotFound after delete, got %v", err)
	}
}
