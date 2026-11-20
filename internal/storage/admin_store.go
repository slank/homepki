package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	ErrAdminNotFound       = errors.New("admin not found")
	ErrAdminAlreadyCreated = errors.New("admin already created")
)

type AdminCredential struct {
	ID           int64
	Username     string
	PasswordHash string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func CreateAdminCredential(ctx context.Context, db *sql.DB, username, passwordHash string, now time.Time) (AdminCredential, error) {
	if db == nil {
		return AdminCredential{}, errors.New("db is required")
	}
	if username == "" {
		return AdminCredential{}, errors.New("username is required")
	}
	if passwordHash == "" {
		return AdminCredential{}, errors.New("password hash is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	var existingCount int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(1) FROM admin_credentials").Scan(&existingCount); err != nil {
		return AdminCredential{}, fmt.Errorf("count admin credentials: %w", err)
	}
	if existingCount > 0 {
		return AdminCredential{}, ErrAdminAlreadyCreated
	}

	_, err := db.ExecContext(
		ctx,
		`INSERT INTO admin_credentials(id, username, password_hash, created_at, updated_at)
		 VALUES(1, ?, ?, ?, ?)`,
		username,
		passwordHash,
		now.Format(time.RFC3339Nano),
		now.Format(time.RFC3339Nano),
	)
	if err != nil {
		return AdminCredential{}, fmt.Errorf("insert admin credential: %w", err)
	}

	return GetAdminCredentialByUsername(ctx, db, username)
}

func GetAdminCredentialByUsername(ctx context.Context, db *sql.DB, username string) (AdminCredential, error) {
	if db == nil {
		return AdminCredential{}, errors.New("db is required")
	}
	if username == "" {
		return AdminCredential{}, errors.New("username is required")
	}

	var (
		credential   AdminCredential
		createdAtRaw string
		updatedAtRaw string
	)

	err := db.QueryRowContext(
		ctx,
		`SELECT id, username, password_hash, created_at, updated_at
		 FROM admin_credentials
		 WHERE username = ?`,
		username,
	).Scan(
		&credential.ID,
		&credential.Username,
		&credential.PasswordHash,
		&createdAtRaw,
		&updatedAtRaw,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return AdminCredential{}, ErrAdminNotFound
	}
	if err != nil {
		return AdminCredential{}, fmt.Errorf("query admin credential: %w", err)
	}

	createdAt, err := parseRFC3339Time(createdAtRaw)
	if err != nil {
		return AdminCredential{}, fmt.Errorf("parse admin created_at: %w", err)
	}
	updatedAt, err := parseRFC3339Time(updatedAtRaw)
	if err != nil {
		return AdminCredential{}, fmt.Errorf("parse admin updated_at: %w", err)
	}
	credential.CreatedAt = createdAt
	credential.UpdatedAt = updatedAt

	return credential, nil
}
