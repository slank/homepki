package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var ErrSessionNotFound = errors.New("session not found")

type AuthSession struct {
	ID            string
	AdminID       int64
	CSRFTokenHash string
	ExpiresAt     time.Time
	CreatedAt     time.Time
	LastSeenAt    time.Time
	RemoteAddr    string
	UserAgent     string
	RevokedAt     *time.Time
}

type CreateAuthSessionParams struct {
	ID            string
	AdminID       int64
	CSRFTokenHash string
	ExpiresAt     time.Time
	RemoteAddr    string
	UserAgent     string
	Now           time.Time
}

func CreateAuthSession(ctx context.Context, db *sql.DB, params CreateAuthSessionParams) (AuthSession, error) {
	if db == nil {
		return AuthSession{}, errors.New("db is required")
	}
	if params.ID == "" {
		return AuthSession{}, errors.New("session id is required")
	}
	if params.AdminID <= 0 {
		return AuthSession{}, errors.New("admin id must be greater than zero")
	}
	if params.CSRFTokenHash == "" {
		return AuthSession{}, errors.New("csrf token hash is required")
	}
	if params.ExpiresAt.IsZero() {
		return AuthSession{}, errors.New("expires_at is required")
	}

	now := params.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	_, err := db.ExecContext(
		ctx,
		`INSERT INTO auth_sessions
			(id, admin_id, csrf_token_hash, expires_at, created_at, last_seen_at, remote_addr, user_agent, revoked_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		params.ID,
		params.AdminID,
		params.CSRFTokenHash,
		params.ExpiresAt.UTC().Format(time.RFC3339Nano),
		now.Format(time.RFC3339Nano),
		now.Format(time.RFC3339Nano),
		params.RemoteAddr,
		params.UserAgent,
	)
	if err != nil {
		return AuthSession{}, fmt.Errorf("insert auth session: %w", err)
	}

	return GetAuthSession(ctx, db, params.ID, now)
}

func GetAuthSession(ctx context.Context, db *sql.DB, sessionID string, now time.Time) (AuthSession, error) {
	if db == nil {
		return AuthSession{}, errors.New("db is required")
	}
	if sessionID == "" {
		return AuthSession{}, errors.New("session id is required")
	}

	if now.IsZero() {
		now = time.Now().UTC()
	}

	var (
		session       AuthSession
		expiresAtRaw  string
		createdAtRaw  string
		lastSeenAtRaw string
		revokedAtRaw  sql.NullString
	)

	err := db.QueryRowContext(
		ctx,
		`SELECT id, admin_id, csrf_token_hash, expires_at, created_at, last_seen_at, remote_addr, user_agent, revoked_at
		 FROM auth_sessions
		 WHERE id = ?`,
		sessionID,
	).Scan(
		&session.ID,
		&session.AdminID,
		&session.CSRFTokenHash,
		&expiresAtRaw,
		&createdAtRaw,
		&lastSeenAtRaw,
		&session.RemoteAddr,
		&session.UserAgent,
		&revokedAtRaw,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthSession{}, ErrSessionNotFound
	}
	if err != nil {
		return AuthSession{}, fmt.Errorf("query auth session: %w", err)
	}

	session.ExpiresAt, err = parseRFC3339Time(expiresAtRaw)
	if err != nil {
		return AuthSession{}, fmt.Errorf("parse expires_at: %w", err)
	}
	session.CreatedAt, err = parseRFC3339Time(createdAtRaw)
	if err != nil {
		return AuthSession{}, fmt.Errorf("parse created_at: %w", err)
	}
	session.LastSeenAt, err = parseRFC3339Time(lastSeenAtRaw)
	if err != nil {
		return AuthSession{}, fmt.Errorf("parse last_seen_at: %w", err)
	}

	if revokedAtRaw.Valid {
		revokedAt, err := parseRFC3339Time(revokedAtRaw.String)
		if err != nil {
			return AuthSession{}, fmt.Errorf("parse revoked_at: %w", err)
		}
		session.RevokedAt = &revokedAt
	}

	if session.RevokedAt != nil || !session.ExpiresAt.After(now) {
		return AuthSession{}, ErrSessionNotFound
	}

	return session, nil
}

func TouchAuthSession(ctx context.Context, db *sql.DB, sessionID string, now time.Time) error {
	if db == nil {
		return errors.New("db is required")
	}
	if sessionID == "" {
		return errors.New("session id is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	result, err := db.ExecContext(
		ctx,
		`UPDATE auth_sessions
		 SET last_seen_at = ?
		 WHERE id = ? AND revoked_at IS NULL`,
		now.Format(time.RFC3339Nano),
		sessionID,
	)
	if err != nil {
		return fmt.Errorf("touch auth session: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read touched row count: %w", err)
	}
	if rows == 0 {
		return ErrSessionNotFound
	}

	return nil
}

func RevokeAuthSession(ctx context.Context, db *sql.DB, sessionID string, now time.Time) error {
	if db == nil {
		return errors.New("db is required")
	}
	if sessionID == "" {
		return errors.New("session id is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	result, err := db.ExecContext(
		ctx,
		`UPDATE auth_sessions
		 SET revoked_at = ?
		 WHERE id = ? AND revoked_at IS NULL`,
		now.Format(time.RFC3339Nano),
		sessionID,
	)
	if err != nil {
		return fmt.Errorf("revoke auth session: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read revoked row count: %w", err)
	}
	if rows == 0 {
		return ErrSessionNotFound
	}

	return nil
}

func parseRFC3339Time(raw string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.UTC(), nil
}
