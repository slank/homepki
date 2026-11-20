package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var ErrCertificateNotFound = errors.New("certificate not found")

type CreateCertificateParams struct {
	SerialNumber string
	CommonName   string
	SANs         []string
	NotBefore    time.Time
	NotAfter     time.Time
	Status       string
	Now          time.Time
}

type Certificate struct {
	ID           int64      `json:"id"`
	SerialNumber string     `json:"serial_number"`
	CommonName   string     `json:"common_name"`
	SANs         []string   `json:"sans"`
	NotBefore    time.Time  `json:"not_before"`
	NotAfter     time.Time  `json:"not_after"`
	Status       string     `json:"status"`
	CreatedAt    time.Time  `json:"created_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

func CreateCertificate(ctx context.Context, db *sql.DB, params CreateCertificateParams) (Certificate, error) {
	if db == nil {
		return Certificate{}, errors.New("db is required")
	}
	if params.SerialNumber == "" {
		return Certificate{}, errors.New("serial number is required")
	}
	if params.CommonName == "" {
		return Certificate{}, errors.New("common name is required")
	}
	if params.NotBefore.IsZero() || params.NotAfter.IsZero() {
		return Certificate{}, errors.New("certificate validity window is required")
	}
	if params.Status == "" {
		params.Status = "active"
	}
	if params.Now.IsZero() {
		params.Now = time.Now().UTC()
	}

	sansJSON, err := json.Marshal(params.SANs)
	if err != nil {
		return Certificate{}, fmt.Errorf("marshal certificate sans: %w", err)
	}

	_, err = db.ExecContext(
		ctx,
		`INSERT INTO certificates
			(serial_number, common_name, sans_json, not_before, not_after, status, created_at, revoked_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
		params.SerialNumber,
		params.CommonName,
		string(sansJSON),
		params.NotBefore.UTC().Format(time.RFC3339Nano),
		params.NotAfter.UTC().Format(time.RFC3339Nano),
		params.Status,
		params.Now.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return Certificate{}, fmt.Errorf("insert certificate: %w", err)
	}

	return GetCertificateBySerial(ctx, db, params.SerialNumber)
}

func ListCertificates(ctx context.Context, db *sql.DB) ([]Certificate, error) {
	if db == nil {
		return nil, errors.New("db is required")
	}

	rows, err := db.QueryContext(
		ctx,
		`SELECT id, serial_number, common_name, sans_json, not_before, not_after, status, created_at, revoked_at
		 FROM certificates
		 ORDER BY id DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	defer rows.Close()

	var certificates []Certificate
	for rows.Next() {
		certificate, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate certificates: %w", err)
	}

	return certificates, nil
}

func GetCertificateBySerial(ctx context.Context, db *sql.DB, serialNumber string) (Certificate, error) {
	if db == nil {
		return Certificate{}, errors.New("db is required")
	}
	if serialNumber == "" {
		return Certificate{}, errors.New("serial number is required")
	}

	rows, err := db.QueryContext(
		ctx,
		`SELECT id, serial_number, common_name, sans_json, not_before, not_after, status, created_at, revoked_at
		 FROM certificates
		 WHERE lower(serial_number) = lower(?)`,
		serialNumber,
	)
	if err != nil {
		return Certificate{}, fmt.Errorf("query certificate: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		return Certificate{}, ErrCertificateNotFound
	}

	certificate, err := scanCertificate(rows)
	if err != nil {
		return Certificate{}, err
	}

	return certificate, nil
}

func RevokeCertificate(ctx context.Context, db *sql.DB, serialNumber string, now time.Time) error {
	if db == nil {
		return errors.New("db is required")
	}
	if serialNumber == "" {
		return errors.New("serial number is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	result, err := db.ExecContext(
		ctx,
		`UPDATE certificates
		 SET status = 'revoked', revoked_at = ?
		 WHERE lower(serial_number) = lower(?)`,
		now.Format(time.RFC3339Nano),
		serialNumber,
	)
	if err != nil {
		return fmt.Errorf("revoke certificate: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read revoked certificate row count: %w", err)
	}
	if rows == 0 {
		return ErrCertificateNotFound
	}

	return nil
}

func DeleteCertificate(ctx context.Context, db *sql.DB, serialNumber string) error {
	if db == nil {
		return errors.New("db is required")
	}
	if serialNumber == "" {
		return errors.New("serial number is required")
	}

	result, err := db.ExecContext(ctx, "DELETE FROM certificates WHERE lower(serial_number) = lower(?)", serialNumber)
	if err != nil {
		return fmt.Errorf("delete certificate: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read deleted certificate row count: %w", err)
	}
	if rows == 0 {
		return ErrCertificateNotFound
	}

	return nil
}

func scanCertificate(scanner interface {
	Scan(dest ...any) error
}) (Certificate, error) {
	var (
		certificate  Certificate
		sansJSON     string
		notBeforeRaw string
		notAfterRaw  string
		createdAtRaw string
		revokedAtRaw sql.NullString
	)

	err := scanner.Scan(
		&certificate.ID,
		&certificate.SerialNumber,
		&certificate.CommonName,
		&sansJSON,
		&notBeforeRaw,
		&notAfterRaw,
		&certificate.Status,
		&createdAtRaw,
		&revokedAtRaw,
	)
	if err != nil {
		return Certificate{}, fmt.Errorf("scan certificate: %w", err)
	}

	if err := json.Unmarshal([]byte(sansJSON), &certificate.SANs); err != nil {
		return Certificate{}, fmt.Errorf("unmarshal certificate sans: %w", err)
	}

	notBefore, err := parseRFC3339Time(notBeforeRaw)
	if err != nil {
		return Certificate{}, fmt.Errorf("parse not_before: %w", err)
	}
	notAfter, err := parseRFC3339Time(notAfterRaw)
	if err != nil {
		return Certificate{}, fmt.Errorf("parse not_after: %w", err)
	}
	createdAt, err := parseRFC3339Time(createdAtRaw)
	if err != nil {
		return Certificate{}, fmt.Errorf("parse created_at: %w", err)
	}

	certificate.NotBefore = notBefore
	certificate.NotAfter = notAfter
	certificate.CreatedAt = createdAt

	if revokedAtRaw.Valid {
		revokedAt, err := parseRFC3339Time(revokedAtRaw.String)
		if err != nil {
			return Certificate{}, fmt.Errorf("parse revoked_at: %w", err)
		}
		certificate.RevokedAt = &revokedAt
	}

	return certificate, nil
}
