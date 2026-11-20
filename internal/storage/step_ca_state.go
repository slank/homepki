package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type StepCAProvisionState struct {
	Status                  string
	CAID                    string
	RootFingerprint         string
	IntermediateFingerprint string
	LastError               string
	UpdatedAt               time.Time
}

func GetStepCAProvisionState(ctx context.Context, db *sql.DB) (StepCAProvisionState, error) {
	if db == nil {
		return StepCAProvisionState{}, errors.New("db is required")
	}

	var (
		state        StepCAProvisionState
		updatedAtRaw string
	)

	err := db.QueryRowContext(
		ctx,
		`SELECT status, ca_id, root_fingerprint, intermediate_fingerprint, last_error, updated_at
		 FROM step_ca_provision_state
		 WHERE id = 1`,
	).Scan(
		&state.Status,
		&state.CAID,
		&state.RootFingerprint,
		&state.IntermediateFingerprint,
		&state.LastError,
		&updatedAtRaw,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return StepCAProvisionState{
			Status: "not_provisioned",
		}, nil
	}
	if err != nil {
		return StepCAProvisionState{}, fmt.Errorf("query step ca provision state: %w", err)
	}

	updatedAt, err := parseRFC3339Time(updatedAtRaw)
	if err != nil {
		return StepCAProvisionState{}, fmt.Errorf("parse step ca updated_at: %w", err)
	}
	state.UpdatedAt = updatedAt

	return state, nil
}

func SaveStepCAProvisionState(ctx context.Context, db *sql.DB, state StepCAProvisionState, now time.Time) error {
	if db == nil {
		return errors.New("db is required")
	}
	if state.Status == "" {
		return errors.New("status is required")
	}

	if now.IsZero() {
		now = time.Now().UTC()
	}

	_, err := db.ExecContext(
		ctx,
		`INSERT INTO step_ca_provision_state
			(id, status, ca_id, root_fingerprint, intermediate_fingerprint, last_error, updated_at)
		 VALUES (1, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
  status = excluded.status,
  ca_id = excluded.ca_id,
  root_fingerprint = excluded.root_fingerprint,
  intermediate_fingerprint = excluded.intermediate_fingerprint,
  last_error = excluded.last_error,
  updated_at = excluded.updated_at`,
		state.Status,
		state.CAID,
		state.RootFingerprint,
		state.IntermediateFingerprint,
		state.LastError,
		now.Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("save step ca provision state: %w", err)
	}

	return nil
}
