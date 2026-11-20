package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type SetupState string

const (
	SetupStateNotInitialized   SetupState = "not_initialized"
	SetupStatePrerequisites    SetupState = "prerequisites"
	SetupStateCAProvisioning   SetupState = "ca_provisioning"
	SetupStateComplete         SetupState = "complete"
	SetupStateRecoverableError SetupState = "recoverable_failure"
)

var ErrInvalidSetupTransition = errors.New("invalid setup state transition")

var allowedSetupTransitions = map[SetupState]map[SetupState]struct{}{
	SetupStateNotInitialized: {
		SetupStatePrerequisites: {}},
	SetupStatePrerequisites: {
		SetupStateCAProvisioning:   {},
		SetupStateRecoverableError: {},
	},
	SetupStateCAProvisioning: {
		SetupStateComplete:         {},
		SetupStateRecoverableError: {},
	},
	SetupStateComplete: {
		SetupStateRecoverableError: {},
	},
	SetupStateRecoverableError: {
		SetupStatePrerequisites: {},
	},
}

func GetSetupState(ctx context.Context, db *sql.DB) (SetupState, string, error) {
	if db == nil {
		return "", "", errors.New("db is required")
	}

	stateValue, err := getSetupStateValue(ctx, db, "setup_state.current")
	if err != nil {
		return "", "", err
	}
	if stateValue == "" {
		return SetupStateNotInitialized, "", nil
	}

	reasonValue, err := getSetupStateValue(ctx, db, "setup_state.reason")
	if err != nil {
		return "", "", err
	}

	return SetupState(stateValue), reasonValue, nil
}

func TransitionSetupState(ctx context.Context, db *sql.DB, next SetupState, reason string, now time.Time) error {
	if db == nil {
		return errors.New("db is required")
	}
	if next == "" {
		return errors.New("next setup state is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	current, _, err := GetSetupState(ctx, db)
	if err != nil {
		return err
	}

	if !isAllowedSetupTransition(current, next) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidSetupTransition, current, next)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin setup state transition: %w", err)
	}

	if err := upsertSetupStateValue(ctx, tx, "setup_state.current", string(next), now); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := upsertSetupStateValue(ctx, tx, "setup_state.reason", reason, now); err != nil {
		_ = tx.Rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit setup state transition: %w", err)
	}

	return nil
}

func isAllowedSetupTransition(from, to SetupState) bool {
	nextStates, ok := allowedSetupTransitions[from]
	if !ok {
		return false
	}
	_, ok = nextStates[to]
	return ok
}

func getSetupStateValue(ctx context.Context, db *sql.DB, key string) (string, error) {
	var value string
	err := db.QueryRowContext(
		ctx,
		"SELECT value FROM setup_state WHERE key = ?",
		key,
	).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("query setup_state key %q: %w", key, err)
	}

	return value, nil
}

func upsertSetupStateValue(ctx context.Context, tx *sql.Tx, key, value string, now time.Time) error {
	_, err := tx.ExecContext(
		ctx,
		`INSERT INTO setup_state(key, value, updated_at)
		 VALUES (?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key,
		value,
		now.Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("upsert setup_state key %q: %w", key, err)
	}

	return nil
}
