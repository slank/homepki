package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type AuditEvent struct {
	ID         int64
	ActorType  string
	ActorID    string
	Action     string
	TargetType string
	TargetID   string
	Outcome    string
	Details    string
	CreatedAt  time.Time
}

type AppendAuditEventParams struct {
	ActorType  string
	ActorID    string
	Action     string
	TargetType string
	TargetID   string
	Outcome    string
	Details    map[string]string
	Now        time.Time
}

func AppendAuditEvent(ctx context.Context, db *sql.DB, params AppendAuditEventParams) error {
	if db == nil {
		return errors.New("db is required")
	}
	if params.ActorType == "" {
		return errors.New("actor_type is required")
	}
	if params.Action == "" {
		return errors.New("action is required")
	}
	if params.TargetType == "" {
		return errors.New("target_type is required")
	}
	if params.Outcome == "" {
		return errors.New("outcome is required")
	}

	now := params.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	detailsJSON, err := json.Marshal(params.Details)
	if err != nil {
		return fmt.Errorf("marshal audit details: %w", err)
	}

	_, err = db.ExecContext(
		ctx,
		`INSERT INTO audit_events
			(actor_type, actor_id, action, target_type, target_id, outcome, details_json, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		params.ActorType,
		params.ActorID,
		params.Action,
		params.TargetType,
		params.TargetID,
		params.Outcome,
		string(detailsJSON),
		now.Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}

	return nil
}
