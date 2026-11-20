package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var migrationFilePattern = regexp.MustCompile(`^([0-9]{4})_(.+)\.(up|down)\.sql$`)

type migration struct {
	Version int
	Name    string
	UpSQL   string
	DownSQL string
}

func ApplyMigrationsFromDir(ctx context.Context, db *sql.DB, dir string) error {
	if db == nil {
		return errors.New("db is required")
	}
	if strings.TrimSpace(dir) == "" {
		return errors.New("migrations directory is required")
	}

	migrations, err := loadMigrationsFromDir(dir)
	if err != nil {
		return err
	}

	if err := ensureMigrationsTable(ctx, db); err != nil {
		return err
	}

	applied, err := readAppliedVersions(ctx, db)
	if err != nil {
		return err
	}

	for _, m := range migrations {
		if _, ok := applied[m.Version]; ok {
			continue
		}

		if strings.TrimSpace(m.UpSQL) == "" {
			return fmt.Errorf("missing up migration for version %04d", m.Version)
		}

		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %04d: %w", m.Version, err)
		}

		if _, err := tx.ExecContext(ctx, m.UpSQL); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %04d: %w", m.Version, err)
		}

		if _, err := tx.ExecContext(
			ctx,
			"INSERT INTO schema_migrations(version, name, applied_at) VALUES(?, ?, ?)",
			m.Version,
			m.Name,
			time.Now().UTC().Format(time.RFC3339Nano),
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %04d: %w", m.Version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %04d: %w", m.Version, err)
		}
	}

	return nil
}

func RollbackMigrationsFromDir(ctx context.Context, db *sql.DB, dir string, steps int) error {
	if db == nil {
		return errors.New("db is required")
	}
	if strings.TrimSpace(dir) == "" {
		return errors.New("migrations directory is required")
	}
	if steps <= 0 {
		return errors.New("rollback steps must be greater than zero")
	}

	migrations, err := loadMigrationsFromDir(dir)
	if err != nil {
		return err
	}

	if err := ensureMigrationsTable(ctx, db); err != nil {
		return err
	}

	rows, err := db.QueryContext(
		ctx,
		"SELECT version FROM schema_migrations ORDER BY version DESC LIMIT ?",
		steps,
	)
	if err != nil {
		return fmt.Errorf("read versions for rollback: %w", err)
	}
	defer rows.Close()

	versions := make([]int, 0, steps)
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return fmt.Errorf("scan rollback version: %w", err)
		}
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate rollback versions: %w", err)
	}

	migrationsByVersion := make(map[int]migration, len(migrations))
	for _, m := range migrations {
		migrationsByVersion[m.Version] = m
	}

	for _, version := range versions {
		m, ok := migrationsByVersion[version]
		if !ok {
			return fmt.Errorf("missing migration files for version %04d", version)
		}
		if strings.TrimSpace(m.DownSQL) == "" {
			return fmt.Errorf("missing down migration for version %04d", version)
		}

		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin rollback %04d: %w", version, err)
		}

		if _, err := tx.ExecContext(ctx, m.DownSQL); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply rollback %04d: %w", version, err)
		}

		if _, err := tx.ExecContext(ctx, "DELETE FROM schema_migrations WHERE version = ?", version); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("delete migration record %04d: %w", version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit rollback %04d: %w", version, err)
		}
	}

	return nil
}

func loadMigrationsFromDir(dir string) ([]migration, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations directory: %w", err)
	}

	byVersion := map[int]migration{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		match := migrationFilePattern.FindStringSubmatch(name)
		if match == nil {
			continue
		}

		version, err := strconv.Atoi(match[1])
		if err != nil {
			return nil, fmt.Errorf("invalid migration version in %q: %w", name, err)
		}

		sqlBytes, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", name, err)
		}

		m := byVersion[version]
		m.Version = version
		m.Name = match[2]

		switch match[3] {
		case "up":
			if m.UpSQL != "" {
				return nil, fmt.Errorf("duplicate up migration for version %04d", version)
			}
			m.UpSQL = string(sqlBytes)
		case "down":
			if m.DownSQL != "" {
				return nil, fmt.Errorf("duplicate down migration for version %04d", version)
			}
			m.DownSQL = string(sqlBytes)
		default:
			return nil, fmt.Errorf("unsupported migration direction in %q", name)
		}

		byVersion[version] = m
	}

	versions := make([]int, 0, len(byVersion))
	for version := range byVersion {
		versions = append(versions, version)
	}
	sort.Ints(versions)

	migrations := make([]migration, 0, len(versions))
	for _, version := range versions {
		m := byVersion[version]
		if strings.TrimSpace(m.UpSQL) == "" {
			return nil, fmt.Errorf("missing up migration file for version %04d", version)
		}
		migrations = append(migrations, m)
	}

	return migrations, nil
}

func ensureMigrationsTable(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(
		ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at TEXT NOT NULL
		)`,
	)
	if err != nil {
		return fmt.Errorf("create schema_migrations table: %w", err)
	}
	return nil
}

func readAppliedVersions(ctx context.Context, db *sql.DB) (map[int]struct{}, error) {
	rows, err := db.QueryContext(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return nil, fmt.Errorf("read applied migration versions: %w", err)
	}
	defer rows.Close()

	applied := map[int]struct{}{}
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("scan applied version: %w", err)
		}
		applied[version] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate applied versions: %w", err)
	}

	return applied, nil
}
