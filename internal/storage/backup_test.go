package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBackupRestoreAndFactoryReset(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "homepki.db")
	configPath := filepath.Join(tempDir, "config.yaml")
	stepPath := filepath.Join(tempDir, ".step")
	if err := os.MkdirAll(filepath.Join(stepPath, "secrets"), 0o700); err != nil {
		t.Fatalf("create step fixture dir: %v", err)
	}

	if err := os.WriteFile(dbPath, []byte("db-content"), 0o600); err != nil {
		t.Fatalf("write db fixture: %v", err)
	}
	if err := os.WriteFile(configPath, []byte("config-content"), 0o600); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stepPath, "secrets", "ca.key"), []byte("ca-key"), 0o600); err != nil {
		t.Fatalf("write ca key fixture: %v", err)
	}

	archivePath := filepath.Join(tempDir, "backup.tar.gz")
	if err := CreateBackupArchive(archivePath, []string{dbPath, configPath, stepPath}); err != nil {
		t.Fatalf("create backup archive: %v", err)
	}

	restoreDir := filepath.Join(tempDir, "restore")
	if err := os.MkdirAll(restoreDir, 0o755); err != nil {
		t.Fatalf("mkdir restore dir: %v", err)
	}
	if err := RestoreBackupArchive(archivePath, restoreDir); err != nil {
		t.Fatalf("restore backup archive: %v", err)
	}

	restoredDB, err := os.ReadFile(filepath.Join(restoreDir, "homepki.db"))
	if err != nil {
		t.Fatalf("read restored db: %v", err)
	}
	if string(restoredDB) != "db-content" {
		t.Fatalf("unexpected restored db content: %q", string(restoredDB))
	}
	restoredCAKey, err := os.ReadFile(filepath.Join(restoreDir, ".step", "secrets", "ca.key"))
	if err != nil {
		t.Fatalf("read restored ca key: %v", err)
	}
	if string(restoredCAKey) != "ca-key" {
		t.Fatalf("unexpected restored ca key: %q", string(restoredCAKey))
	}

	if err := FactoryResetSQLite(dbPath); err != nil {
		t.Fatalf("factory reset sqlite: %v", err)
	}
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatalf("expected db file to be removed, got err=%v", err)
	}
	if err := FactoryResetPath(stepPath); err != nil {
		t.Fatalf("factory reset protected path: %v", err)
	}
	if _, err := os.Stat(stepPath); !os.IsNotExist(err) {
		t.Fatalf("expected protected path to be removed, got err=%v", err)
	}
}
