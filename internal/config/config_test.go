package config

import "testing"

func TestValidate(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Environment: "development",
		Server: ServerConfig{
			Port: 8080,
		},
		Security: SecurityConfig{
			AllowInsecureLocalSessionCookie: true,
		},
		Storage: StorageConfig{
			SQLitePath: "./homepki-dev.db",
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestValidateRejectsInsecureCookieOutsideDevelopment(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Environment: "production",
		Server: ServerConfig{
			Port: 443,
		},
		Security: SecurityConfig{
			AllowInsecureLocalSessionCookie: true,
		},
		Storage: StorageConfig{
			SQLitePath: "/var/lib/homepki/homepki.db",
		},
	}

	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error")
	}
}

func TestSessionSecretFromEnvironment(t *testing.T) {
	t.Setenv("HOMEPKI_SESSION_SECRET", "env-secret")

	cfg := Config{
		Security: SecurityConfig{
			SessionSecret: "config-secret",
		},
	}

	secret, err := cfg.SessionSecretFromEnvironment()
	if err != nil {
		t.Fatalf("session secret from environment: %v", err)
	}
	if secret != "env-secret" {
		t.Fatalf("expected env secret, got %q", secret)
	}
}

func TestSessionSecretFallbackToConfig(t *testing.T) {
	t.Setenv("HOMEPKI_SESSION_SECRET", "")

	cfg := Config{
		Security: SecurityConfig{
			SessionSecret: "config-secret",
		},
	}

	secret, err := cfg.SessionSecretFromEnvironment()
	if err != nil {
		t.Fatalf("session secret from config: %v", err)
	}
	if secret != "config-secret" {
		t.Fatalf("expected config secret, got %q", secret)
	}
}

func TestApplianceExampleIsValid(t *testing.T) {
	t.Parallel()

	cfg, err := Load("../../configs/appliance.example.yaml")
	if err != nil {
		t.Fatalf("load appliance example: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate appliance example: %v", err)
	}
}
