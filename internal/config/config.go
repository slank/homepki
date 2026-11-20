package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Environment string         `yaml:"environment"`
	Server      ServerConfig   `yaml:"server"`
	Security    SecurityConfig `yaml:"security"`
	Storage     StorageConfig  `yaml:"storage"`
	PKI         PKIConfig      `yaml:"pki"`
	YubiKey     YubiKeyConfig  `yaml:"yubikey"`
}

type ServerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type SecurityConfig struct {
	RequireYubiKey                  bool   `yaml:"require_yubikey"`
	AllowInsecureLocalSessionCookie bool   `yaml:"allow_insecure_local_session_cookie"`
	SessionSecret                   string `yaml:"session_secret"`
}

type StorageConfig struct {
	SQLitePath string `yaml:"sqlite_path"`
}

type PKIConfig struct {
	Provider                string   `yaml:"provider"`
	StepBinary              string   `yaml:"step_binary"`
	CAURL                   string   `yaml:"ca_url"`
	RootCertificatePath     string   `yaml:"root_certificate_path"`
	Provisioner             string   `yaml:"provisioner"`
	ProvisionerPasswordFile string   `yaml:"provisioner_password_file"`
	StepPath                string   `yaml:"step_path"`
	CAName                  string   `yaml:"ca_name"`
	CADNSName               string   `yaml:"ca_dns_name"`
	CAAddress               string   `yaml:"ca_address"`
	AdditionalProvisionArgs []string `yaml:"additional_provision_args"`
	StepCABinary            string   `yaml:"step_ca_binary"`
	SystemctlBinary         string   `yaml:"systemctl_binary"`
	SystemctlArgs           []string `yaml:"systemctl_args"`
	CAServiceName           string   `yaml:"ca_service_name"`
	YubiKeyPINFile          string   `yaml:"yubikey_pin_file"`
	YubiKeyRootSlot         string   `yaml:"yubikey_root_slot"`
	YubiKeyIntermediateSlot string   `yaml:"yubikey_intermediate_slot"`
}

type YubiKeyConfig struct {
	YKManBinary    string `yaml:"ykman_binary"`
	PKCS11ToolPath string `yaml:"pkcs11_tool_binary"`
	LibraryPath    string `yaml:"pkcs11_library_path"`
	SigningSlot    string `yaml:"signing_slot"`
}

func Load(path string) (Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(content, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config file: %w", err)
	}

	return cfg, nil
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.Storage.SQLitePath) == "" {
		return errors.New("storage.sqlite_path is required")
	}

	if c.Server.Port < 0 || c.Server.Port > 65535 {
		return errors.New("server.port must be between 0 and 65535")
	}

	if c.Security.AllowInsecureLocalSessionCookie && strings.ToLower(c.Environment) != "development" {
		return errors.New("security.allow_insecure_local_session_cookie is only allowed in development")
	}

	switch c.PKI.Provider {
	case "", "mock":
	case "step":
		if strings.TrimSpace(c.PKI.StepBinary) == "" {
			return errors.New("pki.step_binary is required for step provider")
		}
		if strings.TrimSpace(c.PKI.CAURL) == "" {
			return errors.New("pki.ca_url is required for step provider")
		}
		if strings.TrimSpace(c.PKI.Provisioner) == "" {
			return errors.New("pki.provisioner is required for step provider")
		}
	default:
		return fmt.Errorf("unsupported pki.provider %q", c.PKI.Provider)
	}

	if c.Security.RequireYubiKey &&
		strings.TrimSpace(c.YubiKey.LibraryPath) == "" &&
		(c.PKI.Provider != "step" || strings.TrimSpace(c.PKI.StepBinary) == "") {
		return errors.New("yubikey.pkcs11_library_path or step kms support is required when require_yubikey is true")
	}
	if c.Security.RequireYubiKey && strings.TrimSpace(c.PKI.YubiKeyPINFile) == "" {
		return errors.New("pki.yubikey_pin_file is required when require_yubikey is true")
	}

	return nil
}

func (c Config) SessionSecretFromEnvironment() (string, error) {
	if value := strings.TrimSpace(os.Getenv("HOMEPKI_SESSION_SECRET")); value != "" {
		return value, nil
	}

	if value := strings.TrimSpace(c.Security.SessionSecret); value != "" {
		return value, nil
	}

	return "", errors.New("session secret is required in HOMEPKI_SESSION_SECRET or security.session_secret")
}
