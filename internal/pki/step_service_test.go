package pki

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStepCAServiceRecognizesExistingProvisioning(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	rootPath := filepath.Join(tempDir, "root_ca.crt")
	writeTestCertificate(t, rootPath)

	service := StepCAService{Config: StepCAConfig{
		RootCertificatePath: rootPath,
	}}

	result, err := service.ProvisionCA(context.Background(), ProvisionCAParams{
		RootCommonName: "HomePKI Root CA",
	})
	if err != nil {
		t.Fatalf("provision existing ca: %v", err)
	}
	if result.CAID == "" {
		t.Fatalf("expected non-empty ca id")
	}
}

func TestStepCAServiceStartsSystemdUnit(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	argumentsPath := filepath.Join(tempDir, "arguments.txt")
	systemctlPath := filepath.Join(tempDir, "systemctl")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argumentsPath + "\n"
	if err := os.WriteFile(systemctlPath, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake systemctl: %v", err)
	}

	service := StepCAService{Config: StepCAConfig{
		SystemctlBinary: systemctlPath,
		CAServiceName:   "homepki-step-ca.service",
	}}
	if err := service.StartCA(context.Background()); err != nil {
		t.Fatalf("start ca: %v", err)
	}

	arguments, err := os.ReadFile(argumentsPath)
	if err != nil {
		t.Fatalf("read systemctl arguments: %v", err)
	}
	if string(arguments) != "start\nhomepki-step-ca.service\n" {
		t.Fatalf("unexpected systemctl arguments: %q", string(arguments))
	}
}

func TestStepCAServiceIssuesCertificate(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	certificateFixture := filepath.Join(tempDir, "certificate.pem")
	keyFixture := filepath.Join(tempDir, "private-key.pem")
	writeTestCertificate(t, certificateFixture)
	if err := os.WriteFile(keyFixture, []byte("PRIVATE KEY"), 0o600); err != nil {
		t.Fatalf("write key fixture: %v", err)
	}

	stepPath := filepath.Join(tempDir, "step")
	script := fmt.Sprintf("#!/bin/sh\ncp %q \"$4\"\ncp %q \"$5\"\n", certificateFixture, keyFixture)
	if err := os.WriteFile(stepPath, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake step: %v", err)
	}

	service := StepCAService{Config: StepCAConfig{
		StepBinary:  stepPath,
		Provisioner: "homepki",
	}}
	result, err := service.IssueCertificate(context.Background(), IssueCertificateRequest{
		CommonName: "service.home.example",
		DNSNames:   []string{"service.home.example"},
		TTL:        24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}
	if result.SerialNumber != "1" {
		t.Fatalf("unexpected serial number: %s", result.SerialNumber)
	}
	if string(result.PrivateKeyPEM) != "PRIVATE KEY" {
		t.Fatalf("unexpected private key: %q", string(result.PrivateKeyPEM))
	}
}

func TestStepCAServiceProvisionsYubiKeyPKI(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	stepPath := filepath.Join(tempDir, ".step")
	rootPath := filepath.Join(stepPath, "certs", "root_ca.crt")
	certificateFixture := filepath.Join(tempDir, "certificate.pem")
	pinFile := filepath.Join(tempDir, "yubikey-pin")
	writeTestCertificate(t, certificateFixture)

	stepBinary := filepath.Join(tempDir, "step")
	script := fmt.Sprintf(`#!/bin/sh
if [ "$1" = "ca" ] && [ "$2" = "init" ]; then
  mkdir -p %q/config %q/certs
  printf '{}\n' > %q/config/ca.json
  exit 0
fi
if [ "$1" = "certificate" ]; then
  for arg in "$@"; do output="$arg"; done
  cp %q "$output"
fi
exit 0
`, stepPath, stepPath, stepPath, certificateFixture)
	if err := os.WriteFile(stepBinary, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake step: %v", err)
	}

	service := StepCAService{Config: StepCAConfig{
		StepBinary:              stepBinary,
		StepPath:                stepPath,
		RootCertificatePath:     rootPath,
		Provisioner:             "homepki",
		UseYubiKey:              true,
		YubiKeyPINFile:          pinFile,
		YubiKeyRootSlot:         "82",
		YubiKeyIntermediateSlot: "83",
	}}

	result, err := service.ProvisionCA(context.Background(), ProvisionCAParams{
		RootCommonName:         "HomePKI Root CA",
		IntermediateCommonName: "HomePKI Intermediate CA",
		YubiKeyPIN:             "654321",
	})
	if err != nil {
		t.Fatalf("provision yubikey ca: %v", err)
	}
	if result.CAID == "" {
		t.Fatalf("expected ca id")
	}

	pinContents, err := os.ReadFile(pinFile)
	if err != nil {
		t.Fatalf("read pin file: %v", err)
	}
	if string(pinContents) != "654321\n" {
		t.Fatalf("unexpected pin file content: %q", string(pinContents))
	}

	configContents, err := os.ReadFile(filepath.Join(stepPath, "config", "ca.json"))
	if err != nil {
		t.Fatalf("read ca config: %v", err)
	}
	configText := string(configContents)
	if !strings.Contains(configText, `"key": "yubikey:slot-id=83"`) {
		t.Fatalf("expected yubykey intermediate key in config, got %s", configText)
	}
	if !strings.Contains(configText, `"type": "yubikey"`) {
		t.Fatalf("expected yubikey kms config, got %s", configText)
	}
}

func TestStepCAServiceRevokesWithOneTimeToken(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	argumentsPath := filepath.Join(tempDir, "revoke-arguments.txt")
	stepBinary := filepath.Join(tempDir, "step")
	script := fmt.Sprintf(`#!/bin/sh
if [ "$2" = "token" ]; then
  printf 'revoke-token\n'
  exit 0
fi
if [ "$2" = "revoke" ]; then
  printf '%%s\n' "$@" > %q
  exit 0
fi
exit 2
`, argumentsPath)
	if err := os.WriteFile(stepBinary, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake step: %v", err)
	}

	service := StepCAService{Config: StepCAConfig{
		StepBinary:              stepBinary,
		CAURL:                   "https://ca.example:443",
		RootCertificatePath:     "/tmp/root.crt",
		Provisioner:             "homepki",
		ProvisionerPasswordFile: "/tmp/password",
	}}
	if err := service.RevokeCertificate(context.Background(), RevokeCertificateRequest{
		SerialNumber: "ABC123",
		Reason:       "CessationOfOperation",
	}); err != nil {
		t.Fatalf("revoke certificate: %v", err)
	}

	arguments, err := os.ReadFile(argumentsPath)
	if err != nil {
		t.Fatalf("read revoke arguments: %v", err)
	}
	if !strings.Contains(string(arguments), "--token\nrevoke-token") {
		t.Fatalf("expected revoke token, got %s", string(arguments))
	}
	if !strings.Contains(string(arguments), "\n11256099\n") {
		t.Fatalf("expected normalized hexadecimal serial, got %s", string(arguments))
	}
	if strings.Contains(string(arguments), "--provisioner") {
		t.Fatalf("revoke command must not receive provisioner flags, got %s", string(arguments))
	}
}

func writeTestCertificate(t *testing.T, path string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "HomePKI Test Root",
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}

	contents := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write test certificate: %v", err)
	}
}
