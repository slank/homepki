package pki

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type StepCAConfig struct {
	StepBinary              string
	CAURL                   string
	RootCertificatePath     string
	Provisioner             string
	ProvisionerPasswordFile string
	StepPath                string
	CAName                  string
	CADNSName               string
	CAAddress               string
	AdditionalProvisionArgs []string
	StepCABinary            string
	SystemctlBinary         string
	SystemctlArgs           []string
	CAServiceName           string
	UseYubiKey              bool
	YubiKeyPINFile          string
	YubiKeyRootSlot         string
	YubiKeyIntermediateSlot string
	YKManBinary             string
}

func stepCommandEnvironment(stepBinary, stepPath string) []string {
	pathValue := os.Getenv("PATH")
	baseOutput, err := exec.Command(stepBinary, "path", "--base").Output()
	if err == nil {
		pluginDir := filepath.Join(strings.TrimSpace(string(baseOutput)), "plugins")
		if info, statErr := os.Stat(pluginDir); statErr == nil && info.IsDir() {
			pathValue = pluginDir + string(os.PathListSeparator) + pathValue
		}
	}

	env := os.Environ()
	filtered := env[:0]
	for _, value := range env {
		if strings.HasPrefix(value, "PATH=") || strings.HasPrefix(value, "STEPPATH=") {
			continue
		}
		filtered = append(filtered, value)
	}
	filtered = append(filtered, "PATH="+pathValue, "STEPPATH="+stepPath)
	return filtered
}

type StepCAService struct {
	Config StepCAConfig
}

func (s StepCAService) ProvisionCA(ctx context.Context, params ProvisionCAParams) (ProvisionCAResult, error) {
	rootAlreadyInitialized := false
	existingRootPath := s.Config.RootCertificatePath
	if existingRootPath == "" && s.Config.StepPath != "" {
		existingRootPath = filepath.Join(s.Config.StepPath, "certs", "root_ca.crt")
	}
	if existingRootPath != "" {
		if contents, err := os.ReadFile(existingRootPath); err == nil {
			if !s.Config.UseYubiKey || stepCAConfigUsesYubiKey(s.Config.StepPath) {
				rootCertificate, parseErr := parseCertificatePEM(contents)
				if parseErr != nil {
					return ProvisionCAResult{}, parseErr
				}
				return ProvisionCAResult{
					CAID:          hex.EncodeToString(rootCertificate.RawSubjectPublicKeyInfo),
					ProvisionedAt: rootCertificate.NotBefore,
				}, nil
			}
			rootAlreadyInitialized = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return ProvisionCAResult{}, fmt.Errorf("read existing root ca certificate: %w", err)
		}
	}

	stepBinary, err := requireStepBinary(s.Config.StepBinary)
	if err != nil {
		return ProvisionCAResult{}, err
	}

	name := params.RootCommonName
	if name == "" {
		name = s.Config.CAName
	}
	if name == "" {
		return ProvisionCAResult{}, errors.New("root common name is required")
	}

	stepPath := s.Config.StepPath
	if stepPath == "" {
		return ProvisionCAResult{}, errors.New("step path is required for provisioning")
	}

	args := []string{
		"ca", "init",
		"--name", name,
		"--provisioner", s.Config.Provisioner,
		"--deployment-type", "standalone",
	}
	for _, dnsName := range stepCADNSEntries(s.Config.CAURL, s.Config.CADNSName) {
		args = append(args, "--dns", dnsName)
	}
	if s.Config.CAAddress != "" {
		args = append(args, "--address", s.Config.CAAddress)
	}
	if s.Config.ProvisionerPasswordFile != "" {
		args = append(args, "--password-file", s.Config.ProvisionerPasswordFile)
		args = append(args, "--provisioner-password-file", s.Config.ProvisionerPasswordFile)
	}
	args = append(args, s.Config.AdditionalProvisionArgs...)

	if !rootAlreadyInitialized {
		cmd := exec.CommandContext(ctx, stepBinary, args...)
		cmd.Env = stepCommandEnvironment(stepBinary, stepPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return ProvisionCAResult{}, fmt.Errorf("step ca init: %w: %s", err, strings.TrimSpace(string(output)))
		}
	}

	rootPath := s.Config.RootCertificatePath
	if rootPath == "" {
		rootPath = filepath.Join(stepPath, "certs", "root_ca.crt")
	}
	if s.Config.UseYubiKey {
		if err := s.configureYubiKeyCA(ctx, params, stepBinary, stepPath, rootPath); err != nil {
			return ProvisionCAResult{}, err
		}
	}
	if err := s.configureProvisionerDurations(ctx, stepBinary, stepPath); err != nil {
		return ProvisionCAResult{}, err
	}

	contents, err := os.ReadFile(rootPath)
	if err != nil {
		return ProvisionCAResult{}, fmt.Errorf("read root ca certificate: %w", err)
	}

	rootCertificate, err := parseCertificatePEM(contents)
	if err != nil {
		return ProvisionCAResult{}, err
	}

	return ProvisionCAResult{
		CAID:          hex.EncodeToString(rootCertificate.RawSubjectPublicKeyInfo),
		ProvisionedAt: time.Now().UTC(),
	}, nil
}

func (s StepCAService) configureYubiKeyCA(
	ctx context.Context,
	params ProvisionCAParams,
	stepBinary string,
	stepPath string,
	rootPath string,
) error {
	if strings.TrimSpace(params.YubiKeyPIN) == "" {
		return errors.New("yubikey pin is required")
	}
	if s.Config.YubiKeyPINFile == "" {
		return errors.New("yubikey pin file is required")
	}

	rootSlot := s.Config.YubiKeyRootSlot
	if rootSlot == "" {
		rootSlot = "82"
	}
	intermediateSlot := s.Config.YubiKeyIntermediateSlot
	if intermediateSlot == "" {
		intermediateSlot = "83"
	}

	pinFile, err := os.OpenFile(s.Config.YubiKeyPINFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create yubikey pin file: %w", err)
	}
	_, writeErr := pinFile.WriteString(params.YubiKeyPIN + "\n")
	closeErr := pinFile.Close()
	if writeErr != nil {
		return fmt.Errorf("write yubikey pin file: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close yubikey pin file: %w", closeErr)
	}

	kmsURI := "yubikey:pin-source=" + s.Config.YubiKeyPINFile
	rootKeyURI := "yubikey:slot-id=" + rootSlot
	intermediateKeyURI := "yubikey:slot-id=" + intermediateSlot
	rootCertificatePath := rootPath
	intermediateCertificatePath := filepath.Join(stepPath, "certs", "intermediate_ca.crt")

	for _, key := range []struct {
		uri  string
		slot string
	}{
		{uri: rootKeyURI, slot: rootSlot},
		{uri: intermediateKeyURI, slot: intermediateSlot},
	} {
		if err := s.ensureYubiKey(ctx, stepBinary, stepPath, kmsURI, key.uri, key.slot, params.YubiKeyPIN); err != nil {
			return err
		}
	}

	commands := [][]string{
		{"certificate", "create", "--force", "--profile", "root-ca", "--kms", kmsURI, "--key", rootKeyURI, params.RootCommonName, rootCertificatePath},
		{
			"certificate", "create", "--force", "--profile", "intermediate-ca",
			"--kms", kmsURI,
			"--ca-kms", kmsURI,
			"--ca", rootCertificatePath,
			"--ca-key", rootKeyURI,
			"--key", intermediateKeyURI,
			params.IntermediateCommonName,
			intermediateCertificatePath,
		},
	}

	for _, args := range commands {
		cmd := exec.CommandContext(ctx, stepBinary, args...)
		cmd.Env = stepCommandEnvironment(stepBinary, stepPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("configure yubikey step ca (%s): %w: %s", args[0], err, strings.TrimSpace(string(output)))
		}
	}

	configPath := filepath.Join(stepPath, "config", "ca.json")
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read step ca config: %w", err)
	}

	var stepConfig map[string]any
	if err := json.Unmarshal(configBytes, &stepConfig); err != nil {
		return fmt.Errorf("parse step ca config: %w", err)
	}
	stepConfig["root"] = rootCertificatePath
	stepConfig["crt"] = intermediateCertificatePath
	stepConfig["key"] = intermediateKeyURI
	stepConfig["kms"] = map[string]any{
		"type": "yubikey",
		"uri":  kmsURI,
	}

	updatedConfig, err := json.MarshalIndent(stepConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal step ca config: %w", err)
	}
	if err := os.WriteFile(configPath, append(updatedConfig, '\n'), 0o600); err != nil {
		return fmt.Errorf("write step ca config: %w", err)
	}

	for _, generatedKeyPath := range []string{
		filepath.Join(stepPath, "secrets", "root_ca_key"),
		filepath.Join(stepPath, "secrets", "intermediate_ca_key"),
	} {
		if err := os.Remove(generatedKeyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove superseded software key %q: %w", generatedKeyPath, err)
		}
	}

	return nil
}

func (s StepCAService) configureProvisionerDurations(ctx context.Context, stepBinary, stepPath string) error {
	if strings.TrimSpace(s.Config.Provisioner) == "" {
		return errors.New("provisioner is required to configure certificate duration policy")
	}
	configPath := filepath.Join(stepPath, "config", "ca.json")
	args := []string{
		"ca", "provisioner", "update", s.Config.Provisioner,
		"--ca-config", configPath,
		"--x509-min-dur", "5m",
		"--x509-default-dur", "2160h",
		"--x509-max-dur", "17520h",
	}
	cmd := exec.CommandContext(ctx, stepBinary, args...)
	cmd.Env = stepCommandEnvironment(stepBinary, stepPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("configure provisioner duration policy: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func stepCAConfigUsesYubiKey(stepPath string) bool {
	configBytes, err := os.ReadFile(filepath.Join(stepPath, "config", "ca.json"))
	if err != nil {
		return false
	}
	var config struct {
		Key string `json:"key"`
		KMS struct {
			Type string `json:"type"`
		} `json:"kms"`
	}
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return false
	}
	return config.KMS.Type == "yubikey" && strings.HasPrefix(config.Key, "yubikey:")
}

func (s StepCAService) ensureYubiKey(
	ctx context.Context,
	stepBinary string,
	stepPath string,
	kmsURI string,
	keyURI string,
	slot string,
	pin string,
) error {
	keyCmd := exec.CommandContext(ctx, stepBinary, "kms", "key", "--kms", kmsURI, keyURI)
	keyCmd.Env = stepCommandEnvironment(stepBinary, stepPath)
	if err := keyCmd.Run(); err == nil {
		return nil
	}

	ykmanBinary := s.Config.YKManBinary
	if ykmanBinary == "" {
		ykmanBinary = "ykman"
	}
	publicKeyFile, err := os.CreateTemp("", "homepki-yubikey-public-*")
	if err != nil {
		return fmt.Errorf("create public key output: %w", err)
	}
	publicKeyPath := publicKeyFile.Name()
	publicKeyFile.Close()
	os.Remove(publicKeyPath)
	defer os.Remove(publicKeyPath)

	generateCmd := exec.CommandContext(
		ctx,
		ykmanBinary,
		"piv", "keys", "generate",
		"--algorithm", "RSA2048",
		"--pin-policy", "ALWAYS",
		"--touch-policy", "ALWAYS",
		"--pin", pin,
		slot,
		publicKeyPath,
	)
	output, err := generateCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("generate yubikey key in slot %s: %w: %s", slot, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (s StepCAService) IssueCertificate(ctx context.Context, req IssueCertificateRequest) (IssueCertificateResult, error) {
	if err := ValidateCertificateRequest(req); err != nil {
		return IssueCertificateResult{}, err
	}

	stepBinary, err := requireStepBinary(s.Config.StepBinary)
	if err != nil {
		return IssueCertificateResult{}, err
	}

	tempDir, err := os.MkdirTemp("", "homepki-issue-*")
	if err != nil {
		return IssueCertificateResult{}, fmt.Errorf("create certificate temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	certificatePath := filepath.Join(tempDir, "certificate.pem")
	privateKeyPath := filepath.Join(tempDir, "private-key.pem")

	args := []string{
		"ca", "certificate",
		req.CommonName,
		certificatePath,
		privateKeyPath,
		"--provisioner", s.Config.Provisioner,
		"--not-after", req.TTL.String(),
		"--force",
	}
	for _, name := range req.DNSNames {
		args = append(args, "--san", name)
	}
	if s.Config.CAURL != "" {
		args = append(args, "--ca-url", s.Config.CAURL)
	}
	if s.Config.RootCertificatePath != "" {
		args = append(args, "--root", s.Config.RootCertificatePath)
	}
	if s.Config.ProvisionerPasswordFile != "" {
		args = append(args, "--provisioner-password-file", s.Config.ProvisionerPasswordFile)
	}

	cmd := exec.CommandContext(ctx, stepBinary, args...)
	cmd.Env = stepCommandEnvironment(stepBinary, s.Config.StepPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return IssueCertificateResult{}, fmt.Errorf("step ca certificate: %w: %s", err, strings.TrimSpace(string(output)))
	}

	certificatePEM, err := os.ReadFile(certificatePath)
	if err != nil {
		return IssueCertificateResult{}, fmt.Errorf("read issued certificate: %w", err)
	}
	privateKeyPEM, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return IssueCertificateResult{}, fmt.Errorf("read issued private key: %w", err)
	}

	certificate, err := parseCertificatePEM(certificatePEM)
	if err != nil {
		return IssueCertificateResult{}, err
	}

	return IssueCertificateResult{
		CertificatePEM: certificatePEM,
		PrivateKeyPEM:  privateKeyPEM,
		SerialNumber:   certificate.SerialNumber.Text(16),
		NotBefore:      certificate.NotBefore,
		NotAfter:       certificate.NotAfter,
	}, nil
}

func (s StepCAService) RevokeCertificate(ctx context.Context, req RevokeCertificateRequest) error {
	if strings.TrimSpace(req.SerialNumber) == "" {
		return errors.New("serial number is required")
	}
	if strings.TrimSpace(req.Reason) == "" {
		req.Reason = "unspecified"
	}
	serialNumber := stepRevocationSerial(req.SerialNumber)

	stepBinary, err := requireStepBinary(s.Config.StepBinary)
	if err != nil {
		return err
	}

	tokenArgs := []string{
		"ca", "token",
		serialNumber,
		"--revoke",
		"--provisioner", s.Config.Provisioner,
		"--ca-url", s.Config.CAURL,
	}
	if s.Config.RootCertificatePath != "" {
		tokenArgs = append(tokenArgs, "--root", s.Config.RootCertificatePath)
	}
	if s.Config.ProvisionerPasswordFile != "" {
		tokenArgs = append(tokenArgs, "--provisioner-password-file", s.Config.ProvisionerPasswordFile)
	}

	tokenCmd := exec.CommandContext(ctx, stepBinary, tokenArgs...)
	tokenCmd.Env = stepCommandEnvironment(stepBinary, s.Config.StepPath)
	tokenOutput, err := tokenCmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("step ca revoke token: %w: %s", err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return fmt.Errorf("step ca revoke token: %w", err)
	}
	token := strings.TrimSpace(string(tokenOutput))
	if token == "" {
		return errors.New("step ca revoke token was empty")
	}

	revokeArgs := []string{
		"ca", "revoke",
		serialNumber,
		"--reason", req.Reason,
		"--token", token,
		"--ca-url", s.Config.CAURL,
	}
	if s.Config.RootCertificatePath != "" {
		revokeArgs = append(revokeArgs, "--root", s.Config.RootCertificatePath)
	}

	revokeCmd := exec.CommandContext(ctx, stepBinary, revokeArgs...)
	revokeCmd.Env = stepCommandEnvironment(stepBinary, s.Config.StepPath)
	output, err := revokeCmd.CombinedOutput()
	if err != nil {
		if strings.Contains(strings.ToLower(string(output)), "already revoked") {
			return nil
		}
		return fmt.Errorf("step ca revoke: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func stepRevocationSerial(serialNumber string) string {
	serialNumber = strings.TrimSpace(serialNumber)
	normalized := serialNumber
	decimalOnly := true
	for _, char := range normalized {
		if char < '0' || char > '9' {
			decimalOnly = false
			break
		}
	}
	if decimalOnly {
		return normalized
	}

	normalized = strings.TrimPrefix(strings.TrimPrefix(normalized, "0x"), "0X")
	hexValue, ok := new(big.Int).SetString(normalized, 16)
	if !ok {
		return serialNumber
	}
	return hexValue.String()
}

func (s StepCAService) GetCertificate(ctx context.Context, serialNumber string) (CertificateRecord, error) {
	if strings.TrimSpace(serialNumber) == "" {
		return CertificateRecord{}, errors.New("serial number is required")
	}
	return CertificateRecord{SerialNumber: serialNumber}, nil
}

func (s StepCAService) StartCA(ctx context.Context) error {
	systemctl := s.Config.SystemctlBinary
	if systemctl == "" && s.Config.CAServiceName == "" {
		return nil
	}
	if systemctl == "" {
		systemctl = "systemctl"
	}
	serviceName := s.Config.CAServiceName
	if serviceName == "" {
		serviceName = "homepki-step-ca.service"
	}

	args := append([]string{}, s.Config.SystemctlArgs...)
	args = append(args, "start", serviceName)
	cmd := exec.CommandContext(ctx, systemctl, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("start step ca service: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func ValidateCertificateRequest(req IssueCertificateRequest) error {
	if strings.TrimSpace(req.CommonName) == "" {
		return errors.New("common name is required")
	}
	if req.TTL <= 0 {
		return errors.New("certificate lifetime must be greater than zero")
	}
	if req.TTL > 730*24*time.Hour {
		return errors.New("certificate lifetime cannot exceed 2 years")
	}
	for _, name := range append([]string{req.CommonName}, req.DNSNames...) {
		if strings.TrimSpace(name) == "" || !validDNSName(name) {
			return fmt.Errorf("invalid dns name %q", name)
		}
	}
	return nil
}

func validDNSName(name string) bool {
	name = strings.TrimSuffix(name, ".")
	labels := strings.Split(name, ".")
	if len(labels) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		for index, char := range label {
			alphanumeric := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9'
			hyphen := char == '-'
			if !alphanumeric && !hyphen {
				return false
			}
			if hyphen && (index == 0 || index == len(label)-1) {
				return false
			}
		}
	}
	return true
}

func requireStepBinary(binary string) (string, error) {
	if binary == "" {
		binary = "step"
	}
	resolved, err := exec.LookPath(binary)
	if err != nil {
		return "", fmt.Errorf("find step binary: %w", err)
	}
	return resolved, nil
}

func parseCertificatePEM(contents []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(contents)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("certificate file does not contain a PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return certificate, nil
}

func stepCADNSEntries(caURL, configuredName string) []string {
	seen := map[string]struct{}{}
	dnsEntries := make([]string, 0, 2)
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, exists := seen[value]; exists {
			return
		}
		seen[value] = struct{}{}
		dnsEntries = append(dnsEntries, value)
	}

	add(configuredName)
	if parsed, err := url.Parse(strings.TrimSpace(caURL)); err == nil {
		add(parsed.Hostname())
	}
	return dnsEntries
}
