package yubikey

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type CommandClientConfig struct {
	YKManBinary string
	PKCS11Tool  string
	LibraryPath string
	SigningSlot string
	StepBinary  string
}

type CommandClient struct {
	Config CommandClientConfig
}

func (c CommandClient) Discover(ctx context.Context) ([]Device, error) {
	binary := c.Config.YKManBinary
	if binary == "" {
		binary = "ykman"
	}

	cmd := exec.CommandContext(ctx, binary, "list", "--serials")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, fmt.Errorf("find ykman: %w", err)
		}
		return nil, fmt.Errorf("run ykman list: %w: %s", err, strings.TrimSpace(string(output)))
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	devices := make([]Device, 0, len(lines))
	for _, line := range lines {
		serial := strings.TrimSpace(line)
		if serial == "" {
			continue
		}
		device := Device{
			Serial: serial,
			Model:  "YubiKey",
		}

		infoCmd := exec.CommandContext(ctx, binary, "--device", serial, "info")
		infoOutput, infoErr := infoCmd.CombinedOutput()
		if infoErr == nil {
			device.Model, device.Firmware, device.HasPIV = parseYKManInfo(string(infoOutput))
		}
		devices = append(devices, device)
	}

	if len(devices) == 0 {
		return nil, errors.New("no YubiKey devices found")
	}
	return devices, nil
}

func parseYKManInfo(output string) (model, firmware string, hasPIV bool) {
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		fields := strings.Fields(line)
		switch {
		case strings.HasPrefix(line, "Device type:"):
			model = strings.TrimSpace(strings.TrimPrefix(line, "Device type:"))
		case strings.HasPrefix(line, "Firmware version:"):
			firmware = strings.TrimSpace(strings.TrimPrefix(line, "Firmware version:"))
		case len(fields) >= 2 && fields[0] == "PIV":
			hasPIV = fields[1] == "Enabled"
		}
	}
	return model, firmware, hasPIV
}

func (c CommandClient) DetectPKCS11(ctx context.Context) (PKCS11Capabilities, error) {
	if c.Config.StepBinary != "" && c.Config.LibraryPath == "" {
		cmd := exec.CommandContext(ctx, c.Config.StepBinary, "kms", "--help")
		if output, err := cmd.CombinedOutput(); err != nil {
			return PKCS11Capabilities{}, fmt.Errorf("detect step kms yubikey support: %w: %s", err, strings.TrimSpace(string(output)))
		}
		return PKCS11Capabilities{
			LibraryPath: "step-kms-yubikey",
			SupportsRSA: true,
			SupportsECC: true,
		}, nil
	}

	if c.Config.LibraryPath == "" {
		return PKCS11Capabilities{}, errors.New("pkcs11 library path is required")
	}
	info, err := os.Stat(c.Config.LibraryPath)
	if err != nil {
		return PKCS11Capabilities{}, fmt.Errorf("stat pkcs11 library: %w", err)
	}
	if info.IsDir() {
		return PKCS11Capabilities{}, errors.New("pkcs11 library path is a directory")
	}

	binary := c.Config.PKCS11Tool
	if binary == "" {
		binary = "pkcs11-tool"
	}

	cmd := exec.CommandContext(ctx, binary, "--module", c.Config.LibraryPath, "--list-slots")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return PKCS11Capabilities{}, fmt.Errorf("list pkcs11 slots: %w: %s", err, strings.TrimSpace(string(output)))
	}

	text := strings.ToLower(string(output))
	return PKCS11Capabilities{
		LibraryPath: c.Config.LibraryPath,
		SupportsRSA: strings.Contains(text, "rsa"),
		SupportsECC: strings.Contains(text, "ec") || strings.Contains(text, "ecdsa"),
	}, nil
}

func (c CommandClient) Sign(ctx context.Context, req SignRequest) (SignResult, error) {
	if len(req.Digest) == 0 {
		return SignResult{}, errors.New("digest is required")
	}
	if req.PIN == "" {
		return SignResult{}, errors.New("pin is required")
	}

	keySlot := strings.TrimSpace(req.KeySlot)
	if keySlot == "" {
		keySlot = c.Config.SigningSlot
	}
	if keySlot == "" {
		keySlot = "83"
	}

	if c.Config.StepBinary != "" {
		return c.signWithStepKMS(ctx, req, keySlot)
	}

	inputFile, err := os.CreateTemp("", "homepki-sign-input-*")
	if err != nil {
		return SignResult{}, fmt.Errorf("create signing input: %w", err)
	}
	inputPath := inputFile.Name()
	defer os.Remove(inputPath)
	if _, err := inputFile.Write(req.Digest); err != nil {
		inputFile.Close()
		return SignResult{}, fmt.Errorf("write signing input: %w", err)
	}
	inputFile.Close()

	outputFile, err := os.CreateTemp("", "homepki-sign-output-*")
	if err != nil {
		return SignResult{}, fmt.Errorf("create signing output: %w", err)
	}
	outputPath := outputFile.Name()
	outputFile.Close()
	defer os.Remove(outputPath)

	mechanism := strings.TrimSpace(req.Algorithm)
	if mechanism == "" {
		mechanism = "RSA-PKCS"
	}
	binary := c.Config.PKCS11Tool
	if binary == "" {
		binary = "pkcs11-tool"
	}

	args := []string{
		"--module", c.Config.LibraryPath,
		"--sign",
		"--mechanism", mechanism,
		"--id", keySlot,
		"--pin", req.PIN,
		"--input-file", inputPath,
		"--output-file", outputPath,
	}

	cmd := exec.CommandContext(ctx, binary, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		classified := classifyPKCS11Error(err, string(output))
		return SignResult{}, classified
	}

	signature, err := os.ReadFile(outputPath)
	if err != nil {
		return SignResult{}, fmt.Errorf("read signing output: %w", err)
	}
	return SignResult{Signature: signature}, nil
}

func (c CommandClient) signWithStepKMS(ctx context.Context, req SignRequest, keySlot string) (SignResult, error) {
	pinFile, err := os.CreateTemp("", "homepki-yubikey-pin-*")
	if err != nil {
		return SignResult{}, fmt.Errorf("create temporary yubikey pin file: %w", err)
	}
	pinPath := pinFile.Name()
	defer os.Remove(pinPath)
	_ = pinFile.Chmod(0o600)
	if _, err := pinFile.WriteString(req.PIN); err != nil {
		pinFile.Close()
		return SignResult{}, fmt.Errorf("write temporary yubikey pin file: %w", err)
	}
	pinFile.Close()

	inputFile, err := os.CreateTemp("", "homepki-sign-input-*")
	if err != nil {
		return SignResult{}, fmt.Errorf("create signing input: %w", err)
	}
	inputPath := inputFile.Name()
	defer os.Remove(inputPath)
	if _, err := inputFile.Write(req.Digest); err != nil {
		inputFile.Close()
		return SignResult{}, fmt.Errorf("write signing input: %w", err)
	}
	inputFile.Close()

	algorithm := "SHA256"
	switch strings.ToUpper(req.Algorithm) {
	case "RSA-SHA384", "SHA384":
		algorithm = "SHA384"
	case "RSA-SHA512", "SHA512":
		algorithm = "SHA512"
	}

	cmd := exec.CommandContext(
		ctx,
		c.Config.StepBinary,
		"kms", "sign",
		"--in", inputPath,
		"--verify",
		"--alg", algorithm,
		"--format", "raw",
		"--kms", "yubikey:pin-source="+pinPath,
		"yubikey:slot-id="+keySlot,
	)
	signature, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return SignResult{}, classifyPKCS11Error(err, string(exitErr.Stderr))
		}
		return SignResult{}, fmt.Errorf("step kms sign: %w", err)
	}
	return SignResult{Signature: signature}, nil
}

func classifyPKCS11Error(err error, output string) error {
	lower := strings.ToLower(output)
	switch {
	case strings.Contains(lower, "pin") && (strings.Contains(lower, "incorrect") || strings.Contains(lower, "invalid")):
		return fmt.Errorf("invalid yubikey pin: %w", err)
	case strings.Contains(lower, "timeout") || strings.Contains(lower, "touch"):
		return fmt.Errorf("yubikey touch timeout: %w", err)
	case strings.Contains(lower, "not found") || strings.Contains(lower, "no token"):
		return fmt.Errorf("yubikey signing key missing: %w", err)
	default:
		return fmt.Errorf("pkcs11 signing failed: %w: %s", err, strings.TrimSpace(output))
	}
}
