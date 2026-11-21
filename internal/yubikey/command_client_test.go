package yubikey

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()

	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		t.Fatalf("create temporary executable: %v", err)
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)

	if _, err := file.WriteString(content); err != nil {
		file.Close()
		t.Fatalf("write temporary executable: %v", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		t.Fatalf("sync temporary executable: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close temporary executable: %v", err)
	}
	if err := os.Chmod(tempPath, 0o700); err != nil {
		t.Fatalf("chmod temporary executable: %v", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		t.Fatalf("install fake executable: %v", err)
	}
}

func TestCommandClientDiscover(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	binary := filepath.Join(tempDir, "ykman")
	script := `#!/bin/sh
if [ "$1" = "list" ]; then
  printf '12345678\n87654321\n'
  exit 0
fi
printf 'Device type: YubiKey 5\nFirmware version: 5.7.1\nApplications\nPIV          Enabled\n'
`
	writeExecutable(t, binary, script)

	client := CommandClient{Config: CommandClientConfig{
		YKManBinary: binary,
	}}

	devices, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("discover devices: %v", err)
	}
	if len(devices) != 2 || devices[0].Serial != "12345678" {
		t.Fatalf("unexpected devices: %+v", devices)
	}
	if !devices[0].HasPIV || devices[0].Model != "YubiKey 5" || devices[0].Firmware != "5.7.1" {
		t.Fatalf("unexpected parsed device details: %+v", devices[0])
	}
}

func TestCommandClientReportsPIVUnavailable(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	binary := filepath.Join(tempDir, "ykman")
	script := `#!/bin/sh
if [ "$1" = "list" ]; then
  printf '11112222\n'
  exit 0
fi
printf 'Device type: YubiKey Edge\nFirmware version: 4.3.7\nApplications\nPIV          Not available\n'
`
	writeExecutable(t, binary, script)

	client := CommandClient{Config: CommandClientConfig{YKManBinary: binary}}
	devices, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("discover devices: %v", err)
	}
	if devices[0].HasPIV {
		t.Fatalf("expected PIV to be unavailable: %+v", devices[0])
	}
}

func TestCommandClientDetectPKCS11(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	binary := filepath.Join(tempDir, "pkcs11-tool")
	library := filepath.Join(tempDir, "libykcs11.so")

	writeExecutable(t, binary, "#!/bin/sh\nprintf 'RSA EC ECDSA mechanisms available\\n'\n")
	if err := os.WriteFile(library, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write fake pkcs11 library: %v", err)
	}

	client := CommandClient{Config: CommandClientConfig{
		PKCS11Tool:  binary,
		LibraryPath: library,
	}}

	capabilities, err := client.DetectPKCS11(context.Background())
	if err != nil {
		t.Fatalf("detect pkcs11: %v", err)
	}
	if !capabilities.SupportsRSA || !capabilities.SupportsECC {
		t.Fatalf("unexpected capabilities: %+v", capabilities)
	}
}

func TestCommandClientSign(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	binary := filepath.Join(tempDir, "pkcs11-tool")
	library := filepath.Join(tempDir, "libykcs11.so")
	script := `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output-file" ]; then
    shift
    printf signature > "$1"
    exit 0
  fi
  shift
done
exit 2
`
	writeExecutable(t, binary, script)

	if err := os.WriteFile(library, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write fake pkcs11 library: %v", err)
	}

	client := CommandClient{Config: CommandClientConfig{
		PKCS11Tool:  binary,
		LibraryPath: library,
	}}
	result, err := client.Sign(context.Background(), SignRequest{
		KeySlot:   "9c",
		Algorithm: "RSA-PKCS",
		Digest:    []byte("digest"),
		PIN:       "123456",
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if string(result.Signature) != "signature" {
		t.Fatalf("unexpected signature: %q", string(result.Signature))
	}
}

func TestCommandClientSignWithStepKMS(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	binary := filepath.Join(tempDir, "step")
	script := `#!/bin/sh
printf signature
`
	writeExecutable(t, binary, script)

	client := CommandClient{Config: CommandClientConfig{
		StepBinary:  binary,
		SigningSlot: "83",
	}}
	result, err := client.Sign(context.Background(), SignRequest{
		Algorithm: "RSA-PKCS",
		Digest:    []byte("digest"),
		PIN:       "123456",
	})
	if err != nil {
		t.Fatalf("sign with step kms: %v", err)
	}
	if string(result.Signature) != "signature" {
		t.Fatalf("unexpected signature: %q", string(result.Signature))
	}
}

func TestCommandClientDetectPKCS11WithStepKMS(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	binary := filepath.Join(tempDir, "step")
	writeExecutable(t, binary, "#!/bin/sh\nexit 0\n")

	client := CommandClient{Config: CommandClientConfig{StepBinary: binary}}
	capabilities, err := client.DetectPKCS11(context.Background())
	if err != nil {
		t.Fatalf("detect step kms capabilities: %v", err)
	}
	if !capabilities.SupportsRSA || !capabilities.SupportsECC {
		t.Fatalf("unexpected capabilities: %+v", capabilities)
	}
}
