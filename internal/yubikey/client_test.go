package yubikey

import (
	"context"
	"errors"
	"testing"
)

func TestMockClientDefaults(t *testing.T) {
	t.Parallel()

	mock := MockClient{}
	ctx := context.Background()

	if _, err := mock.Discover(ctx); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented for discover, got %v", err)
	}

	if _, err := mock.DetectPKCS11(ctx); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented for detect, got %v", err)
	}

	if _, err := mock.Sign(ctx, SignRequest{}); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented for sign, got %v", err)
	}
}

func TestMockClientCustomFunctions(t *testing.T) {
	t.Parallel()

	mock := MockClient{
		DiscoverFn: func(ctx context.Context) ([]Device, error) {
			return []Device{
				{Serial: "123456", Model: "YubiKey 5", HasPIV: true},
			}, nil
		},
		DetectPKCS11Fn: func(ctx context.Context) (PKCS11Capabilities, error) {
			return PKCS11Capabilities{
				LibraryPath: "/usr/lib/pkcs11.so",
				SupportsRSA: true,
				SupportsECC: true,
			}, nil
		},
		SignFn: func(ctx context.Context, req SignRequest) (SignResult, error) {
			if req.KeySlot != "9c" {
				t.Fatalf("unexpected key slot: %s", req.KeySlot)
			}
			return SignResult{Signature: []byte("sig"), PublicKeyPEM: "pem"}, nil
		},
	}

	ctx := context.Background()

	devices, err := mock.Discover(ctx)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(devices) != 1 || devices[0].Serial != "123456" {
		t.Fatalf("unexpected devices: %+v", devices)
	}

	capabilities, err := mock.DetectPKCS11(ctx)
	if err != nil {
		t.Fatalf("detect pkcs11: %v", err)
	}
	if !capabilities.SupportsRSA || !capabilities.SupportsECC {
		t.Fatalf("unexpected capabilities: %+v", capabilities)
	}

	result, err := mock.Sign(ctx, SignRequest{KeySlot: "9c"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if string(result.Signature) != "sig" {
		t.Fatalf("unexpected signature: %q", string(result.Signature))
	}
}
