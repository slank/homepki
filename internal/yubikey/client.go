package yubikey

import (
	"context"
	"errors"
	"fmt"
)

var ErrNotImplemented = errors.New("not implemented")

type Device struct {
	Serial   string
	Model    string
	Firmware string
	HasPIV   bool
}

type PKCS11Capabilities struct {
	LibraryPath string
	SupportsRSA bool
	SupportsECC bool
}

type SignRequest struct {
	KeySlot      string
	Algorithm    string
	Digest       []byte
	PIN          string
	RequireTouch bool
}

type SignResult struct {
	Signature    []byte
	PublicKeyPEM string
}

type Client interface {
	Discover(ctx context.Context) ([]Device, error)
	DetectPKCS11(ctx context.Context) (PKCS11Capabilities, error)
	Sign(ctx context.Context, req SignRequest) (SignResult, error)
}

type MockClient struct {
	DiscoverFn     func(ctx context.Context) ([]Device, error)
	DetectPKCS11Fn func(ctx context.Context) (PKCS11Capabilities, error)
	SignFn         func(ctx context.Context, req SignRequest) (SignResult, error)
}

func (m MockClient) Discover(ctx context.Context) ([]Device, error) {
	if m.DiscoverFn != nil {
		return m.DiscoverFn(ctx)
	}
	return nil, fmt.Errorf("discover yubikey devices: %w", ErrNotImplemented)
}

func (m MockClient) DetectPKCS11(ctx context.Context) (PKCS11Capabilities, error) {
	if m.DetectPKCS11Fn != nil {
		return m.DetectPKCS11Fn(ctx)
	}
	return PKCS11Capabilities{}, fmt.Errorf("detect pkcs11 capabilities: %w", ErrNotImplemented)
}

func (m MockClient) Sign(ctx context.Context, req SignRequest) (SignResult, error) {
	if m.SignFn != nil {
		return m.SignFn(ctx, req)
	}
	return SignResult{}, fmt.Errorf("sign with yubikey: %w", ErrNotImplemented)
}
