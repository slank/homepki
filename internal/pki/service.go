package pki

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var ErrNotImplemented = errors.New("not implemented")

type ProvisionCAParams struct {
	RootCommonName         string
	IntermediateCommonName string
	YubiKeyPIN             string
}

type ProvisionCAResult struct {
	CAID          string
	ProvisionedAt time.Time
}

type IssueCertificateRequest struct {
	CommonName string
	DNSNames   []string
	TTL        time.Duration
}

type IssueCertificateResult struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	SerialNumber   string
	NotBefore      time.Time
	NotAfter       time.Time
}

type RevokeCertificateRequest struct {
	SerialNumber string
	Reason       string
}

type CertificateRecord struct {
	SerialNumber string
	CommonName   string
	DNSNames     []string
	NotBefore    time.Time
	NotAfter     time.Time
	Revoked      bool
}

type Service interface {
	ProvisionCA(ctx context.Context, params ProvisionCAParams) (ProvisionCAResult, error)
	IssueCertificate(ctx context.Context, req IssueCertificateRequest) (IssueCertificateResult, error)
	RevokeCertificate(ctx context.Context, req RevokeCertificateRequest) error
	GetCertificate(ctx context.Context, serialNumber string) (CertificateRecord, error)
}

type CAStarter interface {
	StartCA(ctx context.Context) error
}

type MockService struct {
	ProvisionCAFn       func(ctx context.Context, params ProvisionCAParams) (ProvisionCAResult, error)
	IssueCertificateFn  func(ctx context.Context, req IssueCertificateRequest) (IssueCertificateResult, error)
	RevokeCertificateFn func(ctx context.Context, req RevokeCertificateRequest) error
	GetCertificateFn    func(ctx context.Context, serialNumber string) (CertificateRecord, error)
}

func (m MockService) ProvisionCA(ctx context.Context, params ProvisionCAParams) (ProvisionCAResult, error) {
	if m.ProvisionCAFn != nil {
		return m.ProvisionCAFn(ctx, params)
	}
	return ProvisionCAResult{}, fmt.Errorf("provision ca: %w", ErrNotImplemented)
}

func (m MockService) IssueCertificate(ctx context.Context, req IssueCertificateRequest) (IssueCertificateResult, error) {
	if m.IssueCertificateFn != nil {
		return m.IssueCertificateFn(ctx, req)
	}
	return IssueCertificateResult{}, fmt.Errorf("issue certificate: %w", ErrNotImplemented)
}

func (m MockService) RevokeCertificate(ctx context.Context, req RevokeCertificateRequest) error {
	if m.RevokeCertificateFn != nil {
		return m.RevokeCertificateFn(ctx, req)
	}
	return fmt.Errorf("revoke certificate: %w", ErrNotImplemented)
}

func (m MockService) GetCertificate(ctx context.Context, serialNumber string) (CertificateRecord, error) {
	if m.GetCertificateFn != nil {
		return m.GetCertificateFn(ctx, serialNumber)
	}
	return CertificateRecord{}, fmt.Errorf("get certificate: %w", ErrNotImplemented)
}
