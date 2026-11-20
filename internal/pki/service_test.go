package pki

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestValidateCertificateRequest(t *testing.T) {
	t.Parallel()

	valid := IssueCertificateRequest{
		CommonName: "service.home.example",
		DNSNames:   []string{"alias.home.example"},
		TTL:        24 * time.Hour,
	}
	if err := ValidateCertificateRequest(valid); err != nil {
		t.Fatalf("expected valid request: %v", err)
	}

	invalidName := valid
	invalidName.DNSNames = []string{"-bad.home"}
	if err := ValidateCertificateRequest(invalidName); err == nil {
		t.Fatalf("expected invalid DNS name to be rejected")
	}

	invalidTTL := valid
	invalidTTL.TTL = 398 * 24 * time.Hour
	if err := ValidateCertificateRequest(invalidTTL); err == nil {
		t.Fatalf("expected excessive lifetime to be rejected")
	}
}

func TestMockServiceDefaults(t *testing.T) {
	t.Parallel()

	mock := MockService{}
	ctx := context.Background()

	if _, err := mock.ProvisionCA(ctx, ProvisionCAParams{}); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented for provision, got %v", err)
	}
	if _, err := mock.IssueCertificate(ctx, IssueCertificateRequest{}); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented for issue, got %v", err)
	}
	if err := mock.RevokeCertificate(ctx, RevokeCertificateRequest{}); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented for revoke, got %v", err)
	}
	if _, err := mock.GetCertificate(ctx, "serial"); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented for get, got %v", err)
	}
}

func TestMockServiceCustomFunctions(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	mock := MockService{
		ProvisionCAFn: func(ctx context.Context, params ProvisionCAParams) (ProvisionCAResult, error) {
			if params.RootCommonName == "" {
				t.Fatalf("expected root common name")
			}
			return ProvisionCAResult{CAID: "ca-1", ProvisionedAt: now}, nil
		},
		IssueCertificateFn: func(ctx context.Context, req IssueCertificateRequest) (IssueCertificateResult, error) {
			if req.CommonName == "" {
				t.Fatalf("expected common name")
			}
			return IssueCertificateResult{
				SerialNumber: "123",
				NotBefore:    now,
				NotAfter:     now.Add(time.Hour),
			}, nil
		},
		RevokeCertificateFn: func(ctx context.Context, req RevokeCertificateRequest) error {
			if req.SerialNumber != "123" {
				t.Fatalf("unexpected serial: %s", req.SerialNumber)
			}
			return nil
		},
		GetCertificateFn: func(ctx context.Context, serialNumber string) (CertificateRecord, error) {
			return CertificateRecord{
				SerialNumber: serialNumber,
				CommonName:   "service.home",
			}, nil
		},
	}

	ctx := context.Background()

	provisioned, err := mock.ProvisionCA(ctx, ProvisionCAParams{RootCommonName: "Home Root CA"})
	if err != nil || provisioned.CAID != "ca-1" {
		t.Fatalf("unexpected provision result: %+v err=%v", provisioned, err)
	}

	issued, err := mock.IssueCertificate(ctx, IssueCertificateRequest{CommonName: "service.home"})
	if err != nil || issued.SerialNumber != "123" {
		t.Fatalf("unexpected issue result: %+v err=%v", issued, err)
	}

	if err := mock.RevokeCertificate(ctx, RevokeCertificateRequest{SerialNumber: "123"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	record, err := mock.GetCertificate(ctx, "123")
	if err != nil || record.CommonName != "service.home" {
		t.Fatalf("unexpected record: %+v err=%v", record, err)
	}
}
