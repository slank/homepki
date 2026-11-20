package pki

import (
	"errors"
	"testing"
)

func TestIsSigningFailure(t *testing.T) {
	t.Parallel()

	baseErr := errors.New("pin rejected")
	err := &SigningError{
		Code: SigningFailurePINInvalid,
		Err:  baseErr,
	}

	if !IsSigningFailure(err, SigningFailurePINInvalid) {
		t.Fatalf("expected signing failure code match")
	}
	if IsSigningFailure(err, SigningFailureTouchTimeout) {
		t.Fatalf("expected signing failure code mismatch")
	}
	if !errors.Is(err, baseErr) {
		t.Fatalf("expected wrapped error to match base error")
	}
}
