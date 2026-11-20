package pki

import "errors"

type SigningFailureCode string

const (
	SigningFailureKeyMissing    SigningFailureCode = "key_missing"
	SigningFailurePINInvalid    SigningFailureCode = "pin_invalid"
	SigningFailureTouchTimeout  SigningFailureCode = "touch_timeout"
	SigningFailureUserCancelled SigningFailureCode = "user_cancelled"
	SigningFailureTransport     SigningFailureCode = "transport_error"
)

type SigningError struct {
	Code SigningFailureCode
	Err  error
}

func (e *SigningError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err == nil {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.Err.Error()
}

func (e *SigningError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func IsSigningFailure(err error, code SigningFailureCode) bool {
	var signingErr *SigningError
	if !errors.As(err, &signingErr) {
		return false
	}
	return signingErr.Code == code
}
