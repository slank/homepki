package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
)

const CSRFHeaderName = "X-CSRF-Token"

func NewCSRFToken() (string, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(token), nil
}

func HashCSRFToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func ValidateCSRFToken(expectedHash, providedToken string) bool {
	if strings.TrimSpace(expectedHash) == "" || strings.TrimSpace(providedToken) == "" {
		return false
	}

	providedHash := HashCSRFToken(providedToken)
	return subtle.ConstantTimeCompare([]byte(expectedHash), []byte(providedHash)) == 1
}

func CSRFTokenFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}

	headerValue := strings.TrimSpace(r.Header.Get(CSRFHeaderName))
	if headerValue != "" {
		return headerValue
	}

	formValue := strings.TrimSpace(r.FormValue("csrf_token"))
	return formValue
}
