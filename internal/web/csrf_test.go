package web

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestCSRFTokenLifecycle(t *testing.T) {
	t.Parallel()

	token, err := NewCSRFToken()
	if err != nil {
		t.Fatalf("new csrf token: %v", err)
	}
	if token == "" {
		t.Fatalf("expected non-empty token")
	}

	hash := HashCSRFToken(token)
	if !ValidateCSRFToken(hash, token) {
		t.Fatalf("expected token to validate")
	}
	if ValidateCSRFToken(hash, token+"x") {
		t.Fatalf("expected modified token to fail validation")
	}
}

func TestCSRFTokenFromRequest(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest("POST", "/submit", strings.NewReader(url.Values{
		"csrf_token": []string{"form-token"},
	}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set(CSRFHeaderName, "header-token")

	token := CSRFTokenFromRequest(request)
	if token != "header-token" {
		t.Fatalf("expected header token, got %q", token)
	}

	request2 := httptest.NewRequest("POST", "/submit", strings.NewReader(url.Values{
		"csrf_token": []string{"form-token"},
	}.Encode()))
	request2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	token = CSRFTokenFromRequest(request2)
	if token != "form-token" {
		t.Fatalf("expected form token, got %q", token)
	}
}
