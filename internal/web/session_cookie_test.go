package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBuildSessionCookie(t *testing.T) {
	t.Parallel()

	expiresAt := time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC)
	cookie, err := BuildSessionCookie("session-1", expiresAt, true)
	if err != nil {
		t.Fatalf("build session cookie: %v", err)
	}

	if cookie.Name != SessionCookieName {
		t.Fatalf("unexpected cookie name: %s", cookie.Name)
	}
	if !cookie.HttpOnly {
		t.Fatalf("cookie must be httpOnly")
	}
	if !cookie.Secure {
		t.Fatalf("cookie must be secure")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unexpected sameSite: %v", cookie.SameSite)
	}
}

func TestSessionIDFromRequest(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{
		Name:  SessionCookieName,
		Value: "session-2",
	})

	sessionID, err := SessionIDFromRequest(request)
	if err != nil {
		t.Fatalf("session id from request: %v", err)
	}
	if sessionID != "session-2" {
		t.Fatalf("unexpected session id: %s", sessionID)
	}
}
