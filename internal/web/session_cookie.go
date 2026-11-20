package web

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

const SessionCookieName = "homepki_session"
const CSRFTokenCookieName = "homepki_csrf"

func BuildSessionCookie(sessionID string, expiresAt time.Time, secure bool) (*http.Cookie, error) {
	if strings.TrimSpace(sessionID) == "" {
		return nil, errors.New("session id is required")
	}
	if expiresAt.IsZero() {
		return nil, errors.New("expires_at is required")
	}

	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionID,
		Path:     "/",
		Expires:  expiresAt.UTC(),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}, nil
}

func BuildCSRFTokenCookie(token string, expiresAt time.Time, secure bool) (*http.Cookie, error) {
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("csrf token is required")
	}
	if expiresAt.IsZero() {
		return nil, errors.New("expires_at is required")
	}

	return &http.Cookie{
		Name:     CSRFTokenCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt.UTC(),
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}, nil
}

func CSRFTokenFromCookie(r *http.Request) string {
	if r == nil {
		return ""
	}
	cookie, err := r.Cookie(CSRFTokenCookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cookie.Value)
}

func SessionIDFromRequest(r *http.Request) (string, error) {
	if r == nil {
		return "", errors.New("request is required")
	}

	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return "", err
	}

	sessionID := strings.TrimSpace(cookie.Value)
	if sessionID == "" {
		return "", errors.New("session cookie is empty")
	}

	return sessionID, nil
}
