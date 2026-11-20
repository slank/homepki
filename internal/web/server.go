package web

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"homepki/internal/pki"
	"homepki/internal/storage"
	"homepki/internal/yubikey"
)

var safeBackupSuffix = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

type Server struct {
	DB                   *sql.DB
	PKI                  pki.Service
	YubiKey              yubikey.Client
	RequireYubiKey       bool
	SessionTTL           time.Duration
	AllowInsecureCookies bool
	SystemctlBinary      string
	SystemctlArgs        []string
	AppServiceName       string
	CAServiceName        string
	SQLitePath           string
	ConfigPath           string
	BackupOutputDir      string
	ProtectedPaths       []string
}

func NewServer(server Server) http.Handler {
	if server.SessionTTL <= 0 {
		server.SessionTTL = 12 * time.Hour
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", server.handleHome)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/setup", server.handleSetupStatus)
	mux.HandleFunc("/setup/admin", server.handleSetupAdmin)
	mux.HandleFunc("/setup/ca", server.handleSetupCA)
	mux.HandleFunc("/login", server.handleLogin)
	mux.HandleFunc("/logout", server.handleLogout)
	mux.HandleFunc("/certificates", server.handleCertificates)
	mux.HandleFunc("/certificates/", server.handleCertificateAction)
	mux.HandleFunc("/trust-guidance", server.handleTrustGuidance)
	mux.HandleFunc("/admin/backup", server.handleBackup)
	mux.HandleFunc("/admin/factory-reset", server.handleFactoryReset)

	return mux
}

func (s Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ctx := r.Context()
	state, reason, err := storage.GetSetupState(ctx, s.DB)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("read setup state: %v", err))
		return
	}

	hasAdmin := true
	if _, err := storage.GetAdminCredentialByUsername(ctx, s.DB, "admin"); err != nil {
		if errors.Is(err, storage.ErrAdminNotFound) {
			hasAdmin = false
		} else {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("read admin state: %v", err))
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"state":     state,
		"reason":    reason,
		"has_admin": hasAdmin,
	})

}

func (s Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	state, _, err := storage.GetSetupState(r.Context(), s.DB)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	session, err := storageSessionFromRequest(r, s.DB)
	if err != nil {
		if state == storage.SetupStateNotInitialized {
			renderPage(w, http.StatusOK, setupPage, pageModel{Title: "Set up"})
			return
		}
		renderPage(w, http.StatusOK, loginPage, pageModel{Title: "Sign in"})
		return
	}

	if state == storage.SetupStatePrerequisites || state == storage.SetupStateRecoverableError {
		_, reason, _ := storage.GetSetupState(r.Context(), s.DB)
		renderPage(w, http.StatusOK, caSetupPage, pageModel{
			Title:           "Provision CA",
			CSRFToken:       CSRFTokenFromCookie(r),
			Reason:          reason,
			RequiresYubiKey: s.RequireYubiKey,
		})
		return
	}

	certificates, err := storage.ListCertificates(r.Context(), s.DB)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = session
	renderPage(w, http.StatusOK, dashboardPage, pageModel{
		Title:           "Dashboard",
		CSRFToken:       CSRFTokenFromCookie(r),
		SetupState:      state,
		Certificates:    certificates,
		RequiresYubiKey: s.RequireYubiKey,
	})
}

func (s Server) handleSetupAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	isForm := strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded")
	if isForm {
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		payload.Username = r.Form.Get("username")
		payload.Password = r.Form.Get("password")
	} else {
		if err := decodeJSONBody(r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	if strings.TrimSpace(payload.Username) == "" || strings.TrimSpace(payload.Password) == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}
	if len([]rune(payload.Password)) < 12 {
		writeError(w, http.StatusBadRequest, "password must be at least 12 characters")
		return
	}

	ctx := r.Context()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("hash password: %v", err))
		return
	}

	admin, err := storage.CreateAdminCredential(ctx, s.DB, payload.Username, string(hashedPassword), time.Now().UTC())
	if errors.Is(err, storage.ErrAdminAlreadyCreated) {
		writeError(w, http.StatusConflict, "admin already configured")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("create admin credential: %v", err))
		return
	}

	if err := s.startSetupFlowIfNeeded(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("transition setup state: %v", err))
		return
	}

	csrfToken, sessionID, err := s.createSessionForAdmin(ctx, admin.ID, requestRemoteAddress(r), r.UserAgent())
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("create auth session: %v", err))
		return
	}

	if err := s.appendAudit(ctx, storage.AppendAuditEventParams{
		ActorType:  "admin",
		ActorID:    fmt.Sprintf("%d", admin.ID),
		Action:     "setup.admin.create",
		TargetType: "admin_credentials",
		TargetID:   "1",
		Outcome:    "success",
		Details:    map[string]string{"username": admin.Username},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("append audit event: %v", err))
		return
	}

	if err := s.writeSessionCookies(w, sessionID, csrfToken); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if isForm {
		http.Redirect(w, r, "/setup/ca", http.StatusSeeOther)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"csrf_token": csrfToken,
		"message":    "admin created",
	})
}

func (s Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		renderPage(w, http.StatusOK, loginPage, pageModel{Title: "Sign in"})
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	isForm := strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded")
	if isForm {
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		payload.Username = r.Form.Get("username")
		payload.Password = r.Form.Get("password")
	} else {
		if err := decodeJSONBody(r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	ctx := r.Context()
	admin, err := storage.GetAdminCredentialByUsername(ctx, s.DB, payload.Username)
	if errors.Is(err, storage.ErrAdminNotFound) {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("query admin credential: %v", err))
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(payload.Password)); err != nil {
		_ = s.appendAudit(ctx, storage.AppendAuditEventParams{
			ActorType:  "admin",
			ActorID:    fmt.Sprintf("%d", admin.ID),
			Action:     "auth.login",
			TargetType: "session",
			TargetID:   "",
			Outcome:    "failure",
			Details:    map[string]string{"reason": "invalid_credentials"},
		})
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	csrfToken, sessionID, err := s.createSessionForAdmin(ctx, admin.ID, requestRemoteAddress(r), r.UserAgent())
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("create auth session: %v", err))
		return
	}
	if err := s.writeSessionCookies(w, sessionID, csrfToken); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	_ = s.appendAudit(ctx, storage.AppendAuditEventParams{
		ActorType:  "admin",
		ActorID:    fmt.Sprintf("%d", admin.ID),
		Action:     "auth.login",
		TargetType: "session",
		TargetID:   sessionID,
		Outcome:    "success",
		Details:    map[string]string{"remote_addr": requestRemoteAddress(r)},
	})

	if isForm {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"csrf_token": csrfToken,
		"message":    "login successful",
	})
}

func (s Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	session, _, err := s.requireAuthenticatedSession(r, true)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	if err := storage.RevokeAuthSession(r.Context(), s.DB, session.ID, time.Now().UTC()); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("revoke auth session: %v", err))
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   !s.AllowInsecureCookies,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFTokenCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: false,
		Secure:   !s.AllowInsecureCookies,
		SameSite: http.SameSiteLaxMode,
	})
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}

func (s Server) handleSetupCA(w http.ResponseWriter, r *http.Request) {
	session, _, err := s.requireAuthenticatedSession(r, r.Method == http.MethodPost)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	state, reason, err := storage.GetSetupState(r.Context(), s.DB)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if r.Method == http.MethodGet {
		renderPage(w, http.StatusOK, caSetupPage, pageModel{
			Title:           "Provision CA",
			CSRFToken:       CSRFTokenFromCookie(r),
			Reason:          reason,
			RequiresYubiKey: s.RequireYubiKey,
		})
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if state != storage.SetupStatePrerequisites && state != storage.SetupStateRecoverableError {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	now := time.Now().UTC()
	if s.RequireYubiKey {
		if s.YubiKey == nil {
			s.handleSetupCAFailure(w, r, "yubikey client is not configured", now)
			return
		}
		devices, err := s.YubiKey.Discover(r.Context())
		if err != nil {
			s.handleSetupCAFailure(w, r, err.Error(), now)
			return
		}
		if len(devices) == 0 {
			s.handleSetupCAFailure(w, r, "no YubiKey devices found", now)
			return
		}
		hasPIV := false
		for _, device := range devices {
			if device.HasPIV {
				hasPIV = true
				break
			}
		}
		if !hasPIV {
			s.handleSetupCAFailure(
				w,
				r,
				"The connected YubiKey does not expose PIV/CCID; HomePKI requires a YubiKey model with PIV enabled",
				now,
			)
			return
		}
		capabilities, err := s.YubiKey.DetectPKCS11(r.Context())
		if err != nil {
			s.handleSetupCAFailure(w, r, err.Error(), now)
			return
		}
		if !capabilities.SupportsRSA {
			s.handleSetupCAFailure(w, r, "configured YubiKey slot requires RSA PKCS#11 signing support", now)
			return
		}
	}

	if state == storage.SetupStateRecoverableError {
		if err := storage.TransitionSetupState(r.Context(), s.DB, storage.SetupStatePrerequisites, "", now); err != nil {
			s.handleSetupCAFailure(w, r, err.Error(), now)
			return
		}
	}
	if err := storage.TransitionSetupState(r.Context(), s.DB, storage.SetupStateCAProvisioning, "", now.Add(time.Second)); err != nil {
		s.handleSetupCAFailure(w, r, err.Error(), now.Add(time.Second))
		return
	}

	if s.PKI == nil {
		s.handleSetupCAFailure(w, r, "pki provider is not configured", now)
		return
	}

	result, err := s.PKI.ProvisionCA(r.Context(), pki.ProvisionCAParams{
		RootCommonName:         r.Form.Get("root_name"),
		IntermediateCommonName: r.Form.Get("intermediate_name"),
		YubiKeyPIN:             r.Form.Get("yubikey_pin"),
	})
	if err != nil {
		s.handleSetupCAFailure(w, r, err.Error(), now.Add(2*time.Second))
		return
	}
	if starter, ok := s.PKI.(pki.CAStarter); ok {
		if err := starter.StartCA(r.Context()); err != nil {
			s.handleSetupCAFailure(w, r, err.Error(), now.Add(3*time.Second))
			return
		}
	}

	if err := storage.SaveStepCAProvisionState(r.Context(), s.DB, storage.StepCAProvisionState{
		Status: "provisioned",
		CAID:   result.CAID,
	}, now.Add(4*time.Second)); err != nil {
		s.handleSetupCAFailure(w, r, err.Error(), now.Add(4*time.Second))
		return
	}
	if err := storage.TransitionSetupState(r.Context(), s.DB, storage.SetupStateComplete, "", now.Add(5*time.Second)); err != nil {
		s.handleSetupCAFailure(w, r, err.Error(), now.Add(5*time.Second))
		return
	}

	_ = s.appendAudit(r.Context(), storage.AppendAuditEventParams{
		ActorType:  "admin",
		ActorID:    fmt.Sprintf("%d", session.AdminID),
		Action:     "setup.ca.provision",
		TargetType: "ca",
		TargetID:   result.CAID,
		Outcome:    "success",
		Details:    map[string]string{},
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s Server) handleSetupCAFailure(w http.ResponseWriter, r *http.Request, reason string, now time.Time) {
	state, _, stateErr := storage.GetSetupState(r.Context(), s.DB)
	if stateErr == nil && state != storage.SetupStateRecoverableError {
		allowedState := state == storage.SetupStatePrerequisites || state == storage.SetupStateCAProvisioning
		if allowedState {
			_ = storage.TransitionSetupState(r.Context(), s.DB, storage.SetupStateRecoverableError, reason, now)
		}
	}
	_ = storage.SaveStepCAProvisionState(r.Context(), s.DB, storage.StepCAProvisionState{
		Status:    "failed",
		LastError: reason,
	}, now)
	renderPage(w, http.StatusBadGateway, caSetupPage, pageModel{
		Title:           "Provision CA",
		CSRFToken:       CSRFTokenFromCookie(r),
		Error:           reason,
		RequiresYubiKey: s.RequireYubiKey,
	})
}

func (s Server) handleCertificates(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		_, _, err := s.requireAuthenticatedSession(r, false)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}

		certs, err := storage.ListCertificates(r.Context(), s.DB)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("list certificates: %v", err))
			return
		}
		writeJSON(w, http.StatusOK, certs)
	case http.MethodPost:
		session, _, err := s.requireAuthenticatedSession(r, true)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}

		var payload struct {
			CommonName string   `json:"common_name"`
			DNSNames   []string `json:"dns_names"`
			TTLHours   int      `json:"ttl_hours"`
		}
		isForm := strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded")
		if isForm {
			if err := r.ParseForm(); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			payload.CommonName = r.Form.Get("common_name")
			payload.DNSNames = splitFormLines(r.Form.Get("dns_names"))
			_, _ = fmt.Sscan(r.Form.Get("ttl_hours"), &payload.TTLHours)
		} else {
			if err := decodeJSONBody(r, &payload); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		if payload.CommonName == "" {
			writeError(w, http.StatusBadRequest, "common_name is required")
			return
		}
		if payload.TTLHours <= 0 {
			payload.TTLHours = 24
		}

		now := time.Now().UTC()
		serialNumber := ""
		notBefore := now
		notAfter := now.Add(time.Duration(payload.TTLHours) * time.Hour)
		var issuedBundle *pki.IssueCertificateResult

		issueRequest := pki.IssueCertificateRequest{
			CommonName: payload.CommonName,
			DNSNames:   payload.DNSNames,
			TTL:        time.Duration(payload.TTLHours) * time.Hour,
		}
		if err := pki.ValidateCertificateRequest(issueRequest); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if s.PKI != nil {
			issued, err := s.PKI.IssueCertificate(r.Context(), issueRequest)
			if err != nil && !errors.Is(err, pki.ErrNotImplemented) {
				writeError(w, http.StatusBadGateway, fmt.Sprintf("issue certificate: %v", err))
				return
			}
			if err == nil {
				issuedBundle = &issued
				serialNumber = issued.SerialNumber
				notBefore = issued.NotBefore
				notAfter = issued.NotAfter
			}
		}
		if serialNumber == "" {
			serialNumber, err = randomToken(18)
			if err != nil {
				writeError(w, http.StatusInternalServerError, fmt.Sprintf("generate serial: %v", err))
				return
			}
		}

		certificate, err := storage.CreateCertificate(r.Context(), s.DB, storage.CreateCertificateParams{
			SerialNumber: serialNumber,
			CommonName:   payload.CommonName,
			SANs:         payload.DNSNames,
			NotBefore:    notBefore,
			NotAfter:     notAfter,
			Now:          now,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("create certificate record: %v", err))
			return
		}

		_ = s.appendAudit(r.Context(), storage.AppendAuditEventParams{
			ActorType:  "admin",
			ActorID:    fmt.Sprintf("%d", session.AdminID),
			Action:     "cert.issue",
			TargetType: "certificate",
			TargetID:   certificate.SerialNumber,
			Outcome:    "success",
			Details:    map[string]string{"common_name": payload.CommonName},
		})

		if isForm {
			if issuedBundle != nil {
				if err := writeCertificateBundle(w, certificate.SerialNumber, issuedBundle.CertificatePEM, issuedBundle.PrivateKeyPEM); err != nil {
					writeError(w, http.StatusInternalServerError, err.Error())
				}
				return
			}
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		writeJSON(w, http.StatusCreated, certificate)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s Server) handleCertificateAction(w http.ResponseWriter, r *http.Request) {
	session, _, err := s.requireAuthenticatedSession(r, true)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/certificates/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 2 {
		writeError(w, http.StatusNotFound, "not found")
		return
	}

	serialNumber := parts[0]
	action := parts[1]

	var payload struct {
		Confirm string `json:"confirm"`
	}
	isForm := strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded")
	if isForm {
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		payload.Confirm = r.Form.Get("confirm")
	} else {
		if err := decodeJSONBody(r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	switch action {
	case "revoke":
		if payload.Confirm != "REVOKE" {
			writeError(w, http.StatusBadRequest, "revoke requires confirm=REVOKE")
			return
		}
		if s.PKI != nil {
			err := s.PKI.RevokeCertificate(r.Context(), pki.RevokeCertificateRequest{
				SerialNumber: serialNumber,
				Reason:       "unspecified",
			})
			if err != nil && !errors.Is(err, pki.ErrNotImplemented) {
				writeError(w, http.StatusBadGateway, fmt.Sprintf("revoke certificate through pki: %v", err))
				return
			}
		}
		if err := storage.RevokeCertificate(r.Context(), s.DB, serialNumber, time.Now().UTC()); err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, storage.ErrCertificateNotFound) {
				status = http.StatusNotFound
			}
			writeError(w, status, err.Error())
			return
		}
		_ = s.appendAudit(r.Context(), storage.AppendAuditEventParams{
			ActorType:  "admin",
			ActorID:    fmt.Sprintf("%d", session.AdminID),
			Action:     "cert.revoke",
			TargetType: "certificate",
			TargetID:   serialNumber,
			Outcome:    "success",
			Details:    map[string]string{"confirm": payload.Confirm},
		})
		if isForm {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "certificate revoked"})
	case "delete":
		if payload.Confirm != "DELETE" {
			writeError(w, http.StatusBadRequest, "delete requires confirm=DELETE")
			return
		}
		if err := storage.DeleteCertificate(r.Context(), s.DB, serialNumber); err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, storage.ErrCertificateNotFound) {
				status = http.StatusNotFound
			}
			writeError(w, status, err.Error())
			return
		}
		_ = s.appendAudit(r.Context(), storage.AppendAuditEventParams{
			ActorType:  "admin",
			ActorID:    fmt.Sprintf("%d", session.AdminID),
			Action:     "cert.delete",
			TargetType: "certificate",
			TargetID:   serialNumber,
			Outcome:    "success",
			Details:    map[string]string{"confirm": payload.Confirm},
		})
		if isForm {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "certificate deleted"})
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

func (s Server) handleTrustGuidance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	_, _, err := s.requireAuthenticatedSession(r, false)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	if wantsHTML(r) {
		renderPage(w, http.StatusOK, trustPage, pageModel{Title: "Trust guidance"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"warnings": []string{
			"Only trust a CA certificate that was generated by your appliance.",
			"Back up CA material before rotating or resetting setup.",
		},
		"linux": []string{
			"Export the CA certificate from HomePKI.",
			"Copy it to /usr/local/share/ca-certificates/homepki.crt.",
			"Run update-ca-certificates.",
		},
		"macos": []string{
			"Open Keychain Access and import the HomePKI CA certificate.",
			"Set trust to Always Trust for SSL.",
			"Restart browsers that cache trust settings.",
		},
	})
}

func (s Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	session, _, err := s.requireAuthenticatedSession(r, true)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var payload struct {
		NameSuffix string `json:"name_suffix"`
	}
	if err := decodeJSONBody(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if strings.TrimSpace(s.SQLitePath) == "" || strings.TrimSpace(s.ConfigPath) == "" {
		writeError(w, http.StatusInternalServerError, "server backup paths are not configured")
		return
	}

	backupDir := strings.TrimSpace(s.BackupOutputDir)
	if backupDir == "" {
		backupDir = "."
	}

	suffix := strings.TrimSpace(payload.NameSuffix)
	if suffix == "" {
		suffix = time.Now().UTC().Format("20060102-150405")
	}
	if !safeBackupSuffix.MatchString(suffix) || suffix == "." || suffix == ".." {
		writeError(w, http.StatusBadRequest, "name_suffix may contain only letters, numbers, dots, dashes, and underscores")
		return
	}

	archivePath := fmt.Sprintf("%s/homepki-backup-%s.tar.gz", strings.TrimRight(backupDir, "/"), suffix)
	snapshotDir, err := os.MkdirTemp(backupDir, ".homepki-backup-*")
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("create backup snapshot directory: %v", err))
		return
	}
	defer os.RemoveAll(snapshotDir)

	snapshotPath := filepath.Join(snapshotDir, "homepki.db")
	if _, err := s.DB.ExecContext(r.Context(), "VACUUM INTO ?", snapshotPath); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("create sqlite snapshot: %v", err))
		return
	}

	backupPaths := append([]string{snapshotPath, s.ConfigPath}, s.ProtectedPaths...)
	if err := storage.CreateBackupArchive(archivePath, backupPaths); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("create backup archive: %v", err))
		return
	}

	_ = s.appendAudit(r.Context(), storage.AppendAuditEventParams{
		ActorType:  "admin",
		ActorID:    fmt.Sprintf("%d", session.AdminID),
		Action:     "backup.create",
		TargetType: "backup",
		TargetID:   archivePath,
		Outcome:    "success",
		Details:    map[string]string{"archive_path": archivePath},
	})

	writeJSON(w, http.StatusOK, map[string]string{"archive_path": archivePath})
}

func (s Server) handleFactoryReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	session, _, err := s.requireAuthenticatedSession(r, true)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var payload struct {
		Confirm string `json:"confirm"`
	}
	if err := decodeJSONBody(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if payload.Confirm != "FACTORY_RESET" {
		writeError(w, http.StatusBadRequest, "factory reset requires confirm=FACTORY_RESET")
		return
	}
	if strings.TrimSpace(s.SQLitePath) == "" {
		writeError(w, http.StatusInternalServerError, "sqlite path is not configured")
		return
	}

	if err := s.appendAudit(r.Context(), storage.AppendAuditEventParams{
		ActorType:  "admin",
		ActorID:    fmt.Sprintf("%d", session.AdminID),
		Action:     "factory_reset",
		TargetType: "storage",
		TargetID:   s.SQLitePath,
		Outcome:    "requested",
		Details:    map[string]string{"confirm": payload.Confirm},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("append factory reset audit event: %v", err))
		return
	}

	if s.SystemctlBinary != "" && s.CAServiceName != "" {
		if err := s.runSystemctl("stop", s.CAServiceName); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	for _, protectedPath := range s.ProtectedPaths {
		if err := storage.FactoryResetPath(protectedPath); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("factory reset protected path: %v", err))
			return
		}
	}

	if err := s.DB.Close(); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("close database: %v", err))
		return
	}
	if err := storage.FactoryResetSQLite(s.SQLitePath); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("factory reset sqlite: %v", err))
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{"message": "factory reset completed; service restart required"})
	if s.SystemctlBinary != "" && s.AppServiceName != "" {
		go func() {
			time.Sleep(250 * time.Millisecond)
			_ = s.runSystemctl("restart", s.AppServiceName)
		}()
	}
}

func (s Server) runSystemctl(verb, service string) error {
	binary := s.SystemctlBinary
	if binary == "" {
		return errors.New("systemctl binary is not configured")
	}
	args := append([]string{}, s.SystemctlArgs...)
	args = append(args, verb, service)
	cmd := exec.Command(binary, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s %s: %w: %s", verb, service, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (s Server) requireAuthenticatedSession(r *http.Request, requireCSRF bool) (storage.AuthSession, string, error) {
	sessionID, err := SessionIDFromRequest(r)
	if err != nil {
		return storage.AuthSession{}, "", errors.New("missing session cookie")
	}

	session, err := storage.GetAuthSession(r.Context(), s.DB, sessionID, time.Now().UTC())
	if err != nil {
		if errors.Is(err, storage.ErrSessionNotFound) {
			return storage.AuthSession{}, "", errors.New("invalid session")
		}
		return storage.AuthSession{}, "", fmt.Errorf("get auth session: %w", err)
	}

	if err := storage.TouchAuthSession(r.Context(), s.DB, sessionID, time.Now().UTC()); err != nil {
		return storage.AuthSession{}, "", fmt.Errorf("touch auth session: %w", err)
	}

	if requireCSRF {
		providedToken := CSRFTokenFromRequest(r)
		if !ValidateCSRFToken(session.CSRFTokenHash, providedToken) {
			return storage.AuthSession{}, "", errors.New("invalid csrf token")
		}
		return session, providedToken, nil
	}

	return session, "", nil
}

func storageSessionFromRequest(r *http.Request, db *sql.DB) (storage.AuthSession, error) {
	sessionID, err := SessionIDFromRequest(r)
	if err != nil {
		return storage.AuthSession{}, err
	}
	return storage.GetAuthSession(r.Context(), db, sessionID, time.Now().UTC())
}

func (s Server) startSetupFlowIfNeeded(ctx context.Context) error {
	currentState, _, err := storage.GetSetupState(ctx, s.DB)
	if err != nil {
		return err
	}
	if currentState != storage.SetupStateNotInitialized {
		return nil
	}

	now := time.Now().UTC()
	if err := storage.TransitionSetupState(ctx, s.DB, storage.SetupStatePrerequisites, "", now); err != nil {
		return err
	}
	return nil
}

func (s Server) createSessionForAdmin(ctx context.Context, adminID int64, remoteAddr, userAgent string) (csrfToken string, sessionID string, err error) {
	csrfToken, err = NewCSRFToken()
	if err != nil {
		return "", "", err
	}

	sessionID, err = randomToken(32)
	if err != nil {
		return "", "", err
	}

	_, err = storage.CreateAuthSession(ctx, s.DB, storage.CreateAuthSessionParams{
		ID:            sessionID,
		AdminID:       adminID,
		CSRFTokenHash: HashCSRFToken(csrfToken),
		ExpiresAt:     time.Now().UTC().Add(s.SessionTTL),
		RemoteAddr:    remoteAddr,
		UserAgent:     userAgent,
		Now:           time.Now().UTC(),
	})
	if err != nil {
		return "", "", err
	}

	return csrfToken, sessionID, nil
}

func (s Server) writeSessionCookies(w http.ResponseWriter, sessionID, csrfToken string) error {
	expiresAt := time.Now().UTC().Add(s.SessionTTL)
	secure := !s.AllowInsecureCookies
	cookie, err := BuildSessionCookie(sessionID, expiresAt, secure)
	if err != nil {
		return fmt.Errorf("build session cookie: %w", err)
	}
	http.SetCookie(w, cookie)

	csrfCookie, err := BuildCSRFTokenCookie(csrfToken, expiresAt, secure)
	if err != nil {
		return fmt.Errorf("build csrf cookie: %w", err)
	}
	http.SetCookie(w, csrfCookie)
	return nil
}

func (s Server) appendAudit(ctx context.Context, params storage.AppendAuditEventParams) error {
	return storage.AppendAuditEvent(ctx, s.DB, params)
}

func (s Server) confirmYubiKeySigning(ctx context.Context, pin string) error {
	if s.YubiKey == nil {
		return errors.New("yubikey client is not configured")
	}
	if strings.TrimSpace(pin) == "" {
		return errors.New("yubikey pin is required")
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return fmt.Errorf("generate yubikey challenge: %w", err)
	}
	digest := sha256.Sum256(challenge)

	_, err := s.YubiKey.Sign(ctx, yubikey.SignRequest{
		Algorithm:    "RSA-PKCS",
		Digest:       digest[:],
		PIN:          pin,
		RequireTouch: true,
	})
	if err != nil {
		return fmt.Errorf("confirm yubikey signing action: %w", err)
	}
	return nil
}

func decodeJSONBody(r *http.Request, out any) error {
	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("invalid json body: %w", err)
	}
	return nil
}

func writeError(w http.ResponseWriter, statusCode int, message string) {
	writeJSON(w, statusCode, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeCertificateBundle(w http.ResponseWriter, serialNumber string, certificatePEM, privateKeyPEM []byte) error {
	var bundle bytes.Buffer
	archive := zip.NewWriter(&bundle)

	certificateFile, err := archive.Create("certificate.pem")
	if err != nil {
		return fmt.Errorf("create certificate archive entry: %w", err)
	}
	if _, err := certificateFile.Write(certificatePEM); err != nil {
		return fmt.Errorf("write certificate archive entry: %w", err)
	}

	privateKeyFile, err := archive.Create("private-key.pem")
	if err != nil {
		return fmt.Errorf("create private key archive entry: %w", err)
	}
	if _, err := privateKeyFile.Write(privateKeyPEM); err != nil {
		return fmt.Errorf("write private key archive entry: %w", err)
	}

	if err := archive.Close(); err != nil {
		return fmt.Errorf("close certificate archive: %w", err)
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="homepki-%s.zip"`, serialNumber))
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(bundle.Bytes())
	return err
}

func randomToken(byteLength int) (string, error) {
	buf := make([]byte, byteLength)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func requestRemoteAddress(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}
	return r.RemoteAddr
}

func splitFormLines(value string) []string {
	lines := strings.Split(value, "\n")
	names := make([]string, 0, len(lines))
	for _, line := range lines {
		name := strings.TrimSpace(line)
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

func (s Server) shutdown(ctx context.Context) error {
	if s.DB == nil {
		return nil
	}
	return s.DB.Close()
}
