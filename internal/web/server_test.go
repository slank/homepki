package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"homepki/internal/pki"
	"homepki/internal/storage"
)

func TestBrowserSetupWizardProvisionsCA(t *testing.T) {
	t.Parallel()

	handler, _, _, teardown := newTestServerWithPKI(t, pki.MockService{
		ProvisionCAFn: func(ctx context.Context, params pki.ProvisionCAParams) (pki.ProvisionCAResult, error) {
			if params.RootCommonName == "" {
				t.Fatalf("expected root common name")
			}
			return pki.ProvisionCAResult{
				CAID:          "ca-1",
				ProvisionedAt: time.Now().UTC(),
			}, nil
		},
		IssueCertificateFn: func(ctx context.Context, req pki.IssueCertificateRequest) (pki.IssueCertificateResult, error) {
			now := time.Now().UTC()
			return pki.IssueCertificateResult{
				CertificatePEM: []byte("certificate"),
				PrivateKeyPEM:  []byte("private-key"),
				SerialNumber:   "serial-1",
				NotBefore:      now,
				NotAfter:       now.Add(req.TTL),
			}, nil
		},
	})
	defer teardown()

	homeRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	homeRequest.Header.Set("Accept", "text/html")
	homeRecorder := httptest.NewRecorder()
	handler.ServeHTTP(homeRecorder, homeRequest)
	if homeRecorder.Code != http.StatusOK || !bytes.Contains(homeRecorder.Body.Bytes(), []byte("Set up HomePKI")) {
		t.Fatalf("expected setup page, status=%d body=%s", homeRecorder.Code, homeRecorder.Body.String())
	}
	if !bytes.Contains(homeRecorder.Body.Bytes(), []byte("at least 12 characters")) ||
		!bytes.Contains(homeRecorder.Body.Bytes(), []byte(">Show<")) {
		t.Fatalf("expected setup password guidance and toggle, body=%s", homeRecorder.Body.String())
	}

	setupForm := url.Values{
		"username": []string{"admin"},
		"password": []string{"a-long-password"},
	}.Encode()
	setupRequest := httptest.NewRequest(http.MethodPost, "/setup/admin", strings.NewReader(setupForm))
	setupRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setupRecorder := httptest.NewRecorder()
	handler.ServeHTTP(setupRecorder, setupRequest)
	if setupRecorder.Code != http.StatusSeeOther {
		t.Fatalf("expected setup redirect, status=%d body=%s", setupRecorder.Code, setupRecorder.Body.String())
	}

	var sessionCookie, csrfCookie *http.Cookie
	for _, cookie := range setupRecorder.Result().Cookies() {
		switch cookie.Name {
		case SessionCookieName:
			sessionCookie = cookie
		case CSRFTokenCookieName:
			csrfCookie = cookie
		}
	}
	if sessionCookie == nil || csrfCookie == nil {
		t.Fatalf("expected session and csrf cookies")
	}

	provisionForm := url.Values{
		"csrf_token":        []string{csrfCookie.Value},
		"root_name":         []string{"HomePKI Root CA"},
		"intermediate_name": []string{"HomePKI Intermediate CA"},
	}.Encode()
	provisionRequest := httptest.NewRequest(http.MethodPost, "/setup/ca", strings.NewReader(provisionForm))
	provisionRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	provisionRequest.AddCookie(sessionCookie)
	provisionRequest.AddCookie(csrfCookie)
	provisionRecorder := httptest.NewRecorder()
	handler.ServeHTTP(provisionRecorder, provisionRequest)
	if provisionRecorder.Code != http.StatusSeeOther {
		t.Fatalf("expected provision redirect, status=%d body=%s", provisionRecorder.Code, provisionRecorder.Body.String())
	}

	dashboardRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	dashboardRequest.Header.Set("Accept", "text/html")
	dashboardRequest.AddCookie(sessionCookie)
	dashboardRequest.AddCookie(csrfCookie)
	dashboardRecorder := httptest.NewRecorder()
	handler.ServeHTTP(dashboardRecorder, dashboardRequest)
	if dashboardRecorder.Code != http.StatusOK {
		t.Fatalf("expected dashboard page, status=%d body=%s", dashboardRecorder.Code, dashboardRecorder.Body.String())
	}
	dashboardBody := dashboardRecorder.Body.Bytes()
	if !bytes.Contains(dashboardBody, []byte("3 months (recommended)")) ||
		!bytes.Contains(dashboardBody, []byte("value=\"2160\" selected")) ||
		!bytes.Contains(dashboardBody, []byte("You must verify you control each name before issuing")) {
		t.Fatalf("expected certificate lifetime options and ownership guidance, body=%s", dashboardRecorder.Body.String())
	}

	issueForm := url.Values{
		"csrf_token":  []string{csrfCookie.Value},
		"common_name": []string{"service.home.example"},
		"dns_names":   []string{"alias.home.example"},
		"ttl_hours":   []string{"24"},
	}.Encode()
	issueRequest := httptest.NewRequest(http.MethodPost, "/certificates", strings.NewReader(issueForm))
	issueRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	issueRequest.AddCookie(sessionCookie)
	issueRequest.AddCookie(csrfCookie)
	issueRecorder := httptest.NewRecorder()
	handler.ServeHTTP(issueRecorder, issueRequest)
	if issueRecorder.Code != http.StatusOK || issueRecorder.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("expected certificate bundle, status=%d content-type=%q body=%s",
			issueRecorder.Code,
			issueRecorder.Header().Get("Content-Type"),
			issueRecorder.Body.String(),
		)
	}
	if disposition := issueRecorder.Header().Get("Content-Disposition"); !strings.Contains(disposition, "serial-1.zip") {
		t.Fatalf("unexpected content disposition: %s", disposition)
	}
}

func TestSetupLoginAndCertificateFlows(t *testing.T) {
	t.Parallel()

	handler, dbPath, _, teardown := newTestServer(t, false)
	defer teardown()

	csrfToken, sessionCookie := setupAdminSession(t, handler, "admin", "secret-password")

	issuePayload := mustJSON(t, map[string]any{
		"common_name": "service.home",
		"dns_names":   []string{"service.home"},
		"ttl_hours":   24,
	})

	issueRequest := httptest.NewRequest(http.MethodPost, "/certificates", bytes.NewReader(issuePayload))
	issueRequest.Header.Set("Content-Type", "application/json")
	issueRequest.Header.Set(CSRFHeaderName, csrfToken)
	issueRequest.AddCookie(sessionCookie)
	issueRecorder := httptest.NewRecorder()
	handler.ServeHTTP(issueRecorder, issueRequest)
	if issueRecorder.Code != http.StatusCreated {
		t.Fatalf("issue status=%d body=%s", issueRecorder.Code, issueRecorder.Body.String())
	}

	var issued struct {
		SerialNumber string `json:"serial_number"`
	}
	if err := json.Unmarshal(issueRecorder.Body.Bytes(), &issued); err != nil {
		t.Fatalf("unmarshal issue response: %v", err)
	}
	if issued.SerialNumber == "" {
		t.Fatalf("expected serial number")
	}

	listRequest := httptest.NewRequest(http.MethodGet, "/certificates", nil)
	listRequest.AddCookie(sessionCookie)
	listRecorder := httptest.NewRecorder()
	handler.ServeHTTP(listRecorder, listRequest)
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listRecorder.Code, listRecorder.Body.String())
	}

	revokeRequest := httptest.NewRequest(http.MethodPost, "/certificates/"+issued.SerialNumber+"/revoke", bytes.NewReader(
		mustJSON(t, map[string]string{"confirm": "REVOKE"}),
	))
	revokeRequest.Header.Set("Content-Type", "application/json")
	revokeRequest.Header.Set(CSRFHeaderName, csrfToken)
	revokeRequest.AddCookie(sessionCookie)
	revokeRecorder := httptest.NewRecorder()
	handler.ServeHTTP(revokeRecorder, revokeRequest)
	if revokeRecorder.Code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", revokeRecorder.Code, revokeRecorder.Body.String())
	}

	deleteRequest := httptest.NewRequest(http.MethodPost, "/certificates/"+issued.SerialNumber+"/delete", bytes.NewReader(
		mustJSON(t, map[string]string{"confirm": "DELETE"}),
	))
	deleteRequest.Header.Set("Content-Type", "application/json")
	deleteRequest.Header.Set(CSRFHeaderName, csrfToken)
	deleteRequest.AddCookie(sessionCookie)
	deleteRecorder := httptest.NewRecorder()
	handler.ServeHTTP(deleteRecorder, deleteRequest)
	if deleteRecorder.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", deleteRecorder.Code, deleteRecorder.Body.String())
	}

	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("expected db to exist before reset: %v", err)
	}
}

func TestLoginRejectsInvalidPassword(t *testing.T) {
	t.Parallel()

	handler, _, _, teardown := newTestServer(t, false)
	defer teardown()
	setupAdminSession(t, handler, "admin", "right-password")

	loginPayload := mustJSON(t, map[string]string{
		"username": "admin",
		"password": "wrong-password",
	})
	loginRequest := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(loginPayload))
	loginRequest.Header.Set("Content-Type", "application/json")
	loginRecorder := httptest.NewRecorder()
	handler.ServeHTTP(loginRecorder, loginRequest)
	if loginRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized login, got status=%d body=%s", loginRecorder.Code, loginRecorder.Body.String())
	}

}

func TestSetupRejectsShortPassword(t *testing.T) {
	t.Parallel()

	handler, _, _, teardown := newTestServer(t, false)
	defer teardown()

	request := httptest.NewRequest(http.MethodPost, "/setup/admin", bytes.NewReader(
		mustJSON(t, map[string]string{
			"username": "admin",
			"password": "short",
		}),
	))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected short password rejection, status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestBackupAndFactoryResetFlows(t *testing.T) {
	t.Parallel()

	handler, dbPath, tempDir, teardown := newTestServer(t, true)
	defer teardown()
	csrfToken, sessionCookie := setupAdminSession(t, handler, "admin", "secret-password")

	unsafeBackupRequest := httptest.NewRequest(http.MethodPost, "/admin/backup", bytes.NewReader(
		mustJSON(t, map[string]string{"name_suffix": "../escape"}),
	))
	unsafeBackupRequest.Header.Set("Content-Type", "application/json")
	unsafeBackupRequest.Header.Set(CSRFHeaderName, csrfToken)
	unsafeBackupRequest.AddCookie(sessionCookie)
	unsafeBackupRecorder := httptest.NewRecorder()
	handler.ServeHTTP(unsafeBackupRecorder, unsafeBackupRequest)
	if unsafeBackupRecorder.Code != http.StatusBadRequest {
		t.Fatalf("expected unsafe backup suffix rejection, status=%d body=%s", unsafeBackupRecorder.Code, unsafeBackupRecorder.Body.String())
	}

	backupRequest := httptest.NewRequest(http.MethodPost, "/admin/backup", bytes.NewReader(
		mustJSON(t, map[string]string{"name_suffix": "test"}),
	))
	backupRequest.Header.Set("Content-Type", "application/json")
	backupRequest.Header.Set(CSRFHeaderName, csrfToken)
	backupRequest.AddCookie(sessionCookie)
	backupRecorder := httptest.NewRecorder()
	handler.ServeHTTP(backupRecorder, backupRequest)
	if backupRecorder.Code != http.StatusOK {
		t.Fatalf("backup status=%d body=%s", backupRecorder.Code, backupRecorder.Body.String())
	}

	var backupResponse map[string]string
	if err := json.Unmarshal(backupRecorder.Body.Bytes(), &backupResponse); err != nil {
		t.Fatalf("unmarshal backup response: %v", err)
	}
	archivePath := backupResponse["archive_path"]
	if archivePath == "" {
		t.Fatalf("expected archive_path in backup response")
	}
	if _, err := os.Stat(archivePath); err != nil {
		t.Fatalf("expected archive at %s: %v", archivePath, err)
	}

	resetRequest := httptest.NewRequest(http.MethodPost, "/admin/factory-reset", bytes.NewReader(
		mustJSON(t, map[string]string{"confirm": "FACTORY_RESET"}),
	))
	resetRequest.Header.Set("Content-Type", "application/json")
	resetRequest.Header.Set(CSRFHeaderName, csrfToken)
	resetRequest.AddCookie(sessionCookie)
	resetRecorder := httptest.NewRecorder()
	handler.ServeHTTP(resetRecorder, resetRequest)
	if resetRecorder.Code != http.StatusAccepted {
		t.Fatalf("factory reset status=%d body=%s", resetRecorder.Code, resetRecorder.Body.String())
	}

	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatalf("expected db to be removed by factory reset, err=%v", err)
	}

	if _, err := os.Stat(filepath.Join(tempDir, "config.yaml")); err != nil {
		t.Fatalf("expected config to remain after factory reset: %v", err)
	}
}

func TestTrustGuidanceIncludesCertificateDownloadsAndFingerprints(t *testing.T) {
	t.Parallel()

	handler, _, _, teardown := newTestServer(t, false)
	defer teardown()
	_, sessionCookie := setupAdminSession(t, handler, "admin", "secret-password")

	trustRequest := httptest.NewRequest(http.MethodGet, "/trust-guidance", nil)
	trustRequest.Header.Set("Accept", "text/html")
	trustRequest.AddCookie(sessionCookie)
	trustRecorder := httptest.NewRecorder()
	handler.ServeHTTP(trustRecorder, trustRequest)
	if trustRecorder.Code != http.StatusOK {
		t.Fatalf("trust guidance status=%d body=%s", trustRecorder.Code, trustRecorder.Body.String())
	}
	trustBody := trustRecorder.Body.Bytes()
	if !bytes.Contains(trustBody, []byte("/trust/root-ca.crt")) ||
		!bytes.Contains(trustBody, []byte("/trust/intermediate-ca.crt")) ||
		!bytes.Contains(trustBody, []byte("openssl x509 -in root_ca.crt -noout -fingerprint -sha256")) {
		t.Fatalf("expected certificate download and verification instructions, body=%s", trustRecorder.Body.String())
	}

	rootRequest := httptest.NewRequest(http.MethodGet, "/trust/root-ca.crt", nil)
	rootRequest.AddCookie(sessionCookie)
	rootRecorder := httptest.NewRecorder()
	handler.ServeHTTP(rootRecorder, rootRequest)
	if rootRecorder.Code != http.StatusOK || !bytes.Contains(rootRecorder.Body.Bytes(), []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("root certificate download status=%d body=%s", rootRecorder.Code, rootRecorder.Body.String())
	}

	intermediateRequest := httptest.NewRequest(http.MethodGet, "/trust/intermediate-ca.crt", nil)
	intermediateRequest.AddCookie(sessionCookie)
	intermediateRecorder := httptest.NewRecorder()
	handler.ServeHTTP(intermediateRecorder, intermediateRequest)
	if intermediateRecorder.Code != http.StatusOK || !bytes.Contains(intermediateRecorder.Body.Bytes(), []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("intermediate certificate download status=%d body=%s", intermediateRecorder.Code, intermediateRecorder.Body.String())
	}
}

func newTestServer(t *testing.T, includeBackupPaths bool) (http.Handler, string, string, func()) {
	return newTestServerWithConfig(t, includeBackupPaths, nil)
}

func newTestServerWithPKI(t *testing.T, service pki.Service) (http.Handler, string, string, func()) {
	return newTestServerWithConfig(t, false, service)
}

func newTestServerWithConfig(t *testing.T, includeBackupPaths bool, service pki.Service) (http.Handler, string, string, func()) {
	t.Helper()

	ctx := context.Background()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "homepki.db")
	configPath := filepath.Join(tempDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("storage:\n  sqlite_path: ./homepki.db\n"), 0o600); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}

	db, err := storage.OpenSQLite(ctx, storage.SQLiteOptions{Path: dbPath})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}

	migrationsDir := filepath.Join("..", "..", "migrations")
	if err := storage.ApplyMigrationsFromDir(ctx, db, migrationsDir); err != nil {
		_ = db.Close()
		t.Fatalf("apply migrations: %v", err)
	}

	server := Server{
		DB:                   db,
		PKI:                  service,
		SessionTTL:           4 * time.Hour,
		AllowInsecureCookies: true,
		ProtectedPaths:       buildProtectedCertificatePaths(t, tempDir),
	}
	if includeBackupPaths {
		server.SQLitePath = dbPath
		server.ConfigPath = configPath
		server.BackupOutputDir = tempDir
	}

	handler := NewServer(server)
	return handler, dbPath, tempDir, func() { _ = db.Close() }
}

func buildProtectedCertificatePaths(t *testing.T, tempDir string) []string {
	t.Helper()

	stepPath := filepath.Join(tempDir, ".step")
	certsPath := filepath.Join(stepPath, "certs")
	if err := os.MkdirAll(certsPath, 0o700); err != nil {
		t.Fatalf("create certs path: %v", err)
	}
	rootPath := filepath.Join(certsPath, "root_ca.crt")
	intermediatePath := filepath.Join(certsPath, "intermediate_ca.crt")
	writeTestCertificatePEM(t, rootPath, "HomePKI Test Root")
	writeTestCertificatePEM(t, intermediatePath, "HomePKI Test Intermediate")
	return []string{stepPath, rootPath}
}

func writeTestCertificatePEM(t *testing.T, path, commonName string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}
	content := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write test certificate: %v", err)
	}
}

func setupAdminSession(t *testing.T, handler http.Handler, username, password string) (string, *http.Cookie) {
	t.Helper()

	payload := mustJSON(t, map[string]string{
		"username": username,
		"password": password,
	})
	request := httptest.NewRequest(http.MethodPost, "/setup/admin", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("setup status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	var response map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal setup response: %v", err)
	}
	csrfToken := response["csrf_token"]
	if csrfToken == "" {
		t.Fatalf("missing csrf token")
	}

	cookies := recorder.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("missing session cookie")
	}
	return csrfToken, cookies[0]
}

func mustJSON(t *testing.T, payload any) []byte {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal json payload: %v", err)
	}
	return raw
}
