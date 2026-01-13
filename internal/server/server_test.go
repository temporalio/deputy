package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"

	listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
	"github.com/picatz/deputy/gen/deputy/list/v1/listv1connect"
	scanv1 "github.com/picatz/deputy/gen/deputy/scan/v1"
	"github.com/picatz/deputy/gen/deputy/scan/v1/scanv1connect"
	secretsv1 "github.com/picatz/deputy/gen/deputy/secrets/v1"
	"github.com/picatz/deputy/gen/deputy/secrets/v1/secretsv1connect"
)

func TestHealthEndpoint(t *testing.T) {
	srv, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	body, _ := io.ReadAll(rec.Body)
	if string(body) != `{"status":"ok"}` {
		t.Errorf("unexpected body: %s", body)
	}
}

func TestReadyEndpoint(t *testing.T) {
	srv, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	body, _ := io.ReadAll(rec.Body)
	if string(body) != `{"status":"ready"}` {
		t.Errorf("unexpected body: %s", body)
	}
}

func TestScanServiceRegistered(t *testing.T) {
	srv, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	// Start test server
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Create client
	client := scanv1connect.NewScanServiceClient(
		http.DefaultClient,
		ts.URL,
	)

	// Call with empty target - should return InvalidArgument error
	_, err = client.Scan(context.Background(), connect.NewRequest(&scanv1.ScanRequest{
		Target: "",
	}))

	if err == nil {
		t.Fatal("expected error for empty target")
	}

	// Check it's an InvalidArgument error
	connectErr, ok := err.(*connect.Error)
	if !ok {
		t.Fatalf("expected connect.Error, got %T", err)
	}
	if connectErr.Code() != connect.CodeInvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", connectErr.Code())
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Addr != "127.0.0.1:8090" {
		t.Errorf("expected 127.0.0.1:8090, got %s", cfg.Addr)
	}
	if cfg.ReadTimeout == 0 {
		t.Error("expected non-zero ReadTimeout")
	}
	if cfg.WriteTimeout == 0 {
		t.Error("expected non-zero WriteTimeout")
	}
	if cfg.IdleTimeout == 0 {
		t.Error("expected non-zero IdleTimeout")
	}
}

func TestNewServerWithEmptyConfig(t *testing.T) {
	// Should use defaults for empty config
	srv, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}

	if srv.Addr() != "127.0.0.1:8090" {
		t.Errorf("expected default addr 127.0.0.1:8090, got %s", srv.Addr())
	}
}

func TestVersionEndpoint(t *testing.T) {
	srv, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	body, _ := io.ReadAll(rec.Body)
	if string(body) != `{"version":"v1","api":"deputy.v1"}` {
		t.Errorf("unexpected body: %s", body)
	}
}

func TestSecretsServiceRegistered(t *testing.T) {
	srv, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	// Start test server
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Create client
	client := secretsv1connect.NewSecretsServiceClient(
		http.DefaultClient,
		ts.URL,
	)

	// Call ListDetectors - should succeed
	resp, err := client.ListDetectors(context.Background(), connect.NewRequest(&secretsv1.ListDetectorsRequest{}))
	if err != nil {
		t.Fatalf("ListDetectors failed: %v", err)
	}

	// Should return at least some detectors
	if len(resp.Msg.Detectors) == 0 {
		t.Error("expected at least one detector")
	}
}

func TestSecretsServiceScanEmptyTarget(t *testing.T) {
	srv, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	// Start test server
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Create client
	client := secretsv1connect.NewSecretsServiceClient(
		http.DefaultClient,
		ts.URL,
	)

	// Call Scan with empty target - should use "." as default
	// This will fail validation for remote targets, which is expected
	_, err = client.Scan(context.Background(), connect.NewRequest(&secretsv1.ScanRequest{
		Target: "",
	}))

	// For remote server mode, empty/local paths are rejected
	if err == nil {
		t.Fatal("expected error for empty target in remote mode")
	}

	connectErr, ok := err.(*connect.Error)
	if !ok {
		t.Fatalf("expected connect.Error, got %T", err)
	}
	if connectErr.Code() != connect.CodeInvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", connectErr.Code())
	}
}

func TestListServiceRegistered(t *testing.T) {
	srv, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	// Start test server
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Create client
	client := listv1connect.NewListServiceClient(
		http.DefaultClient,
		ts.URL,
	)

	// Call ListEcosystems - should succeed
	resp, err := client.ListEcosystems(context.Background(), connect.NewRequest(&listv1.ListEcosystemsRequest{}))
	if err != nil {
		t.Fatalf("ListEcosystems failed: %v", err)
	}

	// Should return at least some ecosystems
	if len(resp.Msg.Ecosystems) == 0 {
		t.Error("expected at least one ecosystem")
	}
}

func TestAllServicesRegistered(t *testing.T) {
	srv, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	// Start test server
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Test that all service endpoints respond (not 404)
	// We use actual method paths since ConnectRPC routes service/method
	serviceEndpoints := []struct {
		path        string
		contentType string
	}{
		// Scan service
		{"/deputy.scan.v1.ScanService/Scan", "application/json"},
		// List service
		{"/deputy.list.v1.ListService/ListPackages", "application/json"},
		{"/deputy.list.v1.ListService/ListEcosystems", "application/json"},
		// SBOM service
		{"/deputy.sbom.v1.SBOMService/Generate", "application/json"},
		{"/deputy.sbom.v1.SBOMService/Diff", "application/json"},
		// Remediation service
		{"/deputy.remediation.v1.RemediationService/GeneratePlan", "application/json"},
		// Secrets service
		{"/deputy.secrets.v1.SecretsService/Scan", "application/json"},
		{"/deputy.secrets.v1.SecretsService/ListDetectors", "application/json"},
	}

	for _, ep := range serviceEndpoints {
		req, err := http.NewRequest(http.MethodPost, ts.URL+ep.path, nil)
		if err != nil {
			t.Fatalf("failed to create request for %s: %v", ep.path, err)
		}
		req.Header.Set("Content-Type", ep.contentType)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request to %s failed: %v", ep.path, err)
		}
		resp.Body.Close()

		// Should not be 404 (service is registered)
		if resp.StatusCode == http.StatusNotFound {
			t.Errorf("endpoint %s returned 404 - not registered", ep.path)
		}
	}
}
