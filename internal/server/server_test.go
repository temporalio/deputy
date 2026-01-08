package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"

	scanv1 "github.com/picatz/deputy/gen/deputy/scan/v1"
	"github.com/picatz/deputy/gen/deputy/scan/v1/scanv1connect"
)

func TestHealthEndpoint(t *testing.T) {
	srv := New(DefaultConfig())

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
	srv := New(DefaultConfig())

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
	srv := New(DefaultConfig())

	// Start test server
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Create client
	client := scanv1connect.NewScanServiceClient(
		http.DefaultClient,
		ts.URL,
	)

	// Call with empty target - should return InvalidArgument error
	_, err := client.Scan(context.Background(), connect.NewRequest(&scanv1.ScanRequest{
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

	if cfg.Addr != ":8090" {
		t.Errorf("expected :8090, got %s", cfg.Addr)
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
	srv := New(Config{})

	if srv.Addr() != ":8090" {
		t.Errorf("expected default addr :8090, got %s", srv.Addr())
	}
}
