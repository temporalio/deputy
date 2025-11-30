package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// Integration: use the composed license allowlist bundle end-to-end through the Go handler.
func TestGoHandler_ComposedBundleIntegration(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	pol := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "license-allowlist-composed.yaml"))
	engine, err := NewPolicyEngine([]string{pol})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}
	handler, err := newGoModuleHandler(upstream.URL, engine)
	if err != nil {
		t.Fatalf("newGoModuleHandler: %v", err)
	}
	handler.osvClient = nil
	handler.licenseLookup = func(ctx context.Context, module, version string) ([]string, error) {
		return []string{"GPL-3.0"}, nil
	}

	req := httptest.NewRequest(http.MethodGet, "/github.com/example/mod/@v/v1.0.0.zip", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 from composed bundle, got %d", rr.Code)
	}
}

func TestGoHandler_ComposedBundleIntegration_AllowsPermissive(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	pol := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "license-allowlist-composed.yaml"))
	engine, err := NewPolicyEngine([]string{pol})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}
	handler, err := newGoModuleHandler(upstream.URL, engine)
	if err != nil {
		t.Fatalf("newGoModuleHandler: %v", err)
	}
	handler.osvClient = nil
	handler.licenseLookup = func(ctx context.Context, module, version string) ([]string, error) {
		return []string{"MIT"}, nil
	}

	req := httptest.NewRequest(http.MethodGet, "/github.com/example/mod/@v/v1.0.0.zip", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for permissive license, got %d", rr.Code)
	}
}
