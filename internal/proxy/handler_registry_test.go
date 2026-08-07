package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/temporalio/deputy/internal/ecosystem"
	"github.com/temporalio/deputy/internal/policy"
	"google.golang.org/protobuf/proto"
)

// noopPolicyEvaluator is a test policy evaluator that allows all requests.
type noopPolicyEvaluator struct{}

func (noopPolicyEvaluator) Evaluate(ctx context.Context, entrypoint string, input proto.Message) ([]policy.Action, error) {
	return nil, nil
}

func TestHandlerFactory_CreateHandler(t *testing.T) {
	factory := NewHandlerFactory()

	// Create a mock upstream server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Create a no-op policy evaluator
	eval := noopPolicyEvaluator{}

	tests := []struct {
		name      string
		ecosystem ecosystem.Ecosystem
		wantErr   bool
	}{
		{"npm", ecosystem.NPM, false},
		{"pypi", ecosystem.PyPI, false},
		{"go", ecosystem.Go, false},
		{"rubygems", ecosystem.RubyGems, false},
		{"unknown", ecosystem.Unknown, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, err := factory.CreateHandler(tt.ecosystem, upstream.URL, eval)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if handler == nil {
				t.Error("expected handler, got nil")
			}
		})
	}
}

func TestHandlerFactory_CreateHandlerWithOptions(t *testing.T) {
	factory := NewHandlerFactory()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	eval := noopPolicyEvaluator{}

	// Create isolated caches for testing
	opts := &HandlerOptions{
		OSVCache:     NewOSVCache(),
		LicenseCache: NewLicenseCache(),
	}

	handler, err := factory.CreateHandlerWithOptions(ecosystem.Go, upstream.URL, eval, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if handler == nil {
		t.Error("expected handler, got nil")
	}
}

func TestHandlerFactory_SupportedEcosystems(t *testing.T) {
	factory := NewHandlerFactory()
	ecosystems := factory.SupportedEcosystems()

	if len(ecosystems) < 4 {
		t.Errorf("expected at least 4 supported ecosystems, got %d", len(ecosystems))
	}

	// Verify all expected ecosystems are present
	expected := map[ecosystem.Ecosystem]bool{
		ecosystem.NPM:      false,
		ecosystem.PyPI:     false,
		ecosystem.Go:       false,
		ecosystem.RubyGems: false,
	}

	for _, eco := range ecosystems {
		if _, ok := expected[eco]; ok {
			expected[eco] = true
		}
	}

	for eco, found := range expected {
		if !found {
			t.Errorf("expected ecosystem %s not found in supported list", eco)
		}
	}
}

func TestHandlerFactory_Register(t *testing.T) {
	factory := NewHandlerFactory()

	// Register a custom ecosystem
	customConfig := EcosystemConfig{
		Ecosystem: ecosystem.Cargo,
		PathParser: func(path string) PathParseResult {
			return PathParseResult{Name: "test", Version: "1.0.0", Operation: "download"}
		},
	}

	factory.Register(customConfig)

	ecosystems := factory.SupportedEcosystems()
	found := slices.Contains(ecosystems, ecosystem.Cargo)
	if !found {
		t.Error("registered ecosystem not found in supported list")
	}

	// Registration must extend this factory only, never the package-level
	// default registry shared by every other factory.
	if _, ok := ecosystemRegistry[ecosystem.Cargo]; ok {
		t.Error("Register mutated the package-level default registry; factories must own their registry copy")
	}
}

func TestNewHandlerFromString(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	eval := noopPolicyEvaluator{}

	tests := []struct {
		name    string
		eco     string
		wantErr bool
	}{
		{"npm", "npm", false},
		{"npm_uppercase", "NPM", false},
		{"javascript_alias", "javascript", false},
		{"go", "go", false},
		{"golang_alias", "golang", false},
		{"oci", "oci", false},
		{"unknown", "unknown_eco", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, err := NewHandlerFromString(tt.eco, upstream.URL, eval)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if handler == nil {
				t.Error("expected handler, got nil")
			}
		})
	}
}

func TestGenericHandler_ServeHTTP(t *testing.T) {
	// Create a mock upstream that echoes back the request path
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Path", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	eval := noopPolicyEvaluator{}
	factory := NewHandlerFactory()

	// Test NPM handler
	t.Run("npm_metadata", func(t *testing.T) {
		handler, err := factory.CreateHandler(ecosystem.NPM, upstream.URL, eval)
		if err != nil {
			t.Fatalf("failed to create handler: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/lodash", nil)
		req = req.WithContext(t.Context())
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		// Request should be proxied (we're just testing it doesn't error)
		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
	})

	// Test Go handler with valid path
	t.Run("go_module_list", func(t *testing.T) {
		handler, err := factory.CreateHandler(ecosystem.Go, upstream.URL, eval)
		if err != nil {
			t.Fatalf("failed to create handler: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/github.com/foo/bar/@v/list", nil)
		req = req.WithContext(t.Context())
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
	})

	// Test Go handler with invalid path
	t.Run("go_invalid_path", func(t *testing.T) {
		handler, err := factory.CreateHandler(ecosystem.Go, upstream.URL, eval)
		if err != nil {
			t.Fatalf("failed to create handler: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/invalid/path", nil)
		req = req.WithContext(t.Context())
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		// Should return 400 Bad Request for invalid Go proxy paths
		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d", rec.Code)
		}
	})
}

// TestEcosystemRegistryEntrypointsAreCanonical pins the call-site invariant of
// genericHandler.ServeHTTP: every ecosystem registered for proxying must have
// proxy capability and must synthesize a canonical policy entrypoint,
// otherwise proxy policies written for it would never match. It also checks
// the registry covers every proxy-capable ecosystem so download-time policy
// enforcement cannot silently lose an ecosystem.
func TestEcosystemRegistryEntrypointsAreCanonical(t *testing.T) {
	// Sanity floor: 4 proxied ecosystems today (go, npm, pypi, rubygems).
	if len(ecosystemRegistry) < 4 {
		t.Fatalf("ecosystemRegistry has %d ecosystems, want at least 4", len(ecosystemRegistry))
	}

	for eco, config := range ecosystemRegistry {
		if config.Ecosystem != eco {
			t.Errorf("ecosystemRegistry[%s].Ecosystem = %s, want key and value to match", eco, config.Ecosystem)
		}
		if !eco.Capabilities().Proxy {
			t.Errorf("ecosystemRegistry contains %s, which does not declare proxy capability", eco)
		}
		if ep := eco.ProxyEntrypoint(); !ep.IsValid() {
			t.Errorf("proxied ecosystem %s synthesizes entrypoint %q, which is not a canonical policy entrypoint", eco, ep)
		}
	}

	for _, eco := range ecosystem.WithProxy() {
		if _, ok := ecosystemRegistry[eco]; !ok {
			t.Errorf("proxy-capable ecosystem %s is missing from ecosystemRegistry", eco)
		}
	}
}
