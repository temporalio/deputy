package cmd

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestEnvPreparers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		prep     envPreparer
		proxyURL string
		validate func(t *testing.T, env []string, cleanup func())
	}{
		{
			name:     "go",
			prep:     prepareGoEnv,
			proxyURL: "http://127.0.0.1:1234",
			validate: func(t *testing.T, env []string, cleanup func()) {
				if cleanup != nil {
					t.Fatalf("expected nil cleanup")
				}
				if !containsEnv(env, "GOPROXY=http://127.0.0.1:1234,direct") {
					t.Fatalf("env missing GOPROXY: %v", env)
				}
			},
		},
		{
			name:     "npm",
			prep:     prepareNPMEnv,
			proxyURL: "http://127.0.0.1:4321",
			validate: func(t *testing.T, env []string, cleanup func()) {
				if !containsEnv(env, "NPM_CONFIG_REGISTRY=http://127.0.0.1:4321") {
					t.Fatalf("missing npm registry: %v", env)
				}
				if !containsEnv(env, "NPM_CONFIG_STRICT_SSL=false") {
					t.Fatalf("missing strict ssl override: %v", env)
				}
			},
		},
		{
			name:     "pypi",
			prep:     preparePyPIEnv,
			proxyURL: "http://127.0.0.1:5000",
			validate: func(t *testing.T, env []string, cleanup func()) {
				if !containsEnv(env, "PIP_INDEX_URL=http://127.0.0.1:5000/simple") {
					t.Fatalf("missing index env: %v", env)
				}
				if !containsEnv(env, "PIP_TRUSTED_HOST=127.0.0.1:5000") {
					t.Fatalf("missing trusted host: %v", env)
				}
			},
		},
		{
			name:     "rubygems",
			prep:     prepareRubyGemsEnv,
			proxyURL: "http://127.0.0.1:9000",
			validate: func(t *testing.T, env []string, cleanup func()) {
				if cleanup == nil {
					t.Fatalf("expected cleanup func")
				}
				var gemrcPath string
				for _, kv := range env {
					if strings.HasPrefix(kv, "GEMRC=") {
						gemrcPath = strings.TrimPrefix(kv, "GEMRC=")
					}
				}
				if gemrcPath == "" {
					t.Fatalf("gemrc not set: %v", env)
				}
				data, err := os.ReadFile(gemrcPath)
				if err != nil {
					t.Fatalf("read gemrc: %v", err)
				}
				if !strings.Contains(string(data), "http://127.0.0.1:9000") {
					t.Fatalf("gemrc missing proxy source: %s", data)
				}
				cleanup()
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			env, cleanup, err := test.prep(test.proxyURL)
			if err != nil {
				t.Fatalf("prep error: %v", err)
			}
			if len(env) == 0 {
				t.Fatalf("expected env vars")
			}
			test.validate(t, env, cleanup)
		})
	}
}

func TestRunProxyExecSetsEnv(t *testing.T) {
	t.Cleanup(func() {
		startProxyForEcosystem = startEcosystemProxy
		execProxyCommand = runExternalCommand
	})
	startProxyForEcosystem = func(ctx context.Context, ecosystem, upstream string, policyPaths []string) (*proxyInstance, error) {
		if ecosystem != "go" {
			t.Fatalf("unexpected ecosystem %s", ecosystem)
		}
		return &proxyInstance{
			url:  "http://127.0.0.1:5555",
			stop: func(context.Context) error { return nil },
		}, nil
	}
	captured := []string{}
	execProxyCommand = func(ctx context.Context, command []string, env []string) error {
		captured = append([]string{}, env...)
		return nil
	}
	cfg := proxyExecConfig{
		ecosystem: "go",
		upstream:  "https://proxy.golang.org",
		envPrep:   prepareGoEnv,
	}
	if err := runProxyExec(context.Background(), cfg, []string{"echo"}); err != nil {
		t.Fatalf("runProxyExec error: %v", err)
	}
	if !containsEnv(captured, "GOPROXY=http://127.0.0.1:5555,direct") {
		t.Fatalf("env missing GOPROXY: %v", captured)
	}
}

func TestStartProxyInstance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	})
	inst, err := startProxyInstance(ctx, handler)
	if err != nil {
		t.Fatalf("startProxyInstance error: %v", err)
	}
	resp, err := http.Get(inst.url)
	if err != nil {
		t.Fatalf("http get: %v", err)
	}
	resp.Body.Close()
	if err := inst.stop(context.Background()); err != nil {
		t.Fatalf("stop error: %v", err)
	}
}

func TestInstrumentProxyHandlerCapturesDeny(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Deputy-Policy", "unit-test")
		w.Header().Set("X-Deputy-Name", "pkg")
		w.Header().Set("X-Deputy-Version", "1.0.0")
		w.Header().Set("X-Deputy-Ecosystem", "npm")
		w.Header().Set("X-Deputy-Operation", "metadata")
		w.Header().Set("X-Deputy-Reason", "blocked by policy")
		http.Error(w, "blocked by policy", http.StatusForbidden)
	})
	instrumented, events := instrumentProxyHandler(handler)

	req := httptest.NewRequest(http.MethodGet, "/pkg/-/pkg-1.0.0.tgz", nil)
	rec := httptest.NewRecorder()
	instrumented.ServeHTTP(rec, req)

	select {
	case evt := <-events:
		if evt.status != http.StatusForbidden {
			t.Fatalf("unexpected status %d", evt.status)
		}
		if evt.policy != "unit-test" {
			t.Fatalf("unexpected policy header: %s", evt.policy)
		}
		if evt.reason != "blocked by policy" {
			t.Fatalf("missing reason: %s", evt.reason)
		}
		if evt.name != "pkg" || evt.version != "1.0.0" || evt.ecosystem != "npm" || evt.operation != "metadata" {
			t.Fatalf("metadata missing: %+v", evt)
		}
	default:
		t.Fatalf("expected policy event")
	}
}

func containsEnv(env []string, target string) bool {
	for _, v := range env {
		if v == target {
			return true
		}
	}
	return false
}
