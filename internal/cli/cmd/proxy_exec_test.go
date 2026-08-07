package cmd

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
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
					if after, ok := strings.CutPrefix(kv, "GEMRC="); ok {
						gemrcPath = after
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
		{
			name:     "oci",
			prep:     prepareOCIEnv,
			proxyURL: "http://127.0.0.1:8123",
			validate: func(t *testing.T, env []string, cleanup func()) {
				if cleanup != nil {
					t.Fatalf("expected nil cleanup")
				}
				if !containsEnv(env, "DEPUTY_OCI_PROXY=http://127.0.0.1:8123") {
					t.Fatalf("missing proxy env: %v", env)
				}
				if !containsEnv(env, "DEPUTY_OCI_PROXY_HOST=127.0.0.1:8123") {
					t.Fatalf("missing proxy host env: %v", env)
				}
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

func TestRewriteOCICommand(t *testing.T) {
	out, err := rewriteOCICommand("http://127.0.0.1:5555", "https://registry-1.docker.io", []string{"docker", "pull", "ubuntu:latest"})
	if err != nil {
		t.Fatalf("rewrite error: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("unexpected args: %v", out)
	}
	if out[2] != "127.0.0.1:5555/library/ubuntu:latest" {
		t.Fatalf("rewrote %q", out[2])
	}

	unchanged, err := rewriteOCICommand("http://127.0.0.1:5555", "https://registry-1.docker.io", []string{"docker", "pull", "ghcr.io/acme/app:1.0"})
	if err != nil {
		t.Fatalf("rewrite error: %v", err)
	}
	if unchanged[2] != "ghcr.io/acme/app:1.0" {
		t.Fatalf("expected unchanged ref, got %q", unchanged[2])
	}

	ghcr, err := rewriteOCICommand("http://127.0.0.1:5555", "https://ghcr.io", []string{"podman", "pull", "ghcr.io/acme/app:1.0"})
	if err != nil {
		t.Fatalf("rewrite error: %v", err)
	}
	if ghcr[2] != "127.0.0.1:5555/acme/app:1.0" {
		t.Fatalf("rewrote %q", ghcr[2])
	}

	oci, err := rewriteOCICommand("http://127.0.0.1:5555", "https://ghcr.io", []string{"nerdctl", "pull", "oci://ghcr.io/acme/app:1.0"})
	if err != nil {
		t.Fatalf("rewrite error: %v", err)
	}
	if oci[2] != "oci://127.0.0.1:5555/acme/app:1.0" {
		t.Fatalf("rewrote %q", oci[2])
	}

	dockerHub, err := rewriteOCICommand("http://127.0.0.1:5555", "https://registry-1.docker.io", []string{"docker", "pull", "registry-1.docker.io/library/ubuntu:latest"})
	if err != nil {
		t.Fatalf("rewrite error: %v", err)
	}
	if dockerHub[2] != "127.0.0.1:5555/library/ubuntu:latest" {
		t.Fatalf("rewrote %q", dockerHub[2])
	}

	noScheme, err := rewriteOCICommand("http://127.0.0.1:5555", "ghcr.io", []string{"docker", "pull", "ghcr.io/acme/app:1.0"})
	if err != nil {
		t.Fatalf("rewrite error: %v", err)
	}
	if noScheme[2] != "127.0.0.1:5555/acme/app:1.0" {
		t.Fatalf("rewrote %q", noScheme[2])
	}

	alreadyProxy, err := rewriteOCICommand("http://127.0.0.1:5555", "https://registry-1.docker.io", []string{"docker", "pull", "127.0.0.1:5555/library/ubuntu:latest"})
	if err != nil {
		t.Fatalf("rewrite error: %v", err)
	}
	if alreadyProxy[2] != "127.0.0.1:5555/library/ubuntu:latest" {
		t.Fatalf("expected unchanged ref, got %q", alreadyProxy[2])
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
	execProxyCommand = func(ctx context.Context, command []string, env []string, stdin io.Reader, stdout, stderr io.Writer) error {
		captured = append([]string{}, env...)
		return nil
	}
	cfg := proxyExecConfig{
		ecosystem: "go",
		upstream:  "https://proxy.golang.org",
		envPrep:   prepareGoEnv,
	}
	if err := runProxyExec(t.Context(), cfg, []string{"echo"}, nil, io.Discard, io.Discard); err != nil {
		t.Fatalf("runProxyExec error: %v", err)
	}
	if !containsEnv(captured, "GOPROXY=http://127.0.0.1:5555,direct") {
		t.Fatalf("env missing GOPROXY: %v", captured)
	}
}

func TestStartProxyInstance(t *testing.T) {
	ctx := t.Context()
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
	if err := inst.stop(t.Context()); err != nil {
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
	return slices.Contains(env, target)
}
