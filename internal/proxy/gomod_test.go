package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	analysis "github.com/picatz/deputy/internal/analysis"
	"github.com/picatz/deputy/internal/policy"
)

func TestParseGoProxyPath(t *testing.T) {
	cases := []struct {
		path                string
		module, version, ft string
	}{
		{"/github.com/foo/bar/@v/v1.2.3.zip", "github.com/foo/bar", "v1.2.3", ".zip"},
		{"/github.com/foo/bar/@v/list", "github.com/foo/bar", "", ".list"},
		{"/github.com/foo/bar/@v/v1.2.3.mod", "github.com/foo/bar", "v1.2.3", ".mod"},
	}
	for _, c := range cases {
		mod, ver, ft, _, err := parseGoProxyPath(c.path)
		if err != nil {
			t.Fatalf("parseGoProxyPath(%q) unexpected error: %v", c.path, err)
		}
		if mod != c.module || ver != c.version || ft != c.ft {
			t.Fatalf("parseGoProxyPath(%q) => %s %s %s", c.path, mod, ver, ft)
		}
	}
}

func TestGoModuleHandlerPassThrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/github.com/foo/bar/@v/v1.2.3.zip" {
			t.Fatalf("unexpected upstream path %s", r.URL.Path)
		}
		w.Header().Set("X-Upstream", "ok")
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte("payload"))
	}))
	defer upstream.Close()

	handler, err := newGoModuleHandler(upstream.URL, nil)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	handler.osvClient = nil

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/github.com/foo/bar/@v/v1.2.3.zip", nil)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected status 202, got %d", rr.Code)
	}
	if got := rr.Header().Get("X-Upstream"); got != "ok" {
		t.Fatalf("expected upstream header, got %q", got)
	}
	if body := rr.Body.String(); body != "payload" {
		t.Fatalf("unexpected body %q", body)
	}
}

func TestGoModuleHandlerForwardsRequestDetails(t *testing.T) {
	body := "payload"
	var (
		gotMethod string
		gotBody   string
		gotHeader string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		gotMethod = r.Method
		gotBody = string(data)
		gotHeader = r.Header.Get("Go-Get")
		w.WriteHeader(http.StatusCreated)
	}))
	defer upstream.Close()

	handler, err := newGoModuleHandler(upstream.URL, nil)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	handler.osvClient = nil
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/github.com/foo/bar/@v/v1.2.3.info", strings.NewReader(body))
	req.Header.Set("Go-Get", "1")
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.Code)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("expected method POST, got %s", gotMethod)
	}
	if gotBody != body {
		t.Fatalf("body mismatch: %q", gotBody)
	}
	if gotHeader != "1" {
		t.Fatalf("header missing, got %q", gotHeader)
	}
}

func TestGoModuleHandlerPolicyDeny(t *testing.T) {
	handler, err := newGoModuleHandler("https://example.com", denyPolicyEngine{})
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	handler.osvClient = nil
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/github.com/foo/bar/@v/v1.2.3.zip", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

type denyPolicyEngine struct{}

func (denyPolicyEngine) Evaluate(ctx context.Context, entrypoint string, payload map[string]any) ([]policy.Action, error) {
	return []policy.Action{{Type: "deny", Reason: "blocked"}}, nil
}

func TestGoModuleHandlerBlocksCriticalVulnerability(t *testing.T) {
	policySource := `//! policy.name = "block-critical"
(vulnerabilities.exists(v, v.Severity == "CRITICAL")
  ? [{"action":"deny","reason":"critical vuln"}]
  : [])`
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "critical.cel")
	if err := os.WriteFile(policyPath, []byte(policySource), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	engine, err := NewPolicyEngine([]string{policyPath})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}
	handler, err := newGoModuleHandler("https://proxy.golang.org", engine)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	handler.osvClient = nil
	blockedModule := "github.com/example/vuln"
	handler.vulnLookup = func(ctx context.Context, module, version string) ([]analysis.Vulnerability, error) {
		if module == blockedModule {
			return []analysis.Vulnerability{{ID: "OSV-CRIT", Severity: "CRITICAL", Package: module, Version: version}}, nil
		}
		return nil, nil
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+blockedModule+"/@v/v1.0.0.zip", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestGoModuleHandlerLicensePolicy(t *testing.T) {
	policySource := `//! policy.name = "block-gpl"
(licenses.exists(l, l == "GPL-3.0")
  ? [{"action":"deny","reason":"license policy"}]
  : [])`
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "license.cel")
	if err := os.WriteFile(policyPath, []byte(policySource), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	engine, err := NewPolicyEngine([]string{policyPath})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}
	handler, err := newGoModuleHandler("https://proxy.golang.org", engine)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	handler.osvClient = nil
	handler.licenseLookup = func(ctx context.Context, module, version string) ([]string, error) {
		if strings.Contains(module, "blocked") {
			return []string{"GPL-3.0"}, nil
		}
		return nil, nil
	}
	blocked := "/github.com/example/blocked/@v/v1.0.0.zip"
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, blocked, nil)
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for license block, got %d", resp.Code)
	}
}

func TestGoModuleHandlerLicenseAllowlistExample(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	pol := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "license-allowlist.yaml"))
	engine, err := NewPolicyEngine([]string{pol})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}
	handler, err := newGoModuleHandler(upstream.URL, engine)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	handler.osvClient = nil
	handler.licenseLookup = func(ctx context.Context, module, version string) ([]string, error) {
		return []string{"GPL-3.0"}, nil
	}

	req := httptest.NewRequest(http.MethodGet, "/github.com/example/mod/@v/v1.0.0.zip", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for license allowlist policy, got %d", rr.Code)
	}
}

func TestGoModuleHandlerEndToEndPolicies(t *testing.T) {
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		fmt.Fprintf(w, "module:%s", r.URL.Path)
	}))
	defer upstream.Close()

	tmp := t.TempDir()
	policies := []struct {
		name string
		src  string
	}{
		{
			name: "deny_blocked",
			src: `//! policy.name = "deny-blocked"
(request.module.contains("blocked")
  ? [{"action":"deny","reason":"blocked module"}]
  : [])`,
		},
		{
			name: "warn_unstable",
			src: `//! policy.name = "warn-unstable"
(request.version.startsWith("v0.")
  ? [{"action":"warn","reason":"experimental version"}]
  : [])`,
		},
	}

	var paths []string
	for _, pol := range policies {
		p := filepath.Join(tmp, pol.name+".cel")
		if err := os.WriteFile(p, []byte(pol.src), 0o644); err != nil {
			t.Fatalf("write policy %s: %v", pol.name, err)
		}
		paths = append(paths, p)
	}

	engine, err := NewPolicyEngine(paths)
	if err != nil {
		t.Fatalf("NewPolicyEngine() error = %v", err)
	}
	handler, err := newGoModuleHandler(upstream.URL, engine)
	if err != nil {
		t.Fatalf("newGoModuleHandler() error = %v", err)
	}
	handler.osvClient = nil
	ts := httptest.NewServer(handler)
	defer ts.Close()

	tests := []struct {
		name       string
		module     string
		version    string
		fileType   string
		wantStatus int
		wantHit    bool
	}{
		{
			name:       "allow stable version",
			module:     "github.com/example/ok",
			version:    "v1.0.0",
			fileType:   ".zip",
			wantStatus: http.StatusOK,
			wantHit:    true,
		},
		{
			name:       "deny blocked module",
			module:     "github.com/example/blocked",
			version:    "v1.2.3",
			fileType:   ".zip",
			wantStatus: http.StatusForbidden,
			wantHit:    false,
		},
		{
			name:       "warn only still allowed",
			module:     "github.com/example/ok",
			version:    "v0.9.0",
			fileType:   ".zip",
			wantStatus: http.StatusOK,
			wantHit:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := upstreamHits
			path := fmt.Sprintf("/%s/@v/%s%s", tt.module, tt.version, tt.fileType)
			resp, err := http.Get(ts.URL + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			resp.Body.Close()
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d want %d", resp.StatusCode, tt.wantStatus)
			}
			hitDelta := upstreamHits - before
			if tt.wantHit && hitDelta != 1 {
				t.Fatalf("expected upstream hit, got delta %d", hitDelta)
			}
			if !tt.wantHit && hitDelta != 0 {
				t.Fatalf("expected no upstream hit, got delta %d", hitDelta)
			}
		})
	}
}

func TestGoModuleHandlerEndToEndGoGet(t *testing.T) {
	if os.Getenv("DEPUTY_PROXY_E2E") != "1" {
		t.Skip("set DEPUTY_PROXY_E2E=1 to run go toolchain proxy E2E test")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go command not found: %v", err)
	}

	denyModule := "github.com/pkg/errors"
	warnPolicy := `//! policy.name = "warn-v0"
(request.version.startsWith("v0.")
  ? [{"action":"warn","reason":"unstable version"}]
  : [])`
	denyPolicy := fmt.Sprintf(`//! policy.name = "deny-specific"
(request.module == %q
  ? [{"action":"deny","reason":"blocked by policy"}]
  : [])`, denyModule)

	tmp := t.TempDir()
	var policyPaths []string
	for i, src := range []string{warnPolicy, denyPolicy} {
		path := filepath.Join(tmp, fmt.Sprintf("policy-%d.cel", i))
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatalf("write policy: %v", err)
		}
		policyPaths = append(policyPaths, path)
	}

	engine, err := NewPolicyEngine(policyPaths)
	if err != nil {
		t.Fatalf("NewPolicyEngine error: %v", err)
	}
	handler, err := newGoModuleHandler("https://proxy.golang.org", engine)
	if err != nil {
		t.Fatalf("newGoModuleHandler error: %v", err)
	}
	ts := httptest.NewServer(handler)
	defer ts.Close()

	type testCase struct {
		name    string
		module  string
		version string
		wantErr bool
	}

	tests := []testCase{
		{
			name:    "allow testify",
			module:  "github.com/stretchr/testify",
			version: "v1.8.4",
			wantErr: false,
		},
		{
			name:    "deny specific module",
			module:  denyModule,
			version: "v0.9.1",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			caseDir := filepath.Join(tmp, strings.ReplaceAll(tt.name, " ", "_"))
			if err := os.MkdirAll(caseDir, 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			gopath := filepath.Join(caseDir, "gopath")
			if err := os.MkdirAll(gopath, 0o755); err != nil {
				t.Fatalf("mkdir gopath: %v", err)
			}
			gomodcache := filepath.Join(gopath, "pkg", "mod")
			env := []string{
				fmt.Sprintf("GO111MODULE=on"),
				"GOSUMDB=off",
				"GOFLAGS=-modcacherw",
				fmt.Sprintf("GOPROXY=%s", ts.URL),
				fmt.Sprintf("GOPATH=%s", gopath),
				fmt.Sprintf("GOMODCACHE=%s", gomodcache),
			}

			if _, err := runGoCommand(ctx, caseDir, env, "mod", "init", "example.com/testproxy"); err != nil {
				t.Fatalf("go mod init: %v", err)
			}
			_, err := runGoCommand(ctx, caseDir, env, "mod", "download", fmt.Sprintf("%s@%s", tt.module, tt.version))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected download failure")
				}
				if !strings.Contains(err.Error(), "blocked by policy") {
					t.Fatalf("unexpected error: %v", err)
				}
			} else if err != nil {
				t.Fatalf("go mod download error: %v", err)
			}
		})
	}
}

func runGoCommand(ctx context.Context, dir string, baseEnv []string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), baseEnv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%w: %s", err, out)
	}
	return string(out), nil
}
