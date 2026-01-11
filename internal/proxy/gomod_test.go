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

	"github.com/picatz/deputy/internal/analysis/osv"
	"github.com/picatz/deputy/internal/policy"
)

func writeBundle(t *testing.T, dir, name, when, reason, action string) string {
	t.Helper()
	content := fmt.Sprintf(`policies:
  - name: %s
    rules:
      - action: %s
        when: %s
        reason: %q
`, name, action, when, reason)
	path := filepath.Join(dir, name+".yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write bundle %s: %v", name, err)
	}
	return path
}

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
	handler.lookups.osvClient = nil

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
	handler.lookups.osvClient = nil
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
	handler.lookups.osvClient = nil
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
	tmp := t.TempDir()
	policyPath := writeBundle(t, tmp, "block-critical", `vulnerabilities.exists(v, v.advisory.severity.level == severity.critical)`, "critical vuln", "deny")
	engine, err := NewPolicyEngine([]string{policyPath})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}
	handler, err := newGoModuleHandler("https://proxy.golang.org", engine)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	handler.lookups.osvClient = nil
	blockedModule := "github.com/example/vuln"
	handler.lookups.vulnLookup = func(ctx context.Context, module, version string) ([]osv.Vulnerability, error) {
		if module == blockedModule {
			return []osv.Vulnerability{{ID: "OSV-CRIT", Severity: "CRITICAL", Package: module, Version: version}}, nil
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
	tmp := t.TempDir()
	policyPath := writeBundle(t, tmp, "block-gpl", `licenses.exists(l, l == "GPL-3.0")`, "license policy", "deny")
	engine, err := NewPolicyEngine([]string{policyPath})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}
	handler, err := newGoModuleHandler("https://proxy.golang.org", engine)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	handler.lookups.osvClient = nil
	handler.lookups.licenseLookup = func(ctx context.Context, module, version string) ([]string, error) {
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
	handler.lookups.osvClient = nil
	handler.lookups.licenseLookup = func(ctx context.Context, module, version string) ([]string, error) {
		return []string{"GPL-3.0"}, nil
	}

	req := httptest.NewRequest(http.MethodGet, "/github.com/example/mod/@v/v1.0.0.zip", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for license allowlist policy, got %d", rr.Code)
	}
}

func TestGoModuleHandlerIgnoresMissingVersionForVersionPolicies(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "{}")
	}))
	defer upstream.Close()

	tmp := t.TempDir()
	pol := writeBundle(t, tmp, "deny-version", `pkg.name == "github.com/foo/bar" && ["v1.2.3"].exists(v, v.matches(pkg.version))`, "blocked", "deny")

	engine, err := NewPolicyEngine([]string{pol})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}
	handler, err := newGoModuleHandler(upstream.URL, engine)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	handler.lookups.osvClient = nil
	handler.lookups.licenseLookup = nil

	// list (no version) should pass
	{
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/github.com/foo/bar/@v/list", nil)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 for list without version, got %d", rr.Code)
		}
	}
	// non-IOC version should pass
	{
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/github.com/foo/bar/@v/v1.0.0.zip", nil)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 for non-IOC version, got %d", rr.Code)
		}
	}
	// IOC version should be denied
	{
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/github.com/foo/bar/@v/v1.2.3.zip", nil)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for IOC version, got %d", rr.Code)
		}
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
	var paths []string
	paths = append(paths, writeBundle(t, tmp, "deny_blocked", `request.module.contains("blocked")`, "blocked module", "deny"))
	paths = append(paths, writeBundle(t, tmp, "warn_unstable", `request.version.startsWith("v0.")`, "experimental version", "warn"))

	engine, err := NewPolicyEngine(paths)
	if err != nil {
		t.Fatalf("NewPolicyEngine() error = %v", err)
	}
	handler, err := newGoModuleHandler(upstream.URL, engine)
	if err != nil {
		t.Fatalf("newGoModuleHandler() error = %v", err)
	}
	handler.lookups.osvClient = nil
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

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := upstreamHits
			path := fmt.Sprintf("/%s/@v/%s%s", test.module, test.version, test.fileType)
			resp, err := http.Get(ts.URL + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			resp.Body.Close()
			if resp.StatusCode != test.wantStatus {
				t.Fatalf("status = %d want %d", resp.StatusCode, test.wantStatus)
			}
			hitDelta := upstreamHits - before
			if test.wantHit && hitDelta != 1 {
				t.Fatalf("expected upstream hit, got delta %d", hitDelta)
			}
			if !test.wantHit && hitDelta != 0 {
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
	tmp := t.TempDir()
	var policyPaths []string
	policyPaths = append(policyPaths, writeBundle(t, tmp, "warn-un", `request.version.startsWith("v0.")`, "unstable", "warn"))
	policyPaths = append(policyPaths, writeBundle(t, tmp, "deny-specific", fmt.Sprintf(`request.module == "%s"`, denyModule), "blocked by policy", "deny"))

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

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			caseDir := filepath.Join(tmp, strings.ReplaceAll(test.name, " ", "_"))
			if err := os.MkdirAll(caseDir, 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			gopath := filepath.Join(caseDir, "gopath")
			if err := os.MkdirAll(gopath, 0o755); err != nil {
				t.Fatalf("mkdir gopath: %v", err)
			}
			gomodcache := filepath.Join(gopath, "pkg", "mod")
			env := []string{
				"GO111MODULE=on",
				"GOSUMDB=off",
				"GOFLAGS=-modcacherw",
				fmt.Sprintf("GOPROXY=%s", ts.URL),
				fmt.Sprintf("GOPATH=%s", gopath),
				fmt.Sprintf("GOMODCACHE=%s", gomodcache),
			}

			if _, err := runGoCommand(ctx, caseDir, env, "mod", "init", "example.com/testproxy"); err != nil {
				t.Fatalf("go mod init: %v", err)
			}
			_, err := runGoCommand(ctx, caseDir, env, "mod", "download", fmt.Sprintf("%s@%s", test.module, test.version))
			if test.wantErr {
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
