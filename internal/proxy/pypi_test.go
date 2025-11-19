package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	analysis "github.com/picatz/deputy/internal/analysis"
)

func TestParsePyPIPath(t *testing.T) {
	tests := []struct {
		path     string
		pkg      string
		version  string
		op       string
		filename string
	}{
		{"/simple/numpy/", "numpy", "", "simple", ""},
		{"/project/numpy/1.24/", "numpy", "1.24", "project", ""},
		{"/packages/source/n/numpy/numpy-1.24.0.tar.gz", "numpy", "1.24.0", "download", "numpy-1.24.0.tar.gz"},
		{"/packages/ab/cd/google-auth-2.34.0.tar.gz", "google-auth", "2.34.0", "download", "google-auth-2.34.0.tar.gz"},
	}
	for _, tt := range tests {
		pkg, version, filename, op := parsePyPIPath(tt.path)
		if pkg != tt.pkg || version != tt.version || op != tt.op || filename != tt.filename {
			t.Fatalf("parsePyPIPath(%q) -> pkg=%q version=%q op=%q filename=%q", tt.path, pkg, version, op, filename)
		}
	}
}

func TestPyPIHandlerPolicyBlocksVuln(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	policySource := `//! policy.name = "block-critical"
(vulnerabilities.exists(v, v.Severity == "CRITICAL")
  ? [{"action":"deny","reason":"critical vuln"}]
  : [])`
	tmp := t.TempDir()
	path := filepath.Join(tmp, "pypi.cel")
	if err := os.WriteFile(path, []byte(policySource), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	engine, err := newPolicyEngine([]string{path})
	if err != nil {
		t.Fatalf("newPolicyEngine: %v", err)
	}
	handler, err := newPyPIHandler(upstream.URL, engine)
	if err != nil {
		t.Fatalf("newPyPIHandler: %v", err)
	}
	handler.osvClient = nil
	blockedPackage := "vulnerablepkg"
	handler.vulnLookup = func(ctx context.Context, pkg, version string) ([]analysis.Vulnerability, error) {
		if pkg == blockedPackage {
			return []analysis.Vulnerability{{ID: "OSV-123", Severity: "CRITICAL", Package: pkg, Version: version}}, nil
		}
		return nil, nil
	}
	req := httptest.NewRequest(http.MethodGet, "/packages/source/v/vulnerablepkg/vulnerablepkg-1.0.0.tar.gz", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestPyPIHandlerLicensePolicy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	policySource := `//! policy.name = "license-block"
(licenses.exists(l, l == "AGPL-3.0")
  ? [{"action":"deny","reason":"license"}]
  : [])`
	tmp := t.TempDir()
	polPath := filepath.Join(tmp, "license.cel")
	if err := os.WriteFile(polPath, []byte(policySource), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	engine, err := newPolicyEngine([]string{polPath})
	if err != nil {
		t.Fatalf("newPolicyEngine: %v", err)
	}
	handler, err := newPyPIHandler(upstream.URL, engine)
	if err != nil {
		t.Fatalf("newPyPIHandler: %v", err)
	}
	handler.osvClient = nil
	handler.licenseLookup = func(ctx context.Context, pkg, version string) ([]string, error) {
		if strings.Contains(pkg, "blocked") {
			return []string{"AGPL-3.0"}, nil
		}
		return nil, nil
	}
	path := "/packages/source/b/blockedpkg/blockedpkg-0.1.0.tar.gz"
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.Code)
	}
}

func TestPyPIHandlerForwardsRequestBodyAndHeaders(t *testing.T) {
	const body = `{"query":"numpy"}`
	var (
		gotMethod   string
		gotBody     string
		gotAuth     string
		gotPath     string
		gotQuery    string
		contentType string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		gotMethod = r.Method
		gotBody = string(data)
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		contentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	handler, err := newPyPIHandler(upstream.URL, nil)
	if err != nil {
		t.Fatalf("newPyPIHandler: %v", err)
	}
	handler.osvClient = nil
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/simple/search?foo=bar", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", resp.Code)
	}
	if got := strings.TrimSpace(resp.Body.String()); got != "ok" {
		t.Fatalf("unexpected response body %q", got)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("expected POST upstream, got %s", gotMethod)
	}
	if gotBody != body {
		t.Fatalf("body mismatch: %q", gotBody)
	}
	if gotAuth != "Bearer secret" {
		t.Fatalf("authorization header missing: %q", gotAuth)
	}
	if contentType != "application/json" {
		t.Fatalf("content-type missing: %q", contentType)
	}
	if gotPath != "/simple/search" {
		t.Fatalf("path mismatch: %q", gotPath)
	}
	if gotQuery != "foo=bar" {
		t.Fatalf("query mismatch: %q", gotQuery)
	}
}

func TestPyPIHandlerEndToEndPip(t *testing.T) {
	if os.Getenv("DEPUTY_PROXY_PYPI_E2E") != "1" {
		t.Skip("set DEPUTY_PROXY_PYPI_E2E=1 to run pip proxy test")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		python, err = exec.LookPath("python")
		if err != nil {
			t.Skip("python interpreter not found")
		}
	}

	policySource := `//! policy.name = "block-pkginfo"
(request.package == "pkginfo"
  ? [{"action":"deny","reason":"blocked package"}]
  : [])`
	tmp := t.TempDir()
	polPath := filepath.Join(tmp, "pip-policy.cel")
	if err := os.WriteFile(polPath, []byte(policySource), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	engine, err := newPolicyEngine([]string{polPath})
	if err != nil {
		t.Fatalf("newPolicyEngine: %v", err)
	}
	handler, err := newPyPIHandler("https://pypi.org", engine)
	if err != nil {
		t.Fatalf("newPyPIHandler: %v", err)
	}
	handler.osvClient = nil
	ts := httptest.NewServer(handler)
	defer ts.Close()

	indexURL := ts.URL + "/simple"
	u, _ := url.Parse(ts.URL)
	host := u.Host

	ctx := context.Background()
	tests := []struct {
		name    string
		pkg     string
		version string
		wantErr bool
	}{
		{"allow_requests", "requests", "2.31.0", false},
		{"deny_pkginfo", "pkginfo", "1.5.0.1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := filepath.Join(tmp, tt.name)
			if err := os.MkdirAll(dest, 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			pkgSpec := fmt.Sprintf("%s==%s", tt.pkg, tt.version)
			args := []string{
				"-m", "pip", "download", pkgSpec,
				"--no-deps",
				"--disable-pip-version-check",
				"-d", dest,
				"--index-url", indexURL,
				"--trusted-host", host,
			}
			cmd := exec.CommandContext(ctx, python, args...)
			cmd.Env = append(os.Environ(),
				"PIP_NO_CACHE_DIR=off",
				"PIP_RETRIES=0",
			)
			output, err := cmd.CombinedOutput()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected failure, output: %s", output)
				}
				if !strings.Contains(string(output), "blocked package") {
					t.Fatalf("expected policy message in output, got %s", output)
				}
			} else if err != nil {
				t.Fatalf("pip download failed: %v\n%s", err, output)
			}
		})
	}
}
