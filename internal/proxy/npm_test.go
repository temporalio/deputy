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
)

func TestNPMHandlerBlocksVulnerability(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "{}")
	}))
	defer upstream.Close()

	policySource := `//! policy.name = "deny-critical"
(vulnerabilities.exists(v, v.Severity == "CRITICAL")
  ? [{"action":"deny","reason":"critical vuln"}]
  : [])`
	tmp := t.TempDir()
	path := filepath.Join(tmp, "npm.cel")
	if err := os.WriteFile(path, []byte(policySource), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	engine, err := NewPolicyEngine([]string{path})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}
	handler, err := newNPMHandler(upstream.URL, engine)
	if err != nil {
		t.Fatalf("newNPMHandler: %v", err)
	}
	handler.osvClient = nil
	handler.vulnLookup = func(ctx context.Context, pkg, version string) ([]analysis.Vulnerability, error) {
		return []analysis.Vulnerability{{ID: "OSV-crit", Severity: "CRITICAL", Package: pkg, Version: version}}, nil
	}
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/@scope/pkg/-/pkg-1.0.0.tgz", nil)
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.Code)
	}
}

func TestNPMHandlerBlocksLicense(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "{}")
	}))
	defer upstream.Close()

	policySource := `//! policy.name = "deny-license"
(licenses.exists(l, l == "GPL-3.0")
  ? [{"action":"deny","reason":"license"}]
  : [])`
	tmp := t.TempDir()
	pol := filepath.Join(tmp, "license.cel")
	if err := os.WriteFile(pol, []byte(policySource), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	engine, err := NewPolicyEngine([]string{pol})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	handler, err := newNPMHandler(upstream.URL, engine)
	if err != nil {
		t.Fatalf("newNPMHandler: %v", err)
	}
	handler.osvClient = nil
	handler.licenseLookup = func(ctx context.Context, pkg, version string) ([]string, error) {
		return []string{"GPL-3.0"}, nil
	}
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/pkg/-/pkg-1.0.0.tgz", nil)
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.Code)
	}
}

func TestNPMHandlerForwardsRequestBodyAndHeaders(t *testing.T) {
	const body = `{"name":"test","version":"1.0.0"}`
	var (
		receivedMethod string
		receivedBody   string
		receivedAuth   string
		receivedPath   string
		receivedQuery  string
		contentType    string
		npmCommand     string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		receivedMethod = r.Method
		receivedBody = string(data)
		receivedAuth = r.Header.Get("Authorization")
		receivedPath = r.URL.Path
		receivedQuery = r.URL.RawQuery
		contentType = r.Header.Get("Content-Type")
		npmCommand = r.Header.Get("Npm-Command")
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer upstream.Close()

	handler, err := newNPMHandler(upstream.URL, nil)
	if err != nil {
		t.Fatalf("newNPMHandler: %v", err)
	}
	handler.osvClient = nil
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/-/npm/v1/security/audits/quick?foo=bar", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Npm-Command", "audit")
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", resp.Code)
	}
	if got := strings.TrimSpace(resp.Body.String()); got != `{"ok":true}` {
		t.Fatalf("unexpected response body %q", got)
	}
	if receivedMethod != http.MethodPost {
		t.Fatalf("expected POST upstream, got %s", receivedMethod)
	}
	if receivedPath != "/-/npm/v1/security/audits/quick" {
		t.Fatalf("unexpected path %q", receivedPath)
	}
	if receivedQuery != "foo=bar" {
		t.Fatalf("unexpected query %q", receivedQuery)
	}
	if receivedBody != body {
		t.Fatalf("body mismatch: got %q", receivedBody)
	}
	if receivedAuth != "Bearer secret" {
		t.Fatalf("authorization header dropped: %q", receivedAuth)
	}
	if contentType != "application/json" {
		t.Fatalf("content-type header dropped: %q", contentType)
	}
	if npmCommand != "audit" {
		t.Fatalf("custom header dropped: %q", npmCommand)
	}
}

func TestParseNPMPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		path      string
		pkg       string
		version   string
		operation string
	}{
		{"root", "/", "", "", "metadata"},
		{"simple_pkg", "/left-pad", "left-pad", "", "metadata"},
		{"scoped_pkg", "/@scope/pkg", "@scope/pkg", "", "metadata"},
		{"dist_tags", "/-/package/pkg/dist-tags", "pkg", "", "dist-tags"},
		{"download", "/lodash/-/lodash-4.17.21.tgz", "lodash", "4.17.21", "download"},
		{"scoped_download", "/@babel/core/-/core-7.0.0.tgz", "@babel/core", "7.0.0", "download"},
		{"service", "/-/npm/v1/security/advisories/bulk", "", "", "service"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg, version, op := parseNPMPath(tt.path)
			if pkg != tt.pkg || version != tt.version || op != tt.operation {
				t.Fatalf("parseNPMPath(%q) = (%q,%q,%q)", tt.path, pkg, version, op)
			}
		})
	}
}

func TestNPMHandlerEndToEndNPM(t *testing.T) {
	if os.Getenv("DEPUTY_PROXY_NPM_E2E") != "1" {
		t.Skip("set DEPUTY_PROXY_NPM_E2E=1 to run npm proxy test")
	}
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm not found")
	}

	policySource := `//! policy.name = "block-leftpad"
(request.package == "left-pad"
  ? [{"action":"deny","reason":"blocked package"}]
  : [])`
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "npm-policy.cel")
	if err := os.WriteFile(policyPath, []byte(policySource), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	engine, err := NewPolicyEngine([]string{policyPath})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}
	handler, err := newNPMHandler("https://registry.npmjs.org", engine)
	if err != nil {
		t.Fatalf("newNPMHandler: %v", err)
	}
	handler.osvClient = nil
	ts := httptest.NewServer(handler)
	defer ts.Close()

	tests := []struct {
		name    string
		pkg     string
		version string
		wantErr bool
	}{
		{"allow_lodash", "lodash", "4.17.21", false},
		{"deny_leftpad", "left-pad", "1.3.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := filepath.Join(tmp, tt.name)
			if err := os.MkdirAll(dest, 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			args := []string{
				"pack", fmt.Sprintf("%s@%s", tt.pkg, tt.version),
				"--pack-destination", dest,
				"--registry", ts.URL,
			}
			cmd := exec.Command("npm", args...)
			cmd.Env = append(os.Environ(),
				"NPM_CONFIG_STRICT_SSL=false",
			)
			output, err := cmd.CombinedOutput()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected failure\n%s", output)
				}
				if !strings.Contains(string(output), "blocked package") {
					t.Fatalf("expected policy error in output: %s", output)
				}
			} else if err != nil {
				t.Fatalf("npm pack failed: %v\n%s", err, output)
			}
		})
	}
}
