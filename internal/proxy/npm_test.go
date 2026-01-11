package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/picatz/deputy/internal/analysis/osv"
)

func writeNPMBundle(t *testing.T, dir, name, when, reason, action string) string {
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

func TestNPMHandlerBlocksVulnerability(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "{}")
	}))
	defer upstream.Close()

	tmp := t.TempDir()
	path := writeNPMBundle(t, tmp, "deny-critical", `vulnerabilities.exists(v, v.advisory.severity.level == severity.critical)`, "critical vuln", "deny")
	engine, err := NewPolicyEngine([]string{path})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}
	handler, err := newNPMHandler(upstream.URL, engine)
	if err != nil {
		t.Fatalf("newNPMHandler: %v", err)
	}
	handler.lookups.osvClient = nil
	handler.lookups.vulnLookup = func(ctx context.Context, pkg, version string) ([]osv.Vulnerability, error) {
		return []osv.Vulnerability{{ID: "OSV-crit", Severity: "CRITICAL", Package: pkg, Version: version}}, nil
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

	tmp := t.TempDir()
	pol := writeNPMBundle(t, tmp, "deny-license", `licenses.exists(l, l == "GPL-3.0")`, "license", "deny")
	engine, err := NewPolicyEngine([]string{pol})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	handler, err := newNPMHandler(upstream.URL, engine)
	if err != nil {
		t.Fatalf("newNPMHandler: %v", err)
	}
	handler.lookups.osvClient = nil
	handler.lookups.licenseLookup = func(ctx context.Context, pkg, version string) ([]string, error) {
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
	handler.lookups.osvClient = nil
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
	if receivedAuth != "Bearer secret" {
		t.Fatalf("unexpected auth %q", receivedAuth)
	}
	if contentType != "application/json" {
		t.Fatalf("unexpected content type %q", contentType)
	}
	if npmCommand != "audit" {
		t.Fatalf("unexpected npm command %q", npmCommand)
	}
	if receivedBody != body {
		t.Fatalf("unexpected body %q", receivedBody)
	}
}

func TestNPMHandlerEndToEndPolicy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "{}")
	}))
	defer upstream.Close()

	tmp := t.TempDir()
	pol := writeNPMBundle(t, tmp, "deny-blocked", `request.package.contains("blocked")`, "blocked package", "deny")

	engine, err := NewPolicyEngine([]string{pol})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}
	handler, err := newNPMHandler(upstream.URL, engine)
	if err != nil {
		t.Fatalf("newNPMHandler: %v", err)
	}
	handler.lookups.osvClient = nil
	handler.lookups.licenseLookup = func(ctx context.Context, pkg, version string) ([]string, error) {
		return nil, nil
	}

	req := httptest.NewRequest(http.MethodGet, "/blockedpkg/-/blockedpkg-1.0.0.tgz", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 from policy, got %d", rr.Code)
	}
}

func TestNPMHandlerIgnoresMissingVersionForVersionPolicies(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "{}")
	}))
	defer upstream.Close()

	tmp := t.TempDir()
	// Mirrors the IOC-style pattern that previously matched when version was empty.
	pol := writeNPMBundle(t, tmp, "deny-react-ioc", `pkg.name == "react" && ["18.3.1"].exists(v, v.matches(pkg.version))`, "ioc hit", "deny")

	engine, err := NewPolicyEngine([]string{pol})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}
	handler, err := newNPMHandler(upstream.URL, engine)
	if err != nil {
		t.Fatalf("newNPMHandler: %v", err)
	}
	handler.lookups.osvClient = nil
	handler.lookups.licenseLookup = nil

	// Metadata (no version) should not be denied just because version is empty.
	{
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/react", nil)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 for metadata request, got %d", rr.Code)
		}
	}

	// Non-IOC version should pass.
	{
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/react/-/react-19.0.0.tgz", nil)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 for non-IOC download, got %d", rr.Code)
		}
	}

	// IOC version should still be denied.
	{
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/react/-/react-18.3.1.tgz", nil)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for IOC download, got %d", rr.Code)
		}
	}
}
