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
)

func writeRubyBundle(t *testing.T, dir, name, when, reason, action string) string {
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
		t.Fatalf("write bundle: %v", err)
	}
	return path
}

func TestParseRubyGemsPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path      string
		name      string
		version   string
		operation string
	}{
		{path: "/downloads/rails-7.1.0.gem", name: "rails", version: "7.1.0", operation: "download"},
		{path: "/gems/rake-13.2.1.gem", name: "rake", version: "13.2.1", operation: "download"},
		{path: "/api/v1/gems/rack.json", name: "rack", version: "", operation: "api"},
		{path: "/api/v1/versions/rake/latest", name: "", version: "", operation: "api"},
		{path: "/rails", name: "rails", version: "", operation: "metadata"},
	}
	for _, test := range tests {
		name, version, op := parseRubyGemsPath(test.path)
		if name != test.name || version != test.version || op != test.operation {
			t.Fatalf("parseRubyGemsPath(%q) = (%q,%q,%q)", test.path, name, version, op)
		}
	}
}

func TestRubyGemsHandlerBlocksVulnerability(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "{}")
	}))
	defer upstream.Close()

	tmp := t.TempDir()
	pol := writeRubyBundle(t, tmp, "block-critical", `vulnerabilities.exists(v, v.advisory.severity.level == severity.critical)`, "critical vuln", "deny")
	engine, err := NewPolicyEngine([]string{pol})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}
	handler, err := newRubyGemsHandler(upstream.URL, engine)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	handler.lookups.osvClient = nil
	handler.lookups.vulnLookup = func(ctx context.Context, name, version string) ([]osv.Vulnerability, error) {
		return []osv.Vulnerability{{ID: "OSV-crit", Severity: "CRITICAL", Package: name, Version: version}}, nil
	}
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/downloads/rails-7.1.0.gem", nil)
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.Code)
	}
}

func TestRubyGemsHandlerBlocksLicense(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "{}")
	}))
	defer upstream.Close()

	tmp := t.TempDir()
	pol := writeRubyBundle(t, tmp, "block-license", `licenses.exists(l, l == "AGPL-3.0")`, "license", "deny")
	engine, err := NewPolicyEngine([]string{pol})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	handler, err := newRubyGemsHandler(upstream.URL, engine)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	handler.lookups.osvClient = nil
	handler.lookups.licenseLookup = func(ctx context.Context, name, version string) ([]string, error) {
		return []string{"AGPL-3.0"}, nil
	}
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/downloads/badgem-1.0.0.gem", nil)
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.Code)
	}
}

func TestRubyGemsHandlerIgnoresMissingVersionForVersionPolicies(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "{}")
	}))
	defer upstream.Close()

	tmp := t.TempDir()
	pol := writeRubyBundle(t, tmp, "deny-version", `pkg.name == "rails" && ["7.1.0"].exists(v, v.matches(pkg.version))`, "blocked", "deny")
	engine, err := NewPolicyEngine([]string{pol})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	handler, err := newRubyGemsHandler(upstream.URL, engine)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	handler.lookups.osvClient = nil
	handler.lookups.licenseLookup = nil

	// metadata (no version) should pass
	{
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/rails", nil)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 for metadata without version, got %d", rr.Code)
		}
	}
	// non-IOC version should pass
	{
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/rails-6.1.0.gem", nil)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 for non-IOC version, got %d", rr.Code)
		}
	}
	// IOC version should be denied
	{
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/rails-7.1.0.gem", nil)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for IOC version, got %d", rr.Code)
		}
	}
}

func TestRubyGemsHandlerForwardsRequestBodyAndHeaders(t *testing.T) {
	const body = `{"key":"value"}`
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

	handler, err := newRubyGemsHandler(upstream.URL, nil)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	handler.lookups.osvClient = nil
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gems/search.json?q=rack", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", resp.Code)
	}
	if got := strings.TrimSpace(resp.Body.String()); got != "ok" {
		t.Fatalf("unexpected body %q", got)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("expected POST, got %s", gotMethod)
	}
	if gotBody != body {
		t.Fatalf("body mismatch: %q", gotBody)
	}
	if gotAuth != "Bearer secret" {
		t.Fatalf("authorization header missing: %q", gotAuth)
	}
	if contentType != "application/json" {
		t.Fatalf("content type missing: %q", contentType)
	}
	if gotPath != "/api/v1/gems/search.json" {
		t.Fatalf("path mismatch: %q", gotPath)
	}
	if gotQuery != "q=rack" {
		t.Fatalf("query mismatch: %q", gotQuery)
	}
}

func TestRubyGemsHandlerEndToEndGemCLI(t *testing.T) {
	if os.Getenv("DEPUTY_PROXY_RUBY_E2E") != "1" {
		t.Skip("set DEPUTY_PROXY_RUBY_E2E=1 to run gem CLI proxy test")
	}
	if _, err := exec.LookPath("gem"); err != nil {
		t.Skip("gem CLI not found")
	}

	tmp := t.TempDir()
	pol := writeRubyBundle(t, tmp, "block-rake", `request.package == "rake"`, "blocked package", "deny")
	engine, err := NewPolicyEngine([]string{pol})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	handler, err := newRubyGemsHandler("https://rubygems.org", engine)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	handler.lookups.osvClient = nil
	ts := httptest.NewServer(handler)
	defer ts.Close()

	tests := []struct {
		name    string
		pkg     string
		version string
		wantErr bool
	}{
		{"allow_tzinfo", "tzinfo", "2.0.6", false},
		{"deny_rake", "rake", "13.1.0", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := []string{
				"fetch", fmt.Sprintf("%s:%s", test.pkg, test.version),
				"--clear-sources",
				"--source", ts.URL,
			}
			cmd := exec.Command("gem", args...)
			cmd.Env = append(os.Environ(),
				"GEM_HOME="+tmp,
				"GEM_PATH="+tmp,
			)
			output, err := cmd.CombinedOutput()
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected failure\n%s", output)
				}
				if !strings.Contains(string(output), "blocked package") {
					t.Fatalf("expected policy message in output: %s", output)
				}
			} else if err != nil {
				t.Fatalf("gem fetch failed: %v\n%s", err, output)
			}
		})
	}
}
