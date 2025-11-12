package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	analysis "github.com/picatz/deputy/internal/analysis"
)

func TestRubyGemsHandlerBlocksVulnerability(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "{}")
	}))
	defer upstream.Close()

	policySource := `//! policy.name = "block-critical"
(vulnerabilities.exists(v, v.Severity == "CRITICAL")
  ? [{"action":"deny","reason":"critical vuln"}]
  : [])`
	tmp := t.TempDir()
	pol := filepath.Join(tmp, "rubygems.cel")
	if err := os.WriteFile(pol, []byte(policySource), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	engine, err := newPolicyEngine([]string{pol})
	if err != nil {
		t.Fatalf("newPolicyEngine: %v", err)
	}
	handler, err := newRubyGemsHandler(upstream.URL, engine)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	handler.osvClient = nil
	handler.vulnLookup = func(ctx context.Context, name, version string) ([]analysis.Vulnerability, error) {
		return []analysis.Vulnerability{{ID: "OSV-crit", Severity: "CRITICAL", Package: name, Version: version}}, nil
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

	policySource := `//! policy.name = "block-license"
(licenses.exists(l, l == "AGPL-3.0")
  ? [{"action":"deny","reason":"license"}]
  : [])`
	tmp := t.TempDir()
	pol := filepath.Join(tmp, "license.cel")
	if err := os.WriteFile(pol, []byte(policySource), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	engine, err := newPolicyEngine([]string{pol})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	handler, err := newRubyGemsHandler(upstream.URL, engine)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	handler.osvClient = nil
	handler.licenseLookup = func(ctx context.Context, name, version string) ([]string, error) {
		return []string{"AGPL-3.0"}, nil
	}
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/downloads/badgem-1.0.0.gem", nil)
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.Code)
	}
}

func TestRubyGemsHandlerEndToEndGemCLI(t *testing.T) {
	if os.Getenv("DEPUTY_PROXY_RUBY_E2E") != "1" {
		t.Skip("set DEPUTY_PROXY_RUBY_E2E=1 to run gem CLI proxy test")
	}
	if _, err := exec.LookPath("gem"); err != nil {
		t.Skip("gem CLI not found")
	}

	policySource := `//! policy.name = "block-rake"
(request.package == "rake"
  ? [{"action":"deny","reason":"blocked package"}]
  : [])`
	tmp := t.TempDir()
	pol := filepath.Join(tmp, "rake-policy.cel")
	if err := os.WriteFile(pol, []byte(policySource), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	engine, err := newPolicyEngine([]string{pol})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	handler, err := newRubyGemsHandler("https://rubygems.org", engine)
	if err != nil {
		t.Fatalf("handler: %v", err)
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
		{"allow_tzinfo", "tzinfo", "2.0.6", false},
		{"deny_rake", "rake", "13.1.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{
				"fetch", fmt.Sprintf("%s:%s", tt.pkg, tt.version),
				"--clear-sources",
				"--source", ts.URL,
			}
			cmd := exec.Command("gem", args...)
			cmd.Env = append(os.Environ(),
				"GEM_HOME="+tmp,
				"GEM_PATH="+tmp,
			)
			output, err := cmd.CombinedOutput()
			if tt.wantErr {
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
