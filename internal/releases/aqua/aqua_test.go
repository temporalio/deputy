package aqua

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// registryServer serves canned registry.yaml recipes by path and counts hits.
func registryServer(t *testing.T, files map[string]string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	mux := http.NewServeMux()
	for path, body := range files {
		mux.HandleFunc("/"+path, func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			_, _ = w.Write([]byte(body))
		})
	}
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, &hits
}

func TestLookupGitHubReleaseWithPrefix(t *testing.T) {
	server, _ := registryServer(t, map[string]string{
		"acme/tool/registry.yaml": `
packages:
  - type: github_release
    repo_owner: acme
    repo_name: tool
    version_prefix: cli-
    version_filter: 'Version startsWith "cli-"'
`,
	})
	c := NewClient(WithBaseURL(server.URL), WithHTTPClient(server.Client()))

	pkg, err := c.Lookup(t.Context(), "acme/tool")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	owner, repo, ok := pkg.GitHubRepo()
	if !ok || owner != "acme" || repo != "tool" {
		t.Errorf("GitHubRepo = %q/%q ok=%v, want acme/tool true", owner, repo, ok)
	}
	if pkg.Type != "github_release" {
		t.Errorf("Type = %q", pkg.Type)
	}
	if pkg.VersionPrefix != "cli-" {
		t.Errorf("VersionPrefix = %q, want cli-", pkg.VersionPrefix)
	}
	if pkg.VersionFilter == "" {
		t.Error("VersionFilter not captured")
	}
}

func TestLookupHTTPWithRepoIsListable(t *testing.T) {
	// type: http but with repo_owner/repo_name (like hashicorp/terraform): aqua
	// downloads via http yet lists versions from the GitHub repo.
	server, _ := registryServer(t, map[string]string{
		"hashicorp/terraform/registry.yaml": `
packages:
  - type: http
    repo_owner: hashicorp
    repo_name: terraform
    url: https://releases.hashicorp.com/terraform/{{.Version}}/x.zip
`,
	})
	c := NewClient(WithBaseURL(server.URL), WithHTTPClient(server.Client()))

	pkg, err := c.Lookup(t.Context(), "hashicorp/terraform")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if owner, repo, ok := pkg.GitHubRepo(); !ok || owner != "hashicorp" || repo != "terraform" {
		t.Errorf("GitHubRepo = %q/%q ok=%v, want hashicorp/terraform true", owner, repo, ok)
	}
}

func TestLookupHTTPWithoutRepoNotListable(t *testing.T) {
	// type: http with no repo (like 1password/cli): no enumerable version source.
	server, _ := registryServer(t, map[string]string{
		"1password/cli/registry.yaml": `
packages:
  - type: http
    name: 1password/cli
    url: https://cache.agilebits.com/dist/op_{{.Version}}.zip
`,
	})
	c := NewClient(WithBaseURL(server.URL), WithHTTPClient(server.Client()))

	pkg, err := c.Lookup(t.Context(), "1password/cli")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if _, _, ok := pkg.GitHubRepo(); ok {
		t.Error("GitHubRepo ok=true, want false for repo-less http package")
	}
}

func TestLookupCaches(t *testing.T) {
	server, hits := registryServer(t, map[string]string{
		"acme/tool/registry.yaml": "packages:\n  - type: github_release\n    repo_owner: acme\n    repo_name: tool\n",
	})
	c := NewClient(WithBaseURL(server.URL), WithHTTPClient(server.Client()))

	for range 3 {
		if _, err := c.Lookup(t.Context(), "acme/tool"); err != nil {
			t.Fatalf("Lookup: %v", err)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("server hits = %d, want 1 (cached)", got)
	}
}

func TestLookupNotFound(t *testing.T) {
	server, _ := registryServer(t, nil) // mux 404s everything
	c := NewClient(WithBaseURL(server.URL), WithHTTPClient(server.Client()))

	_, err := c.Lookup(t.Context(), "missing/tool")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestLookupRejectsBadNames(t *testing.T) {
	c := NewClient()
	for _, name := range []string{"", "single", "a/b/c", "../etc/passwd", "owner/re:po", `o\r`} {
		if _, err := c.Lookup(t.Context(), name); !errors.Is(err, ErrNotFound) {
			t.Errorf("Lookup(%q) err = %v, want ErrNotFound (no network call)", name, err)
		}
	}
}

func TestLookupMalformedYAML(t *testing.T) {
	server, _ := registryServer(t, map[string]string{
		"acme/bad/registry.yaml": "packages: [ this is not valid",
	})
	c := NewClient(WithBaseURL(server.URL), WithHTTPClient(server.Client()))

	if _, err := c.Lookup(t.Context(), "acme/bad"); err == nil {
		t.Error("Lookup returned nil error for malformed YAML")
	}
}
