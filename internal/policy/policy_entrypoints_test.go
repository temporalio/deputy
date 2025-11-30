package policy

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// findExample returns the path to a named example policy in policy/examples.
func findExample(t *testing.T, name string) string {
	t.Helper()
	rel := filepath.Join("..", "..", "policy", "examples", name)
	return filepath.Clean(rel)
}

func loadAllowlist(t *testing.T) []Source {
	t.Helper()
	path := findExample(t, "license-allowlist.yaml")
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources(%s): %v", path, err)
	}
	return sources
}

func TestLicenseAllowlistEntrypoints(t *testing.T) {
	sources := loadAllowlist(t)

	t.Run("sbom component denies copyleft", func(t *testing.T) {
		payload := map[string]any{
			"component": map[string]any{
				"licenses": []any{"GPL-3.0"},
			},
			"env": map[string]any{"command": "sbom"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		if len(actions) != 1 || actions[0].Type != "deny" {
			t.Fatalf("expected one deny action, got %+v", actions)
		}
	})

	t.Run("proxy request denies copyleft", func(t *testing.T) {
		payload := map[string]any{
			"request": map[string]any{
				"licenses": []any{"AGPL-3.0-only"},
			},
			"env": map[string]any{"command": "proxy"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		if len(actions) != 1 || actions[0].Type != "deny" {
			t.Fatalf("expected one deny action, got %+v", actions)
		}
	})

	t.Run("sbom warn on missing licenses", func(t *testing.T) {
		payload := map[string]any{
			"component": map[string]any{},
			"env":       map[string]any{"command": "sbom"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		if len(actions) != 1 || actions[0].Type != "warn" {
			t.Fatalf("expected one warn action, got %+v", actions)
		}
	})

	t.Run("scan payload does not error", func(t *testing.T) {
		payload := map[string]any{
			"env": map[string]any{"command": "scan"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		// The policy may emit a warn for missing licenses; just ensure no deny.
		for _, act := range actions {
			if act.Type == "deny" {
				t.Fatalf("did not expect deny for scan payload: %+v", act)
			}
		}
	})
}

func loadAllowlistComposed(t *testing.T) []Source {
	t.Helper()
	path := findExample(t, "license-allowlist-composed.yaml")
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources(%s): %v", path, err)
	}
	return sources
}

func TestLicenseAllowlistComposedEntrypoints(t *testing.T) {
	sources := loadAllowlistComposed(t)

	t.Run("vars compose normalized and license_list", func(t *testing.T) {
		payload := map[string]any{
			"component": map[string]any{
				"licenses": []any{"AgPl-3.0-only", "mit"},
			},
			"env": map[string]any{"command": "sbom"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		if len(actions) != 1 || actions[0].Type != "deny" {
			t.Fatalf("expected one deny action, got %+v", actions)
		}
		if !strings.Contains(strings.ToLower(actions[0].Reason), "forbidden") {
			t.Fatalf("expected reason to include forbidden licenses, got %q", actions[0].Reason)
		}
	})

	t.Run("sbom component denies copyleft", func(t *testing.T) {
		payload := map[string]any{
			"component": map[string]any{
				"licenses": []any{"GPL-3.0"},
			},
			"env": map[string]any{"command": "sbom"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		if len(actions) != 1 || actions[0].Type != "deny" {
			t.Fatalf("expected one deny action, got %+v", actions)
		}
	})

	t.Run("proxy request denies copyleft", func(t *testing.T) {
		payload := map[string]any{
			"request": map[string]any{
				"licenses": []any{"AGPL-3.0-ONLY"},
			},
			"env": map[string]any{"command": "proxy"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		if len(actions) != 1 || actions[0].Type != "deny" {
			t.Fatalf("expected one deny action, got %+v", actions)
		}
	})

	t.Run("sbom warn on missing licenses", func(t *testing.T) {
		payload := map[string]any{
			"component": map[string]any{},
			"env":       map[string]any{"command": "sbom"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		if len(actions) != 1 || actions[0].Type != "warn" {
			t.Fatalf("expected one warn action, got %+v", actions)
		}
	})
}

func TestLicenseAllowlistHappySadPaths(t *testing.T) {
	sources := loadAllowlist(t)

	t.Run("happy path allows permissive license", func(t *testing.T) {
		payload := map[string]any{
			"component": map[string]any{"licenses": []any{"MIT"}},
			"env":       map[string]any{"command": "sbom"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if strings.EqualFold(a.Type, "deny") {
				t.Fatalf("did not expect deny: %+v", a)
			}
		}
	})

	t.Run("sad path denies copyleft", func(t *testing.T) {
		payload := map[string]any{
			"request": map[string]any{"licenses": []any{"GPL-3.0-only"}},
			"env":     map[string]any{"command": "proxy"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		foundDeny := false
		for _, a := range actions {
			if a.Type == "deny" {
				foundDeny = true
			}
		}
		if !foundDeny {
			t.Fatalf("expected deny, got %+v", actions)
		}
	})
}

func TestDenyAwsSdkV1Policy(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "deny-aws-sdk-v1.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}

	t.Run("deny v1", func(t *testing.T) {
		payload := map[string]any{
			"pkg": map[string]any{
				"ecosystem": "go",
				"name":      "github.com/aws/aws-sdk-go",
				"version":   "v1.44.0",
			},
			"env": map[string]any{"command": "proxy"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		deny := false
		for _, a := range actions {
			if a.Type == "deny" {
				deny = true
			}
		}
		if !deny {
			t.Fatalf("expected deny for v1, got %+v", actions)
		}
	})

	t.Run("allow v2", func(t *testing.T) {
		payload := map[string]any{
			"pkg": map[string]any{
				"ecosystem": "go",
				"name":      "github.com/aws/aws-sdk-go-v2",
				"version":   "v1.0.0",
			},
			"env": map[string]any{"command": "proxy"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for v2: %+v", actions)
			}
		}
	})
}

func TestGoModRegistryAllowlist(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "gomod-registry-allowlist.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}

	t.Run("deny unapproved org", func(t *testing.T) {
		payload := map[string]any{
			"pkg": map[string]any{
				"ecosystem": "go",
				"name":      "github.com/badorg/module",
				"version":   "v1.0.0",
			},
			"env": map[string]any{"command": "proxy"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		deny := false
		for _, a := range actions {
			if a.Type == "deny" {
				deny = true
			}
		}
		if !deny {
			t.Fatalf("expected deny for unapproved org, got %+v", actions)
		}
	})

	t.Run("allow approved org", func(t *testing.T) {
		payload := map[string]any{
			"pkg": map[string]any{
				"ecosystem": "go",
				"name":      "github.com/org-a/module",
				"version":   "v1.2.3",
			},
			"env": map[string]any{"command": "proxy"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for approved org: %+v", actions)
			}
		}
	})
}

func TestGoPseudoVersionDenyPolicy(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "go-pseudo-version-deny.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}

	t.Run("deny pseudo with 0 qualifier", func(t *testing.T) {
		payload := map[string]any{
			"pkg": map[string]any{
				"ecosystem": "go",
				"name":      "github.com/example/module",
				"version":   "v1.2.3-0.20240528123456-deadbeefcafe",
			},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		deny := false
		for _, a := range actions {
			if a.Type == "deny" {
				deny = true
			}
		}
		if !deny {
			t.Fatalf("expected deny for pseudo-version, got %+v", actions)
		}
	})

	t.Run("deny bare pseudo version", func(t *testing.T) {
		payload := map[string]any{
			"pkg": map[string]any{
				"ecosystem": "go",
				"name":      "github.com/example/module",
				"version":   "v0.0.0-20170915030341-ba0f2cc1c8ab",
			},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		deny := false
		for _, a := range actions {
			if a.Type == "deny" {
				deny = true
			}
		}
		if !deny {
			t.Fatalf("expected deny for bare pseudo-version, got %+v", actions)
		}
	})

	t.Run("allow tagged release", func(t *testing.T) {
		payload := map[string]any{
			"pkg": map[string]any{
				"ecosystem": "go",
				"name":      "github.com/example/module",
				"version":   "v1.2.3",
			},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for tagged release: %+v", actions)
			}
		}
	})
}

func TestPrereleaseGuardPolicy(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "prerelease-guard.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}

	t.Run("deny prerelease by default", func(t *testing.T) {
		payload := map[string]any{
			"pkg": map[string]any{
				"version": "v1.2.3-beta.1",
			},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		found := false
		for _, a := range actions {
			if a.Type == "deny" {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected deny for prerelease version, got %+v", actions)
		}
	})

	t.Run("allow stable release", func(t *testing.T) {
		payload := map[string]any{
			"pkg": map[string]any{
				"version": "1.2.3",
			},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for stable release: %+v", actions)
			}
		}
	})
}
