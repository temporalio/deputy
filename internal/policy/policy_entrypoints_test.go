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
