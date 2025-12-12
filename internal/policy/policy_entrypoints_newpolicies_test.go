package policy

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
)

func TestCriticalTransitiveSpotlight(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "critical-transitive-spotlight.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}
	payload := map[string]any{
		"vulnerability": map[string]any{
			"severity": "CRITICAL",
			"isDirect": false,
		},
		"env": map[string]any{"command": "scan", "entrypoint": "scan_vulnerability"},
	}
	actions, err := EvaluateAll(context.Background(), sources, payload)
	if err != nil {
		t.Fatalf("EvaluateAll: %v", err)
	}
	if !slices.ContainsFunc(actions, func(a Action) bool { return a.Type == "warn" }) {
		t.Fatalf("expected warn for critical indirect vuln, got %+v", actions)
	}
}

func TestTyposquatLevenshteinGuard(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "policy", "examples", "typosquat-levenshtein-guard.yaml"))
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}
	t.Run("deny known close typo", func(t *testing.T) {
		payload := map[string]any{
			"request": map[string]any{"package": "lodas", "ecosystem": "npm"},
			"env":     map[string]any{"command": "proxy"},
		}
		if actions, err := EvaluateAll(context.Background(), sources, payload); err != nil || len(actions) == 0 || actions[0].Type != "deny" {
			t.Fatalf("expected deny for typosquat, got %+v err=%v", actions, err)
		}
	})

	t.Run("deny another near miss", func(t *testing.T) {
		payload := map[string]any{
			"request": map[string]any{"package": "reqeusts", "ecosystem": "npm"},
			"env":     map[string]any{"command": "proxy"},
		}
		if actions, err := EvaluateAll(context.Background(), sources, payload); err != nil || len(actions) == 0 || actions[0].Type != "deny" {
			t.Fatalf("expected deny for typosquat, got %+v err=%v", actions, err)
		}
	})

	t.Run("allow safe distant name", func(t *testing.T) {
		payload := map[string]any{
			"request": map[string]any{"package": "teamlib", "ecosystem": "npm"},
			"env":     map[string]any{"command": "proxy"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for distant name: %+v", actions)
			}
		}
	})

	t.Run("allow scoped package", func(t *testing.T) {
		payload := map[string]any{
			"request": map[string]any{"package": "@acme/lodas", "ecosystem": "npm"},
			"env":     map[string]any{"command": "proxy"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for scoped package: %+v", actions)
			}
		}
	})

	t.Run("allow numeric suffix", func(t *testing.T) {
		payload := map[string]any{
			"request": map[string]any{"package": "react2", "ecosystem": "npm"},
			"env":     map[string]any{"command": "proxy"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for numeric suffix: %+v", actions)
			}
		}
	})

	t.Run("ignore non-proxy command", func(t *testing.T) {
		payload := map[string]any{
			"request": map[string]any{"package": "lodas", "ecosystem": "npm"},
			"env":     map[string]any{"command": "scan"},
		}
		actions, err := EvaluateAll(context.Background(), sources, payload)
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny outside proxy: %+v", actions)
			}
		}
	})
}
