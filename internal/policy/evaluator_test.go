package policy

import (
	"testing"
)

func TestEvaluateSimplePolicy(t *testing.T) {
	const src = `
(sbom.?component.?licenses[?0].orValue("UNKNOWN") in ["GPL-3.0-only"]
  ? [{"action": "deny", "reason": "bad"}]
  : [{"action": "allow"}])`

	input := map[string]any{
		"sbom": map[string]any{
			"component": map[string]any{
				"licenses": []any{"GPL-3.0-only"},
			},
		},
	}
	val, err := Evaluate(t.Context(), src, input)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	res, ok := val.([]any)
	if !ok {
		t.Fatalf("expected []any result, got %T", val)
	}
	if len(res) != 1 {
		t.Fatalf("expected one action, got %d", len(res))
	}
	action, ok := res[0].(map[string]any)
	if !ok {
		t.Fatalf("expected map action, got %T", res[0])
	}
	if action["action"] != "deny" {
		t.Fatalf("expected deny action, got %v", action["action"])
	}
}

func TestCelExtensions(t *testing.T) {
	t.Run("lists slice and repeat", func(t *testing.T) {
		src := `["a","b","c","d"].slice(1,3).reverse().join(",")`
		val, err := Evaluate(t.Context(), src, nil)
		if err != nil {
			t.Fatalf("Evaluate lists: %v", err)
		}
		if s, ok := val.(string); !ok || s != "c,b" {
			t.Fatalf("unexpected value %v", val)
		}
	})

	t.Run("sets contains dedup", func(t *testing.T) {
		src := `sets.contains(["a","b","c"], ["b","c"]) && sets.equivalent(["a","a","b","c"], ["c","b","a"])`
		val, err := Evaluate(t.Context(), src, nil)
		if err != nil {
			t.Fatalf("Evaluate sets: %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Fatalf("expected true, got %v", val)
		}
	})

	t.Run("regex partial match", func(t *testing.T) {
		src := `regex.extractAll("foo123bar456", "\\d+").size() == 2 && regex.extract("foo123", "foo(\\d+)").orValue("") == "123"`
		val, err := Evaluate(t.Context(), src, nil)
		if err != nil {
			t.Fatalf("Evaluate regex: %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Fatalf("expected true, got %v", val)
		}
	})
}

func TestEvaluatePkgHelper(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]any
		expected string // expected pkg.name
	}{
		{
			name: "component package name",
			input: map[string]any{
				"component": map[string]any{"package": "comp-pkg"},
				"request":   map[string]any{"package": "req-pkg"},
			},
			expected: "comp-pkg",
		},
		{
			name: "request package name fallback",
			input: map[string]any{
				"request": map[string]any{"package": "req-pkg"},
			},
			expected: "req-pkg",
		},
		{
			name: "module name fallback",
			input: map[string]any{
				"component": map[string]any{"module": "mod-name"},
			},
			expected: "mod-name",
		},
		{
			name: "generic name fallback",
			input: map[string]any{
				"component": map[string]any{"name": "gen-name"},
			},
			expected: "gen-name",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// We evaluate a simple expression that returns pkg.name
			src := `pkg.name`
			val, err := Evaluate(t.Context(), src, test.input)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if s, ok := val.(string); !ok || s != test.expected {
				t.Errorf("expected pkg.name = %q, got %v", test.expected, val)
			}
		})
	}
}

func TestPkgHelperDefaults(t *testing.T) {
	// Test that pkg fields have sensible defaults when not provided,
	// allowing policies to use them directly without ?.orValue() boilerplate.
	t.Run("licenses defaults to empty list", func(t *testing.T) {
		input := map[string]any{
			"component": map[string]any{"name": "test-pkg"},
		}
		// This should work without ?.orValue() because licenses defaults to []
		src := `pkg.licenses.size() == 0`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected pkg.licenses to be empty list, got %v", val)
		}
	})

	t.Run("licenses exists works without orValue", func(t *testing.T) {
		input := map[string]any{
			"component": map[string]any{"name": "test-pkg"},
		}
		// This should work without ?.orValue()
		src := `!pkg.licenses.exists(l, l == "GPL-3.0")`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected pkg.licenses.exists to work on empty list")
		}
	})

	t.Run("version defaults to empty string", func(t *testing.T) {
		input := map[string]any{
			"component": map[string]any{"name": "test-pkg"},
		}
		src := `pkg.version == ""`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected pkg.version to default to empty string")
		}
	})

	t.Run("ecosystem defaults to empty string", func(t *testing.T) {
		input := map[string]any{
			"component": map[string]any{"name": "test-pkg"},
		}
		src := `pkg.ecosystem == ""`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected pkg.ecosystem to default to empty string")
		}
	})

	t.Run("actual values override defaults", func(t *testing.T) {
		input := map[string]any{
			"component": map[string]any{
				"name":      "test-pkg",
				"version":   "1.2.3",
				"ecosystem": "npm",
				"licenses":  []any{"MIT", "Apache-2.0"},
			},
		}
		src := `pkg.version == "1.2.3" && pkg.ecosystem == "npm" && pkg.licenses.size() == 2`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected actual values to override defaults")
		}
	})

	t.Run("string methods work on default version", func(t *testing.T) {
		input := map[string]any{
			"component": map[string]any{"name": "test-pkg"},
		}
		// String methods should work on empty string default
		src := `!pkg.version.startsWith("v") && !pkg.version.matches(".*alpha.*")`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected string methods to work on default empty version")
		}
	})

	t.Run("pkg always exists with defaults even without component/request", func(t *testing.T) {
		// When there's no component or request, pkg should still exist with all defaults
		input := map[string]any{
			"env": map[string]any{"command": "scan"},
		}
		src := `pkg.name == "" && pkg.version == "" && pkg.ecosystem == "" && pkg.licenses.size() == 0`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected pkg to exist with all defaults when no component/request present")
		}
	})

	t.Run("name defaults to empty string", func(t *testing.T) {
		// Even with component that has no name, pkg.name should be empty string
		input := map[string]any{
			"component": map[string]any{"licenses": []any{"MIT"}},
		}
		src := `pkg.name == ""`
		val, err := Evaluate(t.Context(), src, input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Errorf("expected pkg.name to default to empty string")
		}
	})
}
