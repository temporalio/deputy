package policy

import (
	"context"
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
	val, err := Evaluate(context.Background(), src, input)
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
	ctx := context.Background()

	t.Run("lists slice and repeat", func(t *testing.T) {
		src := `["a","b","c","d"].slice(1,3).reverse().join(",")`
		val, err := Evaluate(ctx, src, nil)
		if err != nil {
			t.Fatalf("Evaluate lists: %v", err)
		}
		if s, ok := val.(string); !ok || s != "c,b" {
			t.Fatalf("unexpected value %v", val)
		}
	})

	t.Run("sets contains dedup", func(t *testing.T) {
		src := `sets.contains(["a","b","c"], ["b","c"]) && sets.equivalent(["a","a","b","c"], ["c","b","a"])`
		val, err := Evaluate(ctx, src, nil)
		if err != nil {
			t.Fatalf("Evaluate sets: %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Fatalf("expected true, got %v", val)
		}
	})

	t.Run("regex partial match", func(t *testing.T) {
		src := `regex.extractAll("foo123bar456", "\\d+").size() == 2 && regex.extract("foo123", "foo(\\d+)").orValue("") == "123"`
		val, err := Evaluate(ctx, src, nil)
		if err != nil {
			t.Fatalf("Evaluate regex: %v", err)
		}
		if b, ok := val.(bool); !ok || !b {
			t.Fatalf("expected true, got %v", val)
		}
	})
}

func TestEvaluatePkgHelper(t *testing.T) {
	ctx := context.Background()

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
			val, err := Evaluate(ctx, src, test.input)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if s, ok := val.(string); !ok || s != test.expected {
				t.Errorf("expected pkg.name = %q, got %v", test.expected, val)
			}
		})
	}
}
