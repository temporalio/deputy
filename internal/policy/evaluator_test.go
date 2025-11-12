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
