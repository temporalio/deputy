package policy

import (
	"testing"
)

func TestEngineAdvisoryDowngradesDeny(t *testing.T) {
	src := Source{
		Name:     "advisory",
		Body:     `true ? [{"action":"deny","reason":"block it"}] : []`,
		Metadata: Metadata{Name: "adv", Mode: ModeAdvisory},
	}
	eng, err := NewEngine([]Source{src})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	actions, err := eng.EvaluateAll(t.Context(), nil, "proxy", "")
	if err != nil {
		t.Fatalf("EvaluateAll: %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
	if actions[0].Type != "warn" {
		t.Fatalf("expected warn, got %s", actions[0].Type)
	}
	if actions[0].Status != nil {
		t.Fatalf("expected status to be nil after downgrade, got %v", *actions[0].Status)
	}
	if actions[0].Reason == "" {
		t.Fatalf("expected reason to be preserved")
	}
}

func TestStructuredPolicyModeAdvisory(t *testing.T) {
	yaml := `policies:
  - name: adv-mode
    mode: advisory
    rules:
      - action: deny
        when: true
        reason: nope
`
	sources, ok, err := tryParseStructuredBundle([]byte(yaml), "inline")
	if err != nil || !ok {
		t.Fatalf("parse structured: %v ok=%v", err, ok)
	}
	eng, err := NewEngine(sources)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	acts, err := eng.EvaluateAll(t.Context(), nil, "scan", "scan_report")
	if err != nil {
		t.Fatalf("EvaluateAll: %v", err)
	}
	if len(acts) != 1 || acts[0].Type != "warn" {
		t.Fatalf("expected warn, got %+v", acts)
	}
}
