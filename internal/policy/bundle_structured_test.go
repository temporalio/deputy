package policy

import (
	"strings"
	"testing"
)

func TestOrderedVarsExpandInAuthorOrder(t *testing.T) {
	p := structuredPolicy{
		Name: "ordered-vars",
		Vars: orderedVars{
			{Name: "a", Expr: "1"},
			{Name: "b", Expr: "a + 1"},
			{Name: "c", Expr: "b + 1"},
		},
		Rules: []structuredRule{
			{Action: "deny", When: "c == 3"},
		},
	}
	body, err := p.toCELSource()
	if err != nil {
		t.Fatalf("toCELSource: %v", err)
	}
	// Verify ordering cues are present in the expanded CEL.
	if !(strings.Contains(body, "map(a") && strings.Contains(body, "map(b") && strings.Contains(body, "map(c")) {
		t.Fatalf("expanded body missing vars: %s", body)
	}
	if err := Compile(body, nil); err != nil {
		t.Fatalf("compiled source invalid: %v", err)
	}
}

func TestOrderedVarsRejectDuplicateNames(t *testing.T) {
	p := structuredPolicy{
		Name: "dupe-vars",
		Vars: orderedVars{
			{Name: "a", Expr: "1"},
			{Name: "a", Expr: "2"},
		},
		Rules: []structuredRule{{Action: "deny", When: "true"}},
	}
	if _, err := p.toCELSource(); err == nil {
		t.Fatalf("expected error for duplicate var names, got nil")
	}
}
