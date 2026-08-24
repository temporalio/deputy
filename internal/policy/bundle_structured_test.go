package policy

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestOrderedVarsExpandInAuthorOrder(t *testing.T) {
	p := structuredPolicy{
		Name: "ordered-vars",
		Vars: orderedVars{
			{Name: "a", Value: "1", IsString: true},
			{Name: "b", Value: "a + 1", IsString: true},
			{Name: "c", Value: "b + 1", IsString: true},
			{Name: "literalList", Value: []any{"x", "y"}, IsString: false},
			{Name: "literalMap", Value: map[string]any{"k": "v"}, IsString: false},
		},
		Rules: []structuredRule{
			{Action: "deny", When: "c == 3 && literalList.size() == 2 && literalMap.k == \"v\""},
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

func TestLiteralsNestedListsAndMapsEvaluate(t *testing.T) {
	p := structuredPolicy{
		Name: "nested-literals",
		Vars: orderedVars{
			{Name: "listMaps", Value: []any{map[string]any{"k": "v"}}, IsString: false},
			{Name: "listLists", Value: []any{[]any{"a", "b"}, []any{"c"}}, IsString: false},
		},
		Rules: []structuredRule{
			{
				Action: "deny",
				When:   `listMaps[0].k == "v" && listLists.size() == 2 && listLists[0].size() == 2`,
				Reason: "nested literals ok",
			},
		},
	}
	src, err := p.toCELSource()
	if err != nil {
		t.Fatalf("toCELSource: %v", err)
	}
	val, err := Evaluate(t.Context(), src, nil)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	actions, ok := val.([]any)
	if !ok || len(actions) != 1 {
		t.Fatalf("expected one action, got %#v", val)
	}
	act, _ := actions[0].(map[string]any)
	if act["action"] != "deny" {
		t.Fatalf("expected deny action, got %+v", act)
	}
}

func TestOrderedVarsRejectDuplicateNames(t *testing.T) {
	p := structuredPolicy{
		Name: "dupe-vars",
		Vars: orderedVars{
			{Name: "a", Value: "1", IsString: true},
			{Name: "a", Value: "2", IsString: true},
		},
		Rules: []structuredRule{{Action: "deny", When: "true"}},
	}
	if _, err := p.toCELSource(); err == nil {
		t.Fatalf("expected error for duplicate var names, got nil")
	}
}

func TestStructuredPolicyNormalizesCommandAliases(t *testing.T) {
	p := structuredPolicy{
		Name:     "sandbox-command",
		Commands: []string{"exec", "sandbox"},
		Rules:    []structuredRule{{Action: "deny", When: "true"}},
	}
	meta, err := p.metadata()
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	if diff := cmp.Diff([]string{"sandbox"}, meta.Commands); diff != "" {
		t.Errorf("metadata().Commands mismatch (-want +got):\n%s", diff)
	}
}
