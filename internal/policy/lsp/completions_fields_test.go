package lsp

import (
	"slices"
	"testing"

	protocol "github.com/sourcegraph/go-lsp"
	"github.com/temporalio/deputy/internal/policy"
)

func TestCompletionProvidesPkgFields(t *testing.T) {
	line := "        when: pkg."
	items := completionItems(line, len(line))
	if !slices.ContainsFunc(items, func(it protocol.CompletionItem) bool { return it.Label == "version" }) {
		t.Fatalf("expected pkg field 'version' in completions, got %v", items)
	}
}

// TestSeverityCompletionsMatchRuntimeConstants pins the severity member list
// offered by completions to the runtime constants map: every offered member
// must be a key of policy.SeverityConstants() and vice versa, so the LSP can
// never teach identifiers (e.g. severity.CRITICAL) that fail to evaluate.
func TestSeverityCompletionsMatchRuntimeConstants(t *testing.T) {
	got := celFieldCompletions("severity")
	want := policy.SeverityConstantNames()
	if !slices.Equal(got, want) {
		t.Fatalf("severity completions = %v, want runtime constant names %v", got, want)
	}

	wantSet := policy.SeverityConstants()
	for _, name := range got {
		if _, ok := wantSet[name]; !ok {
			t.Errorf("completion offers severity.%s, which is not a runtime constant", name)
		}
	}
}
