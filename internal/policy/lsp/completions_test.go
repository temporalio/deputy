package lsp

import (
	"slices"
	"testing"

	protocol "github.com/sourcegraph/go-lsp"
)

func TestCELCompletionIncludesHelpers(t *testing.T) {
	items := celCompletion("when: ", 6)
	hasVar := slices.ContainsFunc(items, func(it protocol.CompletionItem) bool { return it.Label == "request" })
	hasFn := slices.ContainsFunc(items, func(it protocol.CompletionItem) bool { return it.Label == "levenshteinWithin" })
	if !hasVar || !hasFn {
		t.Fatalf("expected request var and levenshteinWithin fn in completions; got %v", items)
	}
}

// TestModeCompletionsOfferEveryCanonicalMode pins the modes editors offer. The
// completion derives them from the policy package rather than repeating a list
// here, so a new execution mode reaches editors without a second edit.
func TestModeCompletionsOfferEveryCanonicalMode(t *testing.T) {
	line := "    mode: "
	items := completionItems(line, len(line))
	got := make([]string, 0, len(items))
	for _, it := range items {
		got = append(got, it.Label)
	}
	want := []string{"enforce", "advisory"}
	if !slices.Equal(want, got) {
		t.Errorf("completionItems(%q) labels = %v, want %v", line, got, want)
	}
}

func TestCELCompletionFieldAfterEnvDot(t *testing.T) {
	line := "when: env."
	items := celCompletion(line, len(line))
	if !slices.ContainsFunc(items, func(it protocol.CompletionItem) bool { return it.Label == "command" }) {
		t.Fatalf("expected env.command completion, got %v", items)
	}
}
