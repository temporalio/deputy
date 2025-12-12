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

func TestCELCompletionFieldAfterEnvDot(t *testing.T) {
	line := "when: env."
	items := celCompletion(line, len(line))
	if !slices.ContainsFunc(items, func(it protocol.CompletionItem) bool { return it.Label == "command" }) {
		t.Fatalf("expected env.command completion, got %v", items)
	}
}
