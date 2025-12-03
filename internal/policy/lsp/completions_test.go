package lsp

import "testing"

func TestCELCompletionIncludesHelpers(t *testing.T) {
	items := celCompletion("when: ", 6)
	var hasVar, hasFn bool
	for _, it := range items {
		if it.Label == "request" {
			hasVar = true
		}
		if it.Label == "levenshteinWithin" {
			hasFn = true
		}
	}
	if !hasVar || !hasFn {
		t.Fatalf("expected request var and levenshteinWithin fn in completions; got %v", items)
	}
}

func TestCELCompletionFieldAfterEnvDot(t *testing.T) {
	line := "when: env."
	items := celCompletion(line, len(line))
	found := false
	for _, it := range items {
		if it.Label == "command" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected env.command completion, got %v", items)
	}
}
