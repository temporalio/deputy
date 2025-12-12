package lsp

import (
	"slices"
	"testing"

	protocol "github.com/sourcegraph/go-lsp"
)

func TestCompletionProvidesPkgFields(t *testing.T) {
	line := "        when: pkg."
	items := completionItems(line, len(line))
	if !slices.ContainsFunc(items, func(it protocol.CompletionItem) bool { return it.Label == "version" }) {
		t.Fatalf("expected pkg field 'version' in completions, got %v", items)
	}
}
