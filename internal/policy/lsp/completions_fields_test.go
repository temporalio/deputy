package lsp

import (
	"testing"
)

func TestCompletionProvidesPkgFields(t *testing.T) {
	line := "        when: pkg."
	items := completionItems(line, len(line))
	found := false
	for _, it := range items {
		if it.Label == "version" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected pkg field 'version' in completions, got %v", items)
	}
}
