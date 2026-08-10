package lsp

import (
	"slices"
	"testing"

	protocol "github.com/sourcegraph/go-lsp"
	"github.com/temporalio/deputy/internal/policy"
)

// TestCompletionVocabulariesComeFromTheValidator pins the editor's closed-set
// suggestions to the vocabularies validation enforces. The action list is
// derived from the deputy.policy.v1.ActionType descriptor, so a hand-kept copy
// here would let a new proto action lint clean while the editor never offered
// it, which is exactly the cross-surface drift the descriptor is meant to
// prevent.
func TestCompletionVocabulariesComeFromTheValidator(t *testing.T) {
	cases := []struct {
		name string
		line string
		want []string
	}{
		{
			name: "actions",
			line: "action: ",
			want: policy.ActionTypes(),
		},
		{
			name: "actions inside a rule item",
			line: "  - action: ",
			want: policy.ActionTypes(),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			items := completionItems(tc.line, len(tc.line))
			labels := make([]string, 0, len(items))
			for _, item := range items {
				labels = append(labels, item.Label)
				if item.Kind != protocol.CIKEnum {
					t.Fatalf("completion %q kind = %v, want enum", item.Label, item.Kind)
				}
			}
			if !slices.Equal(labels, tc.want) {
				t.Fatalf("completions = %v, want %v", labels, tc.want)
			}
		})
	}
}
