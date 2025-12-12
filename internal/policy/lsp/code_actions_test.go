package lsp

import (
	"slices"
	"testing"

	protocol "github.com/sourcegraph/go-lsp"
)

func TestBuildCodeActionsMissingReason(t *testing.T) {
	params := protocol.CodeActionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "file:///x"},
		Context: protocol.CodeActionContext{
			Diagnostics: []protocol.Diagnostic{{
				Code:  "missing-reason",
				Range: protocol.Range{},
			}},
		},
	}
	cmds := buildCodeActions(params, "policies:\n  - name: x\n    rules:\n      - action: deny\n        when: true\n")
	if len(cmds) == 0 {
		t.Fatalf("expected code action command")
	}
	if !slices.ContainsFunc(cmds, func(c any) bool {
		ca, ok := c.(CodeAction)
		return ok && ca.Edit != nil && len(ca.Diagnostics) == 1
	}) {
		t.Fatalf("expected addReason code action with edit, got %+v", cmds)
	}
}

func TestUndeclaredReplacementPrefersRequestChain(t *testing.T) {
	params := protocol.CodeActionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "file:///x"},
		Context: protocol.CodeActionContext{
			Diagnostics: []protocol.Diagnostic{{
				Code:    "undeclared",
				Range:   protocol.Range{Start: protocol.Position{Line: 4, Character: 15}, End: protocol.Position{Line: 4, Character: 28}},
				Message: "CEL: ERROR: <input>:1:1: undeclared reference to 'requestx' (in container '')",
			}},
		},
	}
	doc := "policies:\n  - name: p\n    rules:\n      - action: deny\n        when: requestx.client == true\n"
	cmds := buildCodeActions(params, doc)
	if !slices.ContainsFunc(cmds, func(c any) bool {
		ca, ok := c.(CodeAction)
		if !ok || ca.Edit == nil || len(ca.Edit.Changes) == 0 {
			return false
		}
		for _, edits := range ca.Edit.Changes {
			for _, e := range edits {
				if e.NewText == "request.client" {
					return true
				}
			}
		}
		return false
	}) {
		t.Fatalf("expected replacement to prefer request.client, got %+v", cmds)
	}
}
