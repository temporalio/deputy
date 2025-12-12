package lsp

import (
	"slices"
	"strings"
	"testing"

	protocol "github.com/sourcegraph/go-lsp"
)

func TestDiagnosticsInvalidEntrypoint(t *testing.T) {
	text := `
policies:
  - name: bad-entry
    entrypoints: ["nope_entry"]
    rules:
      - action: deny
        when: true
`
	engine := newDiagnosticEngine()
	diag, err := engine.analyze(protocol.DocumentURI("file:///test.yaml"), text)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(diag) == 0 {
		t.Fatalf("expected diagnostic for invalid entrypoint")
	}
	if !slices.ContainsFunc(diag, func(d protocol.Diagnostic) bool {
		return d.Severity == protocol.Warning && strings.Contains(d.Message, "invalid entrypoint")
	}) {
		t.Fatalf("expected warning about invalid entrypoint, got %+v", diag)
	}
}

func TestDiagnosticsCEL(t *testing.T) {
	text := `
policies:
  - name: bad-cel
    rules:
      - action: deny
        when: foo == true
`
	engine := newDiagnosticEngine()
	diag, err := engine.analyze(protocol.DocumentURI("file:///test.yaml"), text)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(diag) == 0 {
		t.Fatalf("expected CEL diagnostic")
	}
	if !slices.ContainsFunc(diag, func(d protocol.Diagnostic) bool {
		if d.Code != "undeclared" {
			return false
		}
		return d.Range.End.Character-d.Range.Start.Character >= 3
	}) {
		t.Fatalf("expected undeclared code, got %+v", diag)
	}
}
