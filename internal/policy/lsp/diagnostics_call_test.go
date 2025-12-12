package lsp

import (
	"slices"
	"testing"

	protocol "github.com/sourcegraph/go-lsp"
)

// Ensures call target errors widen to the function name token.
func TestDiagnosticsCallTargetRange(t *testing.T) {
	text := `
policies:
  - name: bad-call
    rules:
      - action: deny
        when: missingFunc(request)
`
	engine := newDiagnosticEngine()
	diag, err := engine.analyze(protocol.DocumentURI("file:///call.yaml"), text)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if !slices.ContainsFunc(diag, func(d protocol.Diagnostic) bool {
		return d.Code == "undeclared" && d.Range.End.Character-d.Range.Start.Character >= len("missingFunc")
	}) {
		t.Fatalf("expected widened range on missing function, got %+v", diag)
	}
}
