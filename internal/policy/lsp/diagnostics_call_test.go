package lsp

import (
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
	found := false
	for _, d := range diag {
		if d.Code == "undeclared" && d.Range.End.Character-d.Range.Start.Character >= len("missingFunc") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected widened range on missing function, got %+v", diag)
	}
}
