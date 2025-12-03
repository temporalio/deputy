package lsp

import (
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
	found := false
	for _, d := range diag {
		if d.Severity == protocol.Warning && strings.Contains(d.Message, "invalid entrypoint") {
			found = true
			break
		}
	}
	if !found {
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
	foundUndeclared := false
	for _, d := range diag {
		if d.Code == "undeclared" {
			foundUndeclared = true
			if got := d.Range.End.Character - d.Range.Start.Character; got < 3 {
				t.Fatalf("expected widened range for identifier, got length %d", got)
			}
		}
	}
	if !foundUndeclared {
		t.Fatalf("expected undeclared code, got %+v", diag)
	}
}
