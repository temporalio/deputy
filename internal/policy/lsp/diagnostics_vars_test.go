package lsp

import (
	"testing"

	protocol "github.com/sourcegraph/go-lsp"
)

// Ensure variables declared under vars: are accepted in CEL compilation.
func TestDiagnosticsVarsAreVisible(t *testing.T) {
	text := `
policies:
  - name: allow-sans-copyleft
    vars:
      forbidden:
        - SSPL-1.0
        - AGPL-3.0-only
    rules:
      - action: deny
        when: pkg.?licenses.orValue([]).exists(l, l in forbidden)
        reason: package carries a forbidden license
`
	engine := newDiagnosticEngine()
	diag, err := engine.analyze(protocol.DocumentURI("file:///vars.yaml"), text)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	for _, d := range diag {
		if d.Code == "undeclared" {
			t.Fatalf("expected no undeclared diagnostics, got %+v", diag)
		}
	}

	// Negative control: the same policy referencing a genuinely undeclared
	// variable MUST produce an "undeclared" diagnostic. This proves the
	// analyzer actually reached CEL compilation above; without it the test
	// would pass vacuously if analysis never compiled the expression.
	badText := `
policies:
  - name: allow-sans-copyleft
    vars:
      forbidden:
        - SSPL-1.0
        - AGPL-3.0-only
    rules:
      - action: deny
        when: pkg.?licenses.orValue([]).exists(l, l in fobidden)
        reason: package carries a forbidden license
`
	badDiag, err := engine.analyze(protocol.DocumentURI("file:///vars-bad.yaml"), badText)
	if err != nil {
		t.Fatalf("analyze (negative control): %v", err)
	}
	foundUndeclared := false
	for _, d := range badDiag {
		if d.Code == "undeclared" {
			foundUndeclared = true
		}
	}
	if !foundUndeclared {
		t.Fatalf("expected undeclared diagnostic for misspelled var, got %+v", badDiag)
	}
}
