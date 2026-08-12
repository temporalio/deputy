package lsp

import (
	"slices"
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
        reason: package carries a copyleft license
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
        reason: package carries a copyleft license
`
	// Golden expectation: this is verbatim what a policy author sees in their
	// editor when they misspell a declared var, so all of it is contract, the
	// "(did you mean 'x'?)" wording, the echoed source line, and the caret
	// column that lands under the typo. The caret alignment in particular is
	// behavior nothing else protects, and it breaks silently when the snippet
	// builder is edited.
	//
	// Yes, this is brittle on purpose. Do NOT loosen it back to a code-only or
	// substring check: that is exactly the assertion this test replaced, and it
	// let the useful part of the message go unprotected. If the wording or the
	// snippet layout legitimately changes, read the diff, confirm the new
	// message is what you want a user to read, and update the string.
	//
	// Written as concatenated lines with explicit \n so the caret stays visibly
	// under the misspelled token here in the source, and so no trailing
	// whitespace hides at the end of a line where an editor could strip it.
	const wantMessage = "undeclared reference to 'fobidden' (did you mean 'forbidden'?)\n" +
		"  pkg.?licenses.orValue([]).exists(l, l in fobidden)\n" +
		"                                           ^"

	badDiag, err := engine.analyze(protocol.DocumentURI("file:///vars-bad.yaml"), badText)
	if err != nil {
		t.Fatalf("analyze (negative control): %v", err)
	}
	idx := slices.IndexFunc(badDiag, func(d protocol.Diagnostic) bool { return d.Code == "undeclared" })
	if idx < 0 {
		t.Fatalf("expected undeclared diagnostic for misspelled var, got %+v", badDiag)
	}
	if got := badDiag[idx].Message; got != wantMessage {
		t.Errorf("undeclared diagnostic message mismatch\nwant:\n%s\ngot:\n%s\nwant %q\ngot  %q", wantMessage, got, wantMessage, got)
	}
}
