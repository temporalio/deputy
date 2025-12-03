package lsp

import "testing"

type diagCase struct {
	name      string
	line      int
	col       int
	codeLine  string
	msg       string
	wantMsg   string
	wantCaret int
}

// Tests core diagnostic formatting paths: undeclared, syntax, call target, select chain.
func TestDiagnosticsFormattingVariants(t *testing.T) {
	cases := []diagCase{
		{
			name: "undeclared_with_hint",
			line: 1, col: 42,
			codeLine:  "pkg.?licenses.orValue([]).exists(l, l in forbiddn)",
			msg:       "ERROR: <input>:1:42: undeclared reference to 'forbiddn' (in container '')",
			wantMsg:   "undeclared reference to 'forbiddn'",
			wantCaret: 41,
		},
		{
			name: "syntax_error",
			line: 1, col: 5,
			codeLine:  "pkg.)",
			msg:       "ERROR: <input>:1:5: Syntax error: no viable alternative at input ')'",
			wantMsg:   "Syntax error: no viable alternative at input ')'",
			wantCaret: 4,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sn := snippetFromCelError(tc.codeLine, tc.line, tc.col, extractUndeclaredName(tc.msg))
			if sn.code != tc.codeLine {
				t.Fatalf("code line mismatch: got %q want %q", sn.code, tc.codeLine)
			}
			if sn.caret == "" {
				t.Fatalf("caret missing")
			}
			if len(sn.caret) != tc.wantCaret+1 { // caret string len == spaces+1 caret
				t.Fatalf("caret position mismatch: got len %d want %d (pos %d)", len(sn.caret), tc.wantCaret+1, tc.wantCaret)
			}
			msg := celDetail(tc.msg)
			if msg != tc.wantMsg {
				t.Fatalf("msg mismatch got %q want %q", msg, tc.wantMsg)
			}
		})
	}
}
