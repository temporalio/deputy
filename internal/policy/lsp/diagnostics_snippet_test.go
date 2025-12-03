package lsp

import "testing"

func TestSnippetUsesParsedColumn(t *testing.T) {
	expr := "pkg.?licenses.orValue([]).exists(l, l in forbiddn)"
	// col 42 should point inside "forbiddn"
	s := snippetFromCelError(expr, 1, 42, "forbiddn")
	if s.code == "" {
		t.Fatalf("expected snippet code")
	}
	if s.caret == "" || len(s.caret) != 41+1 {
		t.Fatalf("caret length mismatch, got %q", s.caret)
	}
	// caret should align with the start of the hint
	if s.caret[len(s.caret)-1] != '^' {
		t.Fatalf("caret missing")
	}
}
