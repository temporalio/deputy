package lsp

import "testing"

func TestCelHoverForFunction(t *testing.T) {
	msg := celHover("levenshteinWithin(req.module, req.module, 2)")
	if msg == "" {
		t.Fatalf("expected hover content for levenshteinWithin")
	}
}
