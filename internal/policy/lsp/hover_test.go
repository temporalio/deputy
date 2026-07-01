package lsp

import (
	"strings"
	"testing"
)

func TestCelHoverForFunction(t *testing.T) {
	msg := celHover("levenshteinWithin(req.module, req.module, 2)")
	if msg == "" {
		t.Fatalf("expected hover content for levenshteinWithin")
	}
}

func TestHoverForCommandsMentionsExecAlias(t *testing.T) {
	msg := hoverForLine("commands:")
	if !strings.Contains(msg, "exec") || !strings.Contains(msg, "sandbox") {
		t.Fatalf("commands hover = %q, want exec alias guidance for sandbox", msg)
	}
}
