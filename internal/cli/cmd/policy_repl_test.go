package cmd

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestPolicyREPLCommands(t *testing.T) {
	script := strings.Join([]string{
		":set ecosystem=go",
		":show",
		"request.ecosystem == 'go'",
		":example",
		"request.package.startsWith('@acme/')",
		":exit",
		"",
	}, "\n")
	in := strings.NewReader(script)
	var out bytes.Buffer
	if err := runPolicyREPL(context.Background(), in, &out); err != nil {
		t.Fatalf("runPolicyREPL error: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "set request.ecosystem = go") {
		t.Fatalf("missing set confirmation: %s", text)
	}
	if !strings.Contains(text, "Result: true") {
		t.Fatalf("expected evaluation result, got: %s", text)
	}
	if !strings.Contains(text, "loaded example request data") {
		t.Fatalf("expected example command output")
	}
}
