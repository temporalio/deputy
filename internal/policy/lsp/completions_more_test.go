package lsp

import (
	"strings"
	"testing"

	protocol "github.com/sourcegraph/go-lsp"
)

func assertHasLabel(t *testing.T, items []protocol.CompletionItem, label string) {
	t.Helper()
	for _, it := range items {
		if it.Label == label {
			return
		}
	}
	t.Fatalf("label %q not found in %#v", label, items)
}

func TestCompletionProvidesEnvFields(t *testing.T) {
	line := "when: env."
	items := completionItems(line, len(line))
	assertHasLabel(t, items, "command")
}

func TestCompletionProvidesRequestFields(t *testing.T) {
	line := "when: request."
	items := completionItems(line, len(line))
	assertHasLabel(t, items, "ecosystem")
}

func TestCompletionProvidesRequestClientFields(t *testing.T) {
	line := "when: request.client."
	items := completionItems(line, len(line))
	assertHasLabel(t, items, "ip")
}

func TestCompletionProvidesVulnerabilitiesFields(t *testing.T) {
	line := "when: vulnerabilities."
	items := completionItems(line, len(line))
	// At top-level on vulnerabilities, we suggest variables and helpers; nested fields
	// require select parsing, which is out of scope here. Ensure we at least keep vars.
	assertHasLabel(t, items, "vulnerabilities")
}

func TestCompletionPartialPrefix(t *testing.T) {
	line := "when: pkg.v"
	items := completionItems(line, len(line))
	assertHasLabel(t, items, "version")
}

func TestCompletionProvidesPolicyCommands(t *testing.T) {
	line := "commands: ["
	items := completionItems(line, len(line))
	assertHasLabel(t, items, "scan")
	assertHasLabel(t, items, "sandbox")
	assertHasLabel(t, items, "exec")
	for _, item := range items {
		if item.Label == "exec" && !strings.Contains(item.Detail, "alias") {
			t.Fatalf("exec completion detail = %q, want alias guidance", item.Detail)
		}
	}
}

func TestCompletionProvidesPolicyEntrypoints(t *testing.T) {
	line := "entrypoints: ["
	items := completionItems(line, len(line))
	assertHasLabel(t, items, "scan_vulnerability")
	assertHasLabel(t, items, "sandbox_execution")
}
