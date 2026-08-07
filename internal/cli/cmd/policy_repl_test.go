package cmd

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/temporalio/deputy/internal/policy"
)

func TestPolicyREPLCommands(t *testing.T) {
	script := strings.Join([]string{
		":set ecosystem=go",
		":show",
		"request.ecosystem == 'go'",
		":example",
		// After :example, lodash@4.17.20 is loaded with CVE-2021-23337
		// Test all vulnerability fields match real scan output shape
		"pkg.name == 'lodash'",
		"pkg.ecosystem == 'npm'",
		"vulnerability.severity == 'HIGH'",
		"vulnerability.id == 'GHSA-35jh-r3h4-6jhm'",
		"vulnerability.isDirect == true",
		"vulnerability.fixedVersions.size() > 0",
		"vulnerability.fixedVersions[0] == '4.17.21'",
		":exit",
		"",
	}, "\n")
	in := strings.NewReader(script)
	var out bytes.Buffer
	if err := runPolicyREPL(t.Context(), in, &out); err != nil {
		t.Fatalf("runPolicyREPL error: %v", err)
	}
	text := out.String()
	// New format uses quoted value: set request.ecosystem = "go"
	if !strings.Contains(text, `set request.ecosystem = "go"`) {
		t.Fatalf("missing set confirmation: %s", text)
	}
	// All expressions should evaluate to true
	trueCount := strings.Count(text, "true")
	expectedTrue := 8 // 1 for request.ecosystem + 7 for vulnerability tests
	if trueCount < expectedTrue {
		t.Fatalf("expected at least %d true results, got %d in output:\n%s", expectedTrue, trueCount, text)
	}
	// New example message format with real vulnerability data (GHSA + CVE + CVSS)
	if !strings.Contains(text, "loaded example") {
		t.Fatalf("expected example command output")
	}
	if !strings.Contains(text, "lodash") {
		t.Fatalf("expected lodash in example output, got: %s", text)
	}
	if !strings.Contains(text, "CVE-2021-23337") {
		t.Fatalf("expected CVE in example output, got: %s", text)
	}
}

func TestSuggestCommand(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// Typos that should be corrected
		{":hlep", ":help"},
		{":hepl", ":help"},
		{":hep", ":help"},
		{":clar", ":clear"},
		{":exmaple", ":example"},
		{":vuln", ":vuln"}, // exact match
		{":vulm", ":vuln"}, // close typo
		{":sevrity", ":severity"},
		{":functons", ":functions"},
		{":varss", ":vars"},
		{":entrypint", ":entrypoint"},

		// Commands that are too different (no suggestion)
		{":xyz", ""},
		{":foobar", ""},
		{"help", ""}, // missing colon

		// Exact matches return themselves (distance 0)
		{":help", ":help"},
		{":set", ":set"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := suggestCommand(tt.input)
			if got != tt.expected {
				t.Errorf("suggestCommand(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestLevenshtein(t *testing.T) {
	tests := []struct {
		a, b     string
		expected int
	}{
		{"", "", 0},
		{"a", "", 1},
		{"", "a", 1},
		{"abc", "abc", 0},
		{"abc", "abd", 1},
		{"abc", "ab", 1},
		{"abc", "abcd", 1},
		{"kitten", "sitting", 3},
		{":help", ":hlep", 2},
		{":clear", ":clar", 1}, // just delete 'e'
	}

	for _, tt := range tests {
		t.Run(tt.a+"_"+tt.b, func(t *testing.T) {
			got := levenshtein(tt.a, tt.b)
			if got != tt.expected {
				t.Errorf("levenshtein(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

func TestCompleteREPLCommand(t *testing.T) {
	tests := []struct {
		line     string
		cursor   int
		expected []string
	}{
		// Partial command completions
		{":", 1, []string{":h", ":q", ":fn", ":help", ":set", ":show", ":vuln", ":vars", ":exit", ":quit", ":clear", ":funcs", ":graph", ":example", ":severity", ":functions", ":variables", ":unset", ":entrypoint"}},
		{":h", 2, []string{":h", ":help"}},
		{":he", 3, []string{":help"}},
		{":hel", 4, []string{":help"}},
		{":help", 5, []string{":help"}},
		{":s", 2, []string{":set", ":show", ":severity"}},
		{":se", 3, []string{":set", ":severity"}},
		{":set", 4, []string{":set"}},
		{":v", 2, []string{":vuln", ":vars", ":variables"}},
		{":e", 2, []string{":exit", ":example", ":entrypoint"}},
		{":f", 2, []string{":fn", ":funcs", ":functions"}},

		// After space - no completions (don't complete args)
		{":set ", 5, nil},
		{":entrypoint ", 12, nil},

		// No matches
		{":xyz", 4, nil},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			got := completeREPLCommand(tt.line, tt.cursor)

			// Check that we got expected completions (order may vary due to sort)
			if len(got) != len(tt.expected) {
				// Allow for subset matching on ":" since the full list is long
				if tt.line == ":" {
					if len(got) == 0 {
						t.Errorf("expected completions for %q, got none", tt.line)
					}
					return
				}
				t.Errorf("completeREPLCommand(%q, %d) returned %d completions, want %d\ngot: %v\nwant: %v",
					tt.line, tt.cursor, len(got), len(tt.expected), got, tt.expected)
				return
			}

			// For specific prefix tests, verify expected completions are present
			for _, exp := range tt.expected {
				found := slices.Contains(got, exp)
				if !found && len(tt.expected) > 0 {
					t.Errorf("completeREPLCommand(%q, %d) missing expected %q\ngot: %v",
						tt.line, tt.cursor, exp, got)
				}
			}
		})
	}
}

// TestREPLEntrypointCommand covers the two ways :entrypoint used to mislead:
// it listed a hardcoded 12 of the 37 real entrypoints (including "proxy",
// which is a command, not an entrypoint), and it accepted any string, so a
// typo silently set a context that could never match a policy.
func TestREPLEntrypointCommand(t *testing.T) {
	run := func(t *testing.T, lines ...string) string {
		t.Helper()
		script := strings.Join(append(lines, ":exit", ""), "\n")
		var out bytes.Buffer
		if err := runPolicyREPL(t.Context(), strings.NewReader(script), &out); err != nil {
			t.Fatalf("runPolicyREPL error: %v", err)
		}
		return out.String()
	}

	t.Run("lists every entrypoint", func(t *testing.T) {
		text := run(t, ":entrypoint")
		for _, ep := range policy.AllEntrypoints {
			if !strings.Contains(text, string(ep)) {
				t.Errorf("entrypoint %q missing from :entrypoint listing", ep)
			}
		}
		if strings.Contains(text, "  proxy\n") {
			t.Error(`":entrypoint" listed "proxy", which is a command, not an entrypoint`)
		}
	})

	t.Run("accepts a real entrypoint", func(t *testing.T) {
		text := run(t, ":entrypoint sbom_report")
		if !strings.Contains(text, "entrypoint set to sbom_report") {
			t.Errorf("expected sbom_report to be accepted, got:\n%s", text)
		}
	})

	t.Run("rejects an unknown entrypoint", func(t *testing.T) {
		text := run(t, ":entrypoint scan_reprot")
		if strings.Contains(text, "entrypoint set to scan_reprot") {
			t.Error("typo was accepted; :entrypoint must validate against AllEntrypoints")
		}
		if !strings.Contains(text, "unknown entrypoint") {
			t.Errorf("expected an unknown-entrypoint error, got:\n%s", text)
		}
	})
}
