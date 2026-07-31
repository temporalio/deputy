package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestPolicyExamplesListUsesCanonicalCategories(t *testing.T) {
	var out bytes.Buffer
	if err := listPolicyEntrypoints(&out); err != nil {
		t.Fatalf("listPolicyEntrypoints returned error: %v", err)
	}
	text := out.String()
	for _, want := range []string{
		"container_diff - Container image policies",
		"server - API authorization policies",
		"fix - Remediation planning policies",
		"triage - Vulnerability triage policies",
		"sandbox - Sandbox execution control policies",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("policy examples list missing %q in:\n%s", want, text)
		}
	}
	for _, legacy := range []string{
		"container - Container image policies",
		"service - API authorization policies",
	} {
		if strings.Contains(text, legacy) {
			t.Fatalf("policy examples list used legacy category %q in:\n%s", legacy, text)
		}
	}
}
