package cmd

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/temporalio/deputy/internal/policy"
)

// TestPolicyExamplesListUsesCanonicalCategories derives the expected listing
// from policy.ExampleCategories, so every canonical category (current and
// future) must appear with its registered description, and the legacy
// category names must stay absent.
func TestPolicyExamplesListUsesCanonicalCategories(t *testing.T) {
	var out bytes.Buffer
	if err := listPolicyEntrypoints(&out); err != nil {
		t.Fatalf("listPolicyEntrypoints returned error: %v", err)
	}
	text := out.String()

	// Sanity floor: 12 canonical categories today.
	if len(policy.ExampleCategories) < 12 {
		t.Fatalf("policy.ExampleCategories has %d categories, want at least 12", len(policy.ExampleCategories))
	}
	for _, cat := range policy.ExampleCategories {
		if want := fmt.Sprintf("%s - %s", cat.Name, cat.Description); !strings.Contains(text, want) {
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
