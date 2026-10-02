package docsgen

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/temporalio/deputy/internal/ecosystem"
	"github.com/temporalio/deputy/internal/policy"
)

// TestPolicyInputsDocIsGenerated pins the committed policy entrypoint
// reference to its sources: the policy binding registry and the proto
// descriptor comments. When it fails, the registry or a proto comment changed
// without regenerating the docs; run `go generate ./internal/docsgen/...`.
func TestPolicyInputsDocIsGenerated(t *testing.T) {
	sections := []struct {
		name string
		want string
	}{
		{name: PolicyEntrypointsSection, want: PolicyEntrypointsMarkdown()},
		{name: CanonicalEcosystemsSection, want: CanonicalEcosystemsMarkdown()},
	}

	path := filepath.Join("..", "..", filepath.FromSlash(PolicyInputsDocPath))
	for _, section := range sections {
		t.Run(section.name, func(t *testing.T) {
			got, err := Section(path, section.name)
			if err != nil {
				t.Fatalf("read generated section: %v", err)
			}
			if got != section.want {
				t.Fatalf("%s is stale; run `go generate ./internal/docsgen/...` to regenerate the %s section", PolicyInputsDocPath, section.name)
			}
		})
	}
}

// TestCanonicalEcosystemsMarkdownCoversTheVocabulary guards the ecosystem
// table: every canonical token appears with its display name, so the docs
// cannot fall behind the registry.
func TestCanonicalEcosystemsMarkdownCoversTheVocabulary(t *testing.T) {
	out := CanonicalEcosystemsMarkdown()
	for _, token := range ecosystem.CanonicalEcosystems() {
		row := "| `" + token + "` | " + ecosystem.Display(ecosystem.Ecosystem(token)) + " |"
		if !strings.Contains(out, row) {
			t.Errorf("missing row %q in:\n%s", row, out)
		}
	}
}

// TestPolicyEntrypointsMarkdownCoversEveryEntrypoint guards the renderer
// itself: every registered entrypoint must appear, and proto-derived field
// tables must carry descriptions from proto comments.
func TestPolicyEntrypointsMarkdownCoversEveryEntrypoint(t *testing.T) {
	out := PolicyEntrypointsMarkdown()

	for _, heading := range []string{"## Entrypoint reference", "## Variable types"} {
		if !strings.Contains(out, heading) {
			t.Fatalf("missing %q heading", heading)
		}
	}

	// Every registered entrypoint must render its own heading. Deriving from
	// policy.AllEntrypoints means a new entrypoint the renderer skips fails
	// here instead of silently missing from the reference.
	// Sanity floor: 37 canonical entrypoints today.
	if len(policy.AllEntrypoints) < 37 {
		t.Fatalf("policy.AllEntrypoints has %d entrypoints, want at least 37", len(policy.AllEntrypoints))
	}
	for _, ep := range policy.AllEntrypoints {
		if heading := fmt.Sprintf("#### `%s`", ep); !strings.Contains(out, heading) {
			t.Errorf("missing %s entrypoint heading", ep)
		}
	}

	// A proto-comment-derived cell.
	if !strings.Contains(out, "### `vulnerabilityv1.Finding`") {
		t.Fatal("missing vulnerabilityv1.Finding variable type table")
	}
}
