package docsgen

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestPolicyInputsDocIsGenerated pins the committed policy entrypoint
// reference to its sources: the policy binding registry and the proto
// descriptor comments. When it fails, the registry or a proto comment changed
// without regenerating the docs; run `go generate ./internal/docsgen/...`.
func TestPolicyInputsDocIsGenerated(t *testing.T) {
	path := filepath.Join("..", "..", filepath.FromSlash(PolicyInputsDocPath))
	got, err := Section(path, PolicyEntrypointsSection)
	if err != nil {
		t.Fatalf("read generated section: %v", err)
	}
	want := PolicyEntrypointsMarkdown()
	if got != want {
		t.Fatalf("%s is stale; run `go generate ./internal/docsgen/...` to regenerate the %s section", PolicyInputsDocPath, PolicyEntrypointsSection)
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
	// A representative registry entrypoint and a proto-comment-derived cell.
	if !strings.Contains(out, "#### `scan_vulnerability`") {
		t.Fatal("missing scan_vulnerability entrypoint")
	}
	if !strings.Contains(out, "### `vulnerabilityv1.Finding`") {
		t.Fatal("missing vulnerabilityv1.Finding variable type table")
	}
}
