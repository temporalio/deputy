package sbomx

import (
	"testing"

	"github.com/picatz/deputy/internal/workspace"
)

func Test_normalizeGolangPURLString_relpath(t *testing.T) {
	ws := workspace.NewMemory()
	defer ws.Close()
	got := normalizeGolangPURLString("pkg:golang/./@v1.0.0", ws)
	// Without a module path available this should remain unchanged
	if got != "pkg:golang/./@v1.0.0" {
		t.Fatalf("unexpected change: %q", got)
	}
}
