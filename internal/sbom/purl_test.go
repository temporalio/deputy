package sbomx

import "testing"

func Test_normalizeGolangPURLString_relpath(t *testing.T) {
	got := normalizeGolangPURLString("pkg:golang/./@v1.0.0", "/tmp/notreal")
	// Without a module path available this should remain unchanged
	if got != "pkg:golang/./@v1.0.0" {
		t.Fatalf("unexpected change: %q", got)
	}
}
