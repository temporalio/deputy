package surface

import (
	"path/filepath"
	"slices"
	"testing"
)

// TestUnreachablePackageBaseline is the ratchet: it audits this repository and
// compares the packages nothing imports against the committed baseline. A new
// entry fails, because a package nothing reaches is either unfinished wiring or
// code to delete, and neither should land quietly. An entry that is no longer
// unreachable fails too, so the baseline shrinks as the surface does instead of
// preserving a stale claim.
//
// This is the check that could not exist before the audit did: every package
// listed here has its own tests, so it is used, by its own test, and an
// unused-symbol analyzer is right not to flag it.
func TestUnreachablePackageBaseline(t *testing.T) {
	if testing.Short() {
		t.Skip("audits the whole module; skipped under -short")
	}

	root := filepath.Join("..", "..")
	report, err := Analyze(t.Context(), root)
	if err != nil {
		t.Fatalf("Analyze(%s) error: %v", root, err)
	}

	path := filepath.Join(root, filepath.FromSlash(BaselinePath))
	want, err := ReadBaseline(path)
	if err != nil {
		t.Fatalf("ReadBaseline: %v", err)
	}
	got := report.UnreachableDirs()

	for _, dir := range got {
		if !slices.Contains(want, dir) {
			t.Errorf("no package imports %s, and it is not in %s: wire it up, delete it, or record it with `go run ./internal/surface/cmd -baseline`", dir, BaselinePath)
		}
	}
	for _, dir := range want {
		if !slices.Contains(got, dir) {
			t.Errorf("%s is listed in %s but something imports it now: shrink the baseline with `go run ./internal/surface/cmd -baseline`", dir, BaselinePath)
		}
	}
}
