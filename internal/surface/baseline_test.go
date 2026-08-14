package surface

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
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
			t.Error(orphanedPackageFailure(dir))
		}
	}
	for _, dir := range want {
		if !slices.Contains(got, dir) {
			t.Error(staleBaselineFailure(dir))
		}
	}
}

// orphanedPackageFailure is what the ratchet says about a package nothing
// imports. It is a function so the wording can be pinned: this message is the
// only place a contributor learns what to do about the failure, so a message
// that lists recording the package as an option is not a wording problem, it
// disables the check. Following that advice makes the ratchet pass with the
// package still unreachable.
func orphanedPackageFailure(dir string) string {
	return fmt.Sprintf("no package imports %s, and it is not in %s: %s. Do not add it to the baseline; entries there are only ever removed", dir, BaselinePath, baselineRemedy)
}

// staleBaselineFailure is what the ratchet says about an entry that something
// imports now. This is the one direction the baseline is allowed to move, so it
// is the one message that names the regenerating command.
func staleBaselineFailure(dir string) string {
	return fmt.Sprintf("%s is listed in %s but something imports it now: shrink the baseline with `%s`", dir, BaselinePath, baselineCommand)
}

// TestBaselineFailuresOfferOnlyTheAllowedRemedy pins the messages above against
// the invariant the file header states. The ratchet is only as strong as what it
// tells a contributor to do, and it has no way to notice that its own advice
// contradicts it.
func TestBaselineFailuresOfferOnlyTheAllowedRemedy(t *testing.T) {
	const dir = "internal/example"

	orphan := orphanedPackageFailure(dir)
	if strings.Contains(orphan, baselineCommand) {
		t.Errorf("the new-orphan failure names %q, which records the package instead of wiring it up or deleting it:\n\t%s", baselineCommand, orphan)
	}
	if !strings.Contains(orphan, baselineRemedy) {
		t.Errorf("the new-orphan failure does not say to %q, so it reports a problem without a remedy:\n\t%s", baselineRemedy, orphan)
	}

	// Shrinking is the allowed direction, so that message must keep pointing at
	// the command, or the ratchet fails with no way to satisfy it.
	stale := staleBaselineFailure(dir)
	if !strings.Contains(stale, baselineCommand) {
		t.Errorf("the stale-entry failure does not name %q, so a contributor cannot clear it:\n\t%s", baselineCommand, stale)
	}

	// The header is where the invariant is written down; a message that
	// disagreed with it would be the same defect in the other direction.
	if !strings.Contains(baselineHeader, baselineRemedy) {
		t.Errorf("the generated file's header does not state the remedy %q:\n%s", baselineRemedy, baselineHeader)
	}
}
