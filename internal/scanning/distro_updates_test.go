package scanning

import (
	"context"
	"testing"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
)

type stubDistroChecker struct {
	updates  []*vulnerabilityv1.DistroUpdate
	warnings []string
}

func (s stubDistroChecker) Check(context.Context, []*dependencyv1.Package) ([]*vulnerabilityv1.DistroUpdate, []string) {
	return s.updates, s.warnings
}

// TestWithDistroUpdatesStaysOutOfFindings pins where the signal lands: on the
// coverage report and warnings, never as a finding, so vulnerability totals
// and the clean verdict keep meaning "confirmed by an advisory".
func TestWithDistroUpdatesStaysOutOfFindings(t *testing.T) {
	upd := &vulnerabilityv1.DistroUpdate{Ecosystem: "Alpine:v3.24", SourcePackage: "openssl", InstalledVersion: "3.5.8-r0", AvailableVersion: "3.5.9-r0"}
	checker := stubDistroChecker{updates: []*vulnerabilityv1.DistroUpdate{upd}, warnings: []string{"index unreadable"}}

	cov, warnings := withDistroUpdates(t.Context(), checker, nil, nil, []string{"osv warning"})
	if got := cov.GetDistroUpdates(); len(got) != 1 || got[0] != upd {
		t.Fatalf("coverage distro updates = %v, want the checker's update", got)
	}
	if len(warnings) != 2 || warnings[0] != "osv warning" || warnings[1] != "index unreadable" {
		t.Fatalf("warnings = %v, want source warnings then checker warnings", warnings)
	}

	existing := &vulnerabilityv1.ScanCoverage{Covered: []*vulnerabilityv1.CoverageEntry{{Ecosystem: "alpine"}}}
	cov, _ = withDistroUpdates(t.Context(), stubDistroChecker{}, nil, existing, nil)
	if cov != existing || len(cov.GetDistroUpdates()) != 0 || len(cov.GetCovered()) != 1 {
		t.Fatalf("an empty check must leave coverage untouched, got %v", cov)
	}
}
