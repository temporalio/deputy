package scanning

import (
	"context"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/analysis/alpine"
)

// distroUpdateChecker reports OS source packages behind their distribution
// branch. It is an interface so tests can substitute a recorded mirror.
type distroUpdateChecker interface {
	Check(ctx context.Context, pkgs []*dependencyv1.Package) ([]*vulnerabilityv1.DistroUpdate, []string)
}

// distroChecker is the checker scans use when CheckDistroUpdates is set.
var distroChecker distroUpdateChecker = &alpine.Checker{}

// withDistroUpdates runs the distribution-branch comparison and records its
// result on the coverage report. Updates go to coverage rather than findings
// because they say the advisory answer for a package may be incomplete, not
// that a vulnerability was confirmed, so they never change vulnerability
// totals or the clean verdict. Index read failures become warnings.
func withDistroUpdates(ctx context.Context, checker distroUpdateChecker, pkgs []*dependencyv1.Package, cov *vulnerabilityv1.ScanCoverage, warnings []string) (*vulnerabilityv1.ScanCoverage, []string) {
	updates, checkWarnings := checker.Check(ctx, pkgs)
	if len(updates) > 0 {
		if cov == nil {
			cov = &vulnerabilityv1.ScanCoverage{}
		}
		cov.DistroUpdates = updates
	}
	return cov, append(warnings, checkWarnings...)
}
