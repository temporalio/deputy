package fixresolve

import (
	"context"
	"strings"

	"github.com/temporalio/deputy/internal/vulnerability"
	"golang.org/x/mod/semver"
)

// Options configures fix resolution.
type Options struct {
	// Verify enables installability probes against the resolver. When false,
	// resolution is skipped entirely (the caller keeps legacy behavior of
	// trusting the advisory's fixed version), which is the offline escape hatch
	// behind --no-verify-fixes.
	Verify bool
}

// knownMigrations maps a legacy Go module path to successor module paths that a
// fix may have moved to under a rename (which the mechanical foo -> foo/vN rule
// cannot derive). This is the curated half of the equivalence table; the
// mechanical major-version-suffix rule in isSuccessorPath handles the rest.
var knownMigrations = map[string][]string{
	"github.com/docker/docker": {"github.com/moby/moby/v2"},
	"github.com/moby/moby":     {"github.com/moby/moby/v2"},
}

// Annotate resolves and attaches a FixVerdict to each consolidated finding
// in place. Findings outside the Go ecosystem, or all findings when
// opts.Verify is false, are left unannotated so readers fall back to legacy
// behavior.
func Annotate(ctx context.Context, cons []vulnerability.Consolidated, r Resolver, opts Options) {
	if !opts.Verify || r == nil {
		return
	}
	for i := range cons {
		if v := Resolve(ctx, cons[i], r, opts); v != nil {
			cons[i].Fix = v
		}
	}
}

// Resolve computes the remediation verdict for a single consolidated finding.
// It returns nil when resolution does not apply (non-Go ecosystem or
// verification disabled), signaling callers to use the legacy fixed-version
// path.
func Resolve(ctx context.Context, c vulnerability.Consolidated, r Resolver, opts Options) *vulnerability.FixVerdict {
	if !opts.Verify || r == nil || !isGoEcosystem(c.Ecosystem) {
		return nil
	}

	inPlace := vulnerability.FindBestFixedVersion(c.FixedVersions, c.Version)

	// 1. A claimed in-place fix: verify it is installable on the current path.
	if inPlace != "" {
		switch r.ModuleVersionExists(ctx, c.Package, inPlace) {
		case ExistsYes:
			return &vulnerability.FixVerdict{Status: vulnerability.FixStatusInPlace, Version: inPlace}
		case ExistsUnknown:
			// Could not confirm; don't assert it's broken, but don't promise it
			// either. Surface as unverified with the claimed version.
			return &vulnerability.FixVerdict{Status: vulnerability.FixStatusUnverified, Version: inPlace, Claimed: inPlace}
		case ExistsNo:
			// Definitively absent on this path — fall through to migration search.
		}
	}

	// 2. No installable in-place fix. Look for a migration target among the
	// advisory's sibling affected modules.
	if len(c.PackageFixes) > 0 {
		var fallback *vulnerability.FixVerdict
		for _, pf := range c.PackageFixes {
			if pf == nil || pf.Module == "" || strings.EqualFold(pf.Module, c.Package) {
				continue
			}
			if !isSuccessorPath(c.Package, pf.Module) {
				continue
			}
			target := lowestFixed(pf.FixedVersions)
			if target == "" {
				continue
			}
			verdict := &vulnerability.FixVerdict{
				Status:       vulnerability.FixStatusMigration,
				Version:      target,
				TargetModule: pf.Module,
				Claimed:      inPlace,
			}
			switch r.ModuleVersionExists(ctx, pf.Module, target) {
			case ExistsYes:
				return verdict // confirmed migration target
			default:
				// Keep as a fallback: the in-place fix is confirmed gone, so an
				// advisory-sourced migration is still the best guidance even if
				// the target version can't be confirmed right now.
				if fallback == nil {
					fallback = verdict
				}
			}
		}
		if fallback != nil {
			return fallback
		}
	}

	// 3. Nothing installable and no migration target.
	if inPlace != "" {
		// We had a claim but it resolved to absent with no migration path.
		return &vulnerability.FixVerdict{Status: vulnerability.FixStatusUnavailable, Claimed: inPlace}
	}
	return &vulnerability.FixVerdict{Status: vulnerability.FixStatusUnavailable}
}

// isSuccessorPath reports whether candidate is a plausible migration target for
// base: either a curated rename (knownMigrations) or a mechanical Go
// major-version path bump (github.com/foo -> github.com/foo/vN, or
// github.com/foo/vN -> github.com/foo/vM for M > N).
func isSuccessorPath(base, candidate string) bool {
	for _, m := range knownMigrations[base] {
		if strings.EqualFold(candidate, m) {
			return true
		}
	}
	root := stripMajorSuffix(base)
	cand := stripMajorSuffix(candidate)
	if !strings.EqualFold(root, cand) {
		return false
	}
	// Same root path; treat candidate as a successor when its major version is
	// higher than base's.
	return majorOf(candidate) > majorOf(base)
}

// stripMajorSuffix removes a trailing "/vN" (N >= 2) major-version element.
func stripMajorSuffix(modulePath string) string {
	i := strings.LastIndex(modulePath, "/")
	if i < 0 {
		return modulePath
	}
	last := modulePath[i+1:]
	if len(last) >= 2 && last[0] == 'v' && allDigits(last[1:]) {
		return modulePath[:i]
	}
	return modulePath
}

// majorOf returns the numeric major version encoded in a module path's "/vN"
// suffix, or 1 when there is none (Go treats v0/v1 as the unsuffixed path).
func majorOf(modulePath string) int {
	i := strings.LastIndex(modulePath, "/")
	if i < 0 {
		return 1
	}
	last := modulePath[i+1:]
	if len(last) < 2 || last[0] != 'v' || !allDigits(last[1:]) {
		return 1
	}
	n := 0
	for _, d := range last[1:] {
		n = n*10 + int(d-'0')
	}
	return n
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// lowestFixed returns the smallest fixed version from a module's fix list,
// preserving its original string form. Cross-module fix selection can't be
// anchored to the current (different-path) version, so the earliest fix is the
// safest migration floor.
func lowestFixed(versions []string) string {
	best := ""
	bestNorm := ""
	for _, v := range versions {
		nv := v
		if !strings.HasPrefix(nv, "v") {
			nv = "v" + nv
		}
		if !semver.IsValid(nv) {
			continue
		}
		if best == "" || semver.Compare(nv, bestNorm) < 0 {
			best, bestNorm = v, nv
		}
	}
	if best == "" && len(versions) > 0 {
		return versions[0]
	}
	return best
}

func isGoEcosystem(eco string) bool {
	return strings.EqualFold(eco, "Go")
}
