package regression_test

import (
	"os"
	"slices"
	"strings"
	"testing"

	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/dependency"
	"github.com/temporalio/deputy/internal/regression"
	"github.com/temporalio/deputy/internal/scanning"
	_ "github.com/temporalio/deputy/internal/targets/providers"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// TestLiveRegressionImages scans every recorded image end to end, pulling it
// by digest and querying live advisory data. It needs registry and OSV access,
// so it runs only with DEPUTY_REGRESSION_E2E=1:
//
//	DEPUTY_REGRESSION_E2E=1 go test -v -run TestLiveRegressionImages ./internal/regression/
//
// Assertions are lower bounds on live data (new advisories only add findings)
// plus the shapes the offline tests pin from the recordings.
func TestLiveRegressionImages(t *testing.T) {
	if os.Getenv("DEPUTY_REGRESSION_E2E") != "1" {
		t.Skip("set DEPUTY_REGRESSION_E2E=1 to scan the regression images live")
	}
	tests := []struct {
		name  string
		opts  scanning.Options
		check func(t *testing.T, r *scanning.Result)
	}{
		{"base-server-1.15.3", scanning.Options{}, func(t *testing.T, r *scanning.Result) {
			requireAdvisory(t, r, "DEPUTY-EOL-ALPINE-3.18")
			if cves := countKind(r, vulnerabilityv1.FindingKind_FINDING_KIND_EOL, false); cves == 0 {
				t.Error("no vulnerability findings alongside the EOL finding")
			}
		}},
		{"server-1.20.0", scanning.Options{}, func(t *testing.T, r *scanning.Result) {
			requireAdvisory(t, r, "DEPUTY-EOL-ALPINE-3.17")
			n := 0
			for _, f := range r.Findings {
				if f.Dependency.Name == "go.temporal.io/server" && strings.HasPrefix(f.AdvisoryID, "GHSA-") {
					n++
				}
			}
			if n == 0 {
				t.Error("no server advisories reported on a release that predates their fixes")
			}
		}},
		{"alpine-3.24.0", scanning.Options{}, func(t *testing.T, r *scanning.Result) {
			if !slices.ContainsFunc(r.Findings, func(f vulnerability.Finding) bool { return f.Dependency.Name == "libssl3" }) {
				t.Error("no findings on libssl3; source-name matching regressed")
			}
		}},
		{"alpine-3.24.1", scanning.Options{CheckDistroUpdates: true}, func(t *testing.T, r *scanning.Result) {
			if len(r.Coverage.GetDistroUpdates()) == 0 {
				t.Error("no distro_updates on a point release behind its branch")
			}
		}},
		{"admin-tools-1.31.4", scanning.Options{}, func(t *testing.T, r *scanning.Result) {
			bins := map[string]bool{}
			for _, p := range r.Packages {
				for _, l := range dependency.PackagePaths(p) {
					if strings.HasPrefix(l, "usr/local/bin/") {
						bins[l] = true
					}
				}
			}
			if len(bins) < 5 {
				t.Errorf("Go binaries inventoried = %d, want at least 5", len(bins))
			}
		}},
		{"debian-12-slim", scanning.Options{}, supportedDistro("debian", "12")},
		{"distroless-static-debian12", scanning.Options{}, supportedDistro("debian", "12")},
		{"distroless-base-debian12", scanning.Options{}, supportedDistro("debian", "12")},
		{"ubuntu-24.04", scanning.Options{}, supportedDistro("ubuntu", "24.04")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			img, err := regression.Load(tt.name)
			if err != nil {
				t.Fatal(err)
			}
			exec, err := scanning.ScanContainerImage(t.Context(), img.Ref(), map[string]string{"platform": img.Platform, "transport": "remote"}, tt.opts)
			if err != nil {
				t.Fatalf("scan %s: %v", img.Ref(), err)
			}
			t.Cleanup(func() { _ = exec.Close() })
			// The scan path can inventory a few entries the recording (from
			// deputy list) folds together, so the recording is a lower bound.
			if exec.Result.PackagesScanned < len(img.Packages) {
				t.Errorf("packages = %d, recorded %d; re-record if the inventory change is intended", exec.Result.PackagesScanned, len(img.Packages))
			}
			tt.check(t, &exec.Result)
		})
	}
}

func requireAdvisory(t *testing.T, r *scanning.Result, id string) {
	t.Helper()
	if !slices.ContainsFunc(r.Findings, func(f vulnerability.Finding) bool { return f.AdvisoryID == id }) {
		t.Errorf("no %s finding", id)
	}
}

// countKind counts findings whose advisory is (or, with is=false, is not) of
// the given kind.
func countKind(r *scanning.Result, kind vulnerabilityv1.FindingKind, is bool) int {
	n := 0
	for _, f := range r.Findings {
		if (r.Advisories[f.AdvisoryID].GetKind() == kind) == is {
			n++
		}
	}
	return n
}

func supportedDistro(distribution, release string) func(*testing.T, *scanning.Result) {
	return func(t *testing.T, r *scanning.Result) {
		ds := r.Coverage.GetDistros()
		if len(ds) != 1 || ds[0].GetDistribution() != distribution || ds[0].GetRelease() != release ||
			ds[0].GetStatus() != vulnerabilityv1.DistroStatus_DISTRO_STATUS_SUPPORTED {
			t.Errorf("distros = %v, want %s %s supported", ds, distribution, release)
		}
		if countKind(r, vulnerabilityv1.FindingKind_FINDING_KIND_EOL, true) != 0 {
			t.Error("EOL finding on a supported release")
		}
	}
}
