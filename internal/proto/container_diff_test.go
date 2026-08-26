package proto

import (
	"slices"
	"testing"

	"github.com/google/osv-scalibr/extractor"

	diffv1 "github.com/temporalio/deputy/gen/deputy/diff/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/dependency"
	"github.com/temporalio/deputy/internal/scanning"
	"github.com/temporalio/deputy/internal/vulnerability"
)

func TestBuildContainerDiffResponseFromScanningDeduplicatesAdvisoryAliases(t *testing.T) {
	const (
		pkgName = "github.com/example/vulnerable"
		purl    = "pkg:golang/github.com/example/vulnerable@v1.0.0"
	)
	base := &scanning.Result{
		Packages: []*extractor.Package{
			{Name: pkgName, Version: "v1.0.0", PURLType: "golang"},
		},
		Findings: []vulnerability.Finding{
			containerDiffFinding("GO-2024-0001", pkgName, purl, "v1.0.0"),
			containerDiffFinding("GHSA-abcd-efgh-ijkl", pkgName, purl, "v1.0.0"),
		},
		Advisories: map[string]*vulnerabilityv1.Advisory{
			"GO-2024-0001": {
				Id:       "GO-2024-0001",
				Aliases:  []string{"GHSA-abcd-efgh-ijkl", "CVE-2024-1234"},
				Summary:  "Test vulnerability",
				Severity: vulnerability.NewSeverity("HIGH", ""),
			},
			"GHSA-abcd-efgh-ijkl": {
				Id:       "GHSA-abcd-efgh-ijkl",
				Aliases:  []string{"GO-2024-0001", "CVE-2024-1234"},
				Summary:  "Same test vulnerability",
				Severity: vulnerability.NewSeverity("HIGH", ""),
			},
		},
	}
	target := &scanning.Result{
		Packages: []*extractor.Package{
			{Name: pkgName, Version: "v1.0.1", PURLType: "golang"},
		},
		Advisories: map[string]*vulnerabilityv1.Advisory{},
	}

	resp := BuildContainerDiffResponseFromScanning(base, target)
	if got, want := len(resp.VulnerabilityChanges), 1; got != want {
		t.Fatalf("vulnerability changes = %d, want %d: %#v", got, want, resp.VulnerabilityChanges)
	}

	change := resp.VulnerabilityChanges[0]
	if got, want := change.Id, "CVE-2024-1234"; got != want {
		t.Fatalf("change ID = %q, want %q", got, want)
	}
	if got, want := change.ChangeKind, diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_FIXED; got != want {
		t.Fatalf("change kind = %s, want %s", got, want)
	}
	if got, want := change.BaseVersion, "v1.0.0"; got != want {
		t.Fatalf("base version = %q, want %q", got, want)
	}
	if got, want := change.TargetVersion, "v1.0.1"; got != want {
		t.Fatalf("target version = %q, want %q", got, want)
	}
	if got, want := resp.Summary.GetVulnerabilitiesFixed(), int32(1); got != want {
		t.Fatalf("vulnerabilities fixed = %d, want %d", got, want)
	}
	if got, want := len(resp.Advisories), 1; got != want {
		t.Fatalf("advisories = %d, want %d: %#v", got, want, resp.Advisories)
	}
	if resp.Advisories["CVE-2024-1234"] == nil {
		t.Fatalf("expected advisory keyed by primary ID")
	}
}

// TestBuildContainerDiffResponseFromScanningCarriesScanWarnings pins the
// guarantee a diff has to inherit from its two scans: if either scan could not
// expand an advisory, the diff is not a complete comparison, and a vulnerability
// missing from one side must not read as one that image does not have. Warnings
// are the only thing carrying that, so losing them here makes an incomplete diff
// indistinguishable from a clean one.
func TestBuildContainerDiffResponseFromScanningCarriesScanWarnings(t *testing.T) {
	const (
		missingAdvisory = "osv: advisory GO-2026-6255 reported for github.com/moby/buildkit@v0.30.0 is absent from osv's findings: withdrawn"
		otherAdvisory   = "osv: advisory GHSA-7236-3392-c5c6 reported for github.com/example/other@v1.0.0 is absent from osv's findings: withdrawn"
	)

	tests := []struct {
		name          string
		baseWarnings  []string
		otherWarnings []string
		// nilBase and nilTarget exercise the callers that hand in no result at
		// all, which must stay a diff with no warnings rather than a panic.
		nilBase   bool
		nilTarget bool
		want      []string
	}{
		{
			name: "clean scans add no warnings",
		},
		{
			name:      "nil results add no warnings",
			nilBase:   true,
			nilTarget: true,
		},
		{
			name:         "base-only warning names the base image",
			baseWarnings: []string{missingAdvisory},
			want:         []string{"base image: " + missingAdvisory},
		},
		{
			name:          "target-only warning names the target image",
			otherWarnings: []string{missingAdvisory},
			want:          []string{"target image: " + missingAdvisory},
		},
		{
			// The common case: the advisory is withdrawn upstream, so both
			// scans hit it. Two lines, each saying which image it is about,
			// beats one line that leaves the reader guessing.
			name:          "warning on both sides is reported once per image",
			baseWarnings:  []string{missingAdvisory},
			otherWarnings: []string{missingAdvisory},
			want: []string{
				"base image: " + missingAdvisory,
				"target image: " + missingAdvisory,
			},
		},
		{
			name:          "base warnings precede target warnings",
			baseWarnings:  []string{otherAdvisory},
			otherWarnings: []string{missingAdvisory},
			want: []string{
				"base image: " + otherAdvisory,
				"target image: " + missingAdvisory,
			},
		},
		{
			name:         "repeat within one scan is not shown twice",
			baseWarnings: []string{missingAdvisory, missingAdvisory},
			want:         []string{"base image: " + missingAdvisory},
		},
		{
			name:         "blank warnings are dropped",
			baseWarnings: []string{"", "   ", missingAdvisory},
			want:         []string{"base image: " + missingAdvisory},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := &scanning.Result{Warnings: tt.baseWarnings}
			if tt.nilBase {
				base = nil
			}
			target := &scanning.Result{Warnings: tt.otherWarnings}
			if tt.nilTarget {
				target = nil
			}

			resp := BuildContainerDiffResponseFromScanning(base, target)
			if !slices.Equal(resp.GetWarnings(), tt.want) {
				t.Fatalf("warnings = %q, want %q", resp.GetWarnings(), tt.want)
			}
		})
	}
}

func containerDiffFinding(advisoryID, pkgName, purl, version string) vulnerability.Finding {
	return vulnerability.Finding{
		AdvisoryID: advisoryID,
		Dependency: dependency.ID{
			Name:      pkgName,
			Ecosystem: "go",
			PURL:      purl,
		},
		Version:  version,
		Affected: true,
	}
}
