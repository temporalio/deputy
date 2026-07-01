package proto

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"

	diffv1 "github.com/temporalio/deputy/gen/deputy/diff/v1"
	"github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
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
