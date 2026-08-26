package server

import (
	"slices"
	"testing"

	"connectrpc.com/connect"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	remediationv1 "github.com/temporalio/deputy/gen/deputy/remediation/v1"
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// TestGeneratePlanAcceptsEcosystemlessPackages pins a live-spin regression:
// scan results legitimately contain packages without a package ecosystem
// (Dockerfile base-image references, unrecognized SBOM components), and plan
// generation must not reject the whole scan over them.
func TestGeneratePlanAcceptsEcosystemlessPackages(t *testing.T) {
	vulnerable := &dependencyv1.Package{
		Name:      "github.com/example/widget",
		Version:   "v1.4.0",
		Ecosystem: "go",
		Purl:      "pkg:golang/github.com/example/widget@v1.4.0",
		Direct:    true,
		ManifestRefs: []*dependencyv1.ManifestRef{
			{Path: "go.mod", Manager: "go"},
		},
	}
	baseImage := &dependencyv1.Package{
		Name:    "library/golang",
		Version: "1.24",
		Purl:    "pkg:docker/library%2Fgolang@1.24",
		Direct:  true,
	}

	scan := &scanv1.ScanResponse{
		PackagesScanned: 2,
		Packages:        []*dependencyv1.Package{vulnerable, baseImage},
		Findings: []*vulnerabilityv1.Finding{
			{AdvisoryId: "GO-2026-0001", Package: vulnerable, Affected: true},
		},
		Advisories: map[string]*vulnerabilityv1.Advisory{
			"GO-2026-0001": {
				Id:            "GO-2026-0001",
				Summary:       "Fixable vulnerability",
				Severity:      vulnerability.NewSeverity("HIGH", ""),
				FixedVersions: []string{"1.5.0"},
			},
		},
		Stats: &vulnerabilityv1.Stats{Total: 1, Unique: 1, High: 1},
	}

	handler := NewRemediationHandler()
	resp, err := handler.GeneratePlan(t.Context(), connect.NewRequest(&remediationv1.GeneratePlanRequest{
		Source: &remediationv1.GeneratePlanRequest_ScanResult{ScanResult: scan},
	}))
	if err != nil {
		t.Fatalf("GeneratePlan rejected a scan with an ecosystem-less package: %v", err)
	}
	if got := resp.Msg.GetStats().GetVulnerabilitiesAddressed(); got != 1 {
		t.Fatalf("vulnerabilitiesAddressed = %d, want 1", got)
	}
	var covered bool
	for _, step := range resp.Msg.GetPlan().GetSteps() {
		for _, id := range step.GetAffectedVulnerabilities() {
			if id == "GO-2026-0001" {
				covered = true
			}
		}
	}
	if !covered {
		t.Fatalf("no step remediates GO-2026-0001: %+v", resp.Msg.GetPlan().GetSteps())
	}
}

// TestGeneratePlanCarriesScanWarnings pins the guarantee a plan inherits from
// its scan. When an advisory could not be expanded, its finding never reached
// planning: no step addresses it and it is absent from
// unaddressed_vulnerabilities, so the warning is the only thing distinguishing
// "nothing to fix" from "we could not see everything". The empty-plan case is
// the one that matters most, because that is the response that tells a consumer
// no remediation is needed.
func TestGeneratePlanCarriesScanWarnings(t *testing.T) {
	const (
		unresolved = "osv: advisory GO-2026-6255 reported for github.com/moby/buildkit@v0.30.0 is missing from this report: withdrawn"
		other      = "osv: advisory GHSA-7236-3392-c5c6 reported for github.com/example/other@v1.0.0 is missing from this report: withdrawn"
	)

	vulnerable := &dependencyv1.Package{
		Name:      "github.com/example/widget",
		Version:   "v1.4.0",
		Ecosystem: "go",
		Purl:      "pkg:golang/github.com/example/widget@v1.4.0",
		Direct:    true,
		ManifestRefs: []*dependencyv1.ManifestRef{
			{Path: "go.mod", Manager: "go"},
		},
	}
	fixableFindings := []*vulnerabilityv1.Finding{
		{AdvisoryId: "GO-2026-0001", Package: vulnerable, Affected: true},
	}
	fixableAdvisories := map[string]*vulnerabilityv1.Advisory{
		"GO-2026-0001": {
			Id:            "GO-2026-0001",
			Summary:       "Fixable vulnerability",
			Severity:      vulnerability.NewSeverity("HIGH", ""),
			FixedVersions: []string{"1.5.0"},
		},
	}

	tests := []struct {
		name       string
		scan       *scanv1.ScanResponse
		wantSteps  bool
		wantWarned []string
	}{
		{
			// The path that currently reads as clean: no findings, empty plan,
			// and until now no sign that a record went missing.
			name: "empty plan still reports the scan's warnings",
			scan: &scanv1.ScanResponse{
				PackagesScanned: 1,
				Packages:        []*dependencyv1.Package{vulnerable},
				Stats:           &vulnerabilityv1.Stats{},
				Warnings:        []string{unresolved},
			},
			wantWarned: []string{unresolved},
		},
		{
			name: "populated plan reports the scan's warnings",
			scan: &scanv1.ScanResponse{
				PackagesScanned: 1,
				Packages:        []*dependencyv1.Package{vulnerable},
				Findings:        fixableFindings,
				Advisories:      fixableAdvisories,
				Stats:           &vulnerabilityv1.Stats{Total: 1, Unique: 1, High: 1},
				Warnings:        []string{unresolved},
			},
			wantSteps:  true,
			wantWarned: []string{unresolved},
		},
		{
			name: "every warning survives, in the scan's order",
			scan: &scanv1.ScanResponse{
				PackagesScanned: 1,
				Packages:        []*dependencyv1.Package{vulnerable},
				Findings:        fixableFindings,
				Advisories:      fixableAdvisories,
				Stats:           &vulnerabilityv1.Stats{Total: 1, Unique: 1, High: 1},
				Warnings:        []string{other, unresolved},
			},
			wantSteps:  true,
			wantWarned: []string{other, unresolved},
		},
		{
			name: "a clean scan adds no warnings",
			scan: &scanv1.ScanResponse{
				PackagesScanned: 1,
				Packages:        []*dependencyv1.Package{vulnerable},
				Stats:           &vulnerabilityv1.Stats{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewRemediationHandler()
			resp, err := handler.GeneratePlan(t.Context(), connect.NewRequest(&remediationv1.GeneratePlanRequest{
				Source: &remediationv1.GeneratePlanRequest_ScanResult{ScanResult: tt.scan},
			}))
			if err != nil {
				t.Fatalf("GeneratePlan: %v", err)
			}
			if gotSteps := len(resp.Msg.GetPlan().GetSteps()) > 0; gotSteps != tt.wantSteps {
				t.Fatalf("plan has steps = %t, want %t", gotSteps, tt.wantSteps)
			}
			if !slices.Equal(resp.Msg.GetWarnings(), tt.wantWarned) {
				t.Fatalf("warnings = %q, want %q", resp.Msg.GetWarnings(), tt.wantWarned)
			}
		})
	}
}
