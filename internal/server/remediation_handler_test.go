package server

import (
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
