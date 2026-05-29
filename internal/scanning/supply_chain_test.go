package scanning

import (
	"context"
	"testing"

	"github.com/google/osv-scalibr/extractor"
)

func TestCheckSupplyChain_UnpinnedAction(t *testing.T) {
	pkgs := []*extractor.Package{
		{
			Name:     "actions/checkout",
			Version:  "v4",
			PURLType: "githubactions",
		},
	}

	findings, advisories := checkSupplyChain(context.Background(), pkgs, nil, "")

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].AdvisoryID != AdvisoryUnpinnedAction {
		t.Errorf("expected advisory ID %q, got %q", AdvisoryUnpinnedAction, findings[0].AdvisoryID)
	}
	if findings[0].Dependency.Name != "actions/checkout" {
		t.Errorf("expected dependency name actions/checkout, got %q", findings[0].Dependency.Name)
	}
	if !findings[0].Affected {
		t.Error("expected finding to be marked affected")
	}
	if advisories == nil {
		t.Fatal("expected advisories map")
	}
	if _, ok := advisories[AdvisoryUnpinnedAction]; !ok {
		t.Error("expected advisory definition for DEPUTY-SC-UNPINNED-ACTION")
	}
}

func TestCheckSupplyChain_SelfReferenceSkipped(t *testing.T) {
	pkgs := []*extractor.Package{
		{
			Name:     "temporalio/deputy/actions/setup",
			Version:  "main",
			PURLType: "githubactions",
		},
		{
			Name:     "temporalio/deputy", // reusable workflow self-reference
			Version:  "main",
			PURLType: "githubactions",
		},
		{
			Name:     "actions/checkout", // third-party, still flagged
			Version:  "v4",
			PURLType: "githubactions",
		},
	}

	findings, _ := checkSupplyChain(context.Background(), pkgs, nil, "temporalio/deputy")

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (third-party only), got %d", len(findings))
	}
	if findings[0].Dependency.Name != "actions/checkout" {
		t.Errorf("expected only actions/checkout flagged, got %q", findings[0].Dependency.Name)
	}
}

func TestCheckSupplyChain_SelfReferenceCaseInsensitive(t *testing.T) {
	pkgs := []*extractor.Package{
		{
			Name:     "Temporalio/Deputy/actions/setup",
			Version:  "main",
			PURLType: "githubactions",
		},
	}

	findings, _ := checkSupplyChain(context.Background(), pkgs, nil, "temporalio/deputy")

	if len(findings) != 0 {
		t.Errorf("expected self-reference match to be case-insensitive, got %d findings", len(findings))
	}
}

func TestCheckSupplyChain_PinnedActionSkipped(t *testing.T) {
	pkgs := []*extractor.Package{
		{
			Name:     "actions/checkout",
			Version:  "11bd71901bbe5b1630ceea73d27597364c9af683",
			PURLType: "githubactions",
		},
	}

	findings, advisories := checkSupplyChain(context.Background(), pkgs, nil, "")

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for pinned action, got %d", len(findings))
	}
	if advisories != nil {
		t.Errorf("expected nil advisories for pinned action")
	}
}

func TestCheckSupplyChain_NonGHASkipped(t *testing.T) {
	pkgs := []*extractor.Package{
		{
			Name:     "lodash",
			Version:  "4.17.21",
			PURLType: "npm",
		},
	}

	findings, advisories := checkSupplyChain(context.Background(), pkgs, nil, "")

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-GHA package, got %d", len(findings))
	}
	if advisories != nil {
		t.Error("expected nil advisories for non-GHA packages")
	}
}

func TestCheckSupplyChain_MixedPackages(t *testing.T) {
	sha := "11bd71901bbe5b1630ceea73d27597364c9af683"
	pkgs := []*extractor.Package{
		{Name: "actions/checkout", Version: "v4", PURLType: "githubactions"},
		{Name: "actions/setup-go", Version: sha, PURLType: "githubactions"},
		{Name: "lodash", Version: "4.17.21", PURLType: "npm"},
		{Name: "golangci/golangci-lint-action", Version: "v6", PURLType: "githubactions"},
		nil, // nil package should be skipped
	}

	findings, advisories := checkSupplyChain(context.Background(), pkgs, nil, "")

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (2 unpinned actions), got %d", len(findings))
	}
	if advisories == nil {
		t.Fatal("expected advisories map")
	}

	names := map[string]bool{}
	for _, f := range findings {
		names[f.Dependency.Name] = true
		if f.AdvisoryID != AdvisoryUnpinnedAction {
			t.Errorf("unexpected advisory ID: %q", f.AdvisoryID)
		}
	}
	if !names["actions/checkout"] {
		t.Error("expected finding for actions/checkout")
	}
	if !names["golangci/golangci-lint-action"] {
		t.Error("expected finding for golangci/golangci-lint-action")
	}
}

func TestCheckSupplyChain_EmptyPackages(t *testing.T) {
	findings, advisories := checkSupplyChain(context.Background(), nil, nil, "")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
	if advisories != nil {
		t.Error("expected nil advisories")
	}
}

func TestCheckSupplyChain_LocationsPreserved(t *testing.T) {
	pkgs := []*extractor.Package{
		{
			Name:      "actions/checkout",
			Version:   "v4",
			PURLType:  "githubactions",
			Locations: []string{".github/workflows/ci.yml"},
		},
	}

	findings, _ := checkSupplyChain(context.Background(), pkgs, nil, "")

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if len(findings[0].Locations) != 1 || findings[0].Locations[0] != ".github/workflows/ci.yml" {
		t.Errorf("expected Locations [.github/workflows/ci.yml], got %v", findings[0].Locations)
	}

	// Verify it's a copy, not a shared reference.
	pkgs[0].Locations[0] = "mutated"
	if findings[0].Locations[0] == "mutated" {
		t.Error("finding Locations should be a copy, not a shared reference")
	}
}

func TestCheckSupplyChain_AdvisoryMetadata(t *testing.T) {
	pkgs := []*extractor.Package{
		{Name: "actions/checkout", Version: "v4", PURLType: "githubactions"},
	}

	_, advisories := checkSupplyChain(context.Background(), pkgs, nil, "")

	adv := advisories[AdvisoryUnpinnedAction]
	if adv == nil {
		t.Fatal("expected advisory for DEPUTY-SC-UNPINNED-ACTION")
	}

	// FixedVersions should be set so --ignore-unfixed doesn't drop it.
	if len(adv.FixedVersions) == 0 {
		t.Error("expected FixedVersions to be set (for --ignore-unfixed compatibility)")
	}

	// CWEs should be set.
	if len(adv.Cwes) == 0 {
		t.Error("expected CWEs to be set")
	}

	// DatabaseSpecific should identify this as a supply-chain finding.
	if adv.DatabaseSpecific["type"] != "supply-chain" {
		t.Errorf("expected database_specific.type = supply-chain, got %q", adv.DatabaseSpecific["type"])
	}
	if adv.DatabaseSpecific["remediation"] != "deputy pin" {
		t.Errorf("expected database_specific.remediation = deputy pin, got %q", adv.DatabaseSpecific["remediation"])
	}
}

func TestCheckSupplyChain_EcosystemField(t *testing.T) {
	pkgs := []*extractor.Package{
		{Name: "actions/checkout", Version: "v4", PURLType: "githubactions"},
	}

	findings, _ := checkSupplyChain(context.Background(), pkgs, nil, "")

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Dependency.Ecosystem != "GitHub Actions" {
		t.Errorf("expected ecosystem 'GitHub Actions', got %q", findings[0].Dependency.Ecosystem)
	}
}

// --- Container image tests ---

func TestCheckSupplyChain_UnpinnedImage(t *testing.T) {
	pkgs := []*extractor.Package{
		{Name: "alpine", Version: "3.19", PURLType: "docker"},
	}

	findings, advisories := checkSupplyChain(context.Background(), pkgs, nil, "")

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].AdvisoryID != AdvisoryUnpinnedImage {
		t.Errorf("expected advisory ID %q, got %q", AdvisoryUnpinnedImage, findings[0].AdvisoryID)
	}
	if findings[0].Dependency.Ecosystem != "Docker" {
		t.Errorf("expected ecosystem Docker, got %q", findings[0].Dependency.Ecosystem)
	}
	if _, ok := advisories[AdvisoryUnpinnedImage]; !ok {
		t.Error("expected advisory for DEPUTY-SC-UNPINNED-IMAGE")
	}
	// Should NOT include the action advisory since no actions are present.
	if _, ok := advisories[AdvisoryUnpinnedAction]; ok {
		t.Error("should not include action advisory when only images are unpinned")
	}
}

func TestCheckSupplyChain_PinnedImageSkipped(t *testing.T) {
	pkgs := []*extractor.Package{
		{Name: "alpine", Version: "sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c", PURLType: "docker"},
		{Name: "ghcr.io/owner/image", Version: "v1@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", PURLType: "oci"},
	}

	findings, advisories := checkSupplyChain(context.Background(), pkgs, nil, "")

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for pinned images, got %d", len(findings))
	}
	if advisories != nil {
		t.Error("expected nil advisories")
	}
}

func TestCheckSupplyChain_UnpinnedOCIImage(t *testing.T) {
	pkgs := []*extractor.Package{
		{Name: "ghcr.io/owner/image", Version: "v2", PURLType: "oci"},
	}

	findings, advisories := checkSupplyChain(context.Background(), pkgs, nil, "")

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].AdvisoryID != AdvisoryUnpinnedImage {
		t.Errorf("expected %q, got %q", AdvisoryUnpinnedImage, findings[0].AdvisoryID)
	}
	if _, ok := advisories[AdvisoryUnpinnedImage]; !ok {
		t.Error("expected advisory for DEPUTY-SC-UNPINNED-IMAGE")
	}
}

func TestCheckSupplyChain_MixedActionsAndImages(t *testing.T) {
	pkgs := []*extractor.Package{
		{Name: "actions/checkout", Version: "v4", PURLType: "githubactions"},
		{Name: "alpine", Version: "3.19", PURLType: "docker"},
		{Name: "lodash", Version: "4.17.21", PURLType: "npm"},
	}

	findings, advisories := checkSupplyChain(context.Background(), pkgs, nil, "")

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (1 action + 1 image), got %d", len(findings))
	}

	// Both advisory types should be present.
	if _, ok := advisories[AdvisoryUnpinnedAction]; !ok {
		t.Error("expected action advisory")
	}
	if _, ok := advisories[AdvisoryUnpinnedImage]; !ok {
		t.Error("expected image advisory")
	}
}
