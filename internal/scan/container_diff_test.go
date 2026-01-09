package scan

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"
	containerv1 "github.com/picatz/deputy/gen/deputy/container/v1"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/compare"
	"github.com/picatz/deputy/internal/container/image"
	"github.com/picatz/deputy/internal/dependency"
	"github.com/picatz/deputy/internal/vulnerability"
)

func TestBuildContainerDiffReport(t *testing.T) {
	t.Run("nil results", func(t *testing.T) {
		report := buildContainerDiffReport(nil, nil)
		if report == nil {
			t.Fatal("expected non-nil report")
		}
		if len(report.PackageChanges) != 0 {
			t.Errorf("expected no package changes, got %d", len(report.PackageChanges))
		}
	})

	t.Run("empty results", func(t *testing.T) {
		base := &Result{
			Inventory: Inventory{},
		}
		target := &Result{
			Inventory: Inventory{},
		}
		report := buildContainerDiffReport(base, target)
		if report == nil {
			t.Fatal("expected non-nil report")
		}
		if len(report.PackageChanges) != 0 {
			t.Errorf("expected no package changes, got %d", len(report.PackageChanges))
		}
	})
}

func TestExtractImageRef(t *testing.T) {
	t.Run("nil result", func(t *testing.T) {
		ref := extractImageRef(nil)
		if ref.Reference != "" {
			t.Errorf("expected empty reference, got %q", ref.Reference)
		}
	})

	t.Run("with target info", func(t *testing.T) {
		result := &Result{
			Target: Target{
				DisplayPath: "oci://nginx:1.25",
				Provenance: map[string]string{
					"registry":   "docker.io",
					"repository": "library/nginx",
					"tag":        "1.25",
					"digest":     "sha256:abc123",
				},
			},
		}
		ref := extractImageRef(result)
		if ref.Reference != "oci://nginx:1.25" {
			t.Errorf("expected reference %q, got %q", "oci://nginx:1.25", ref.Reference)
		}
		if ref.Registry != "docker.io" {
			t.Errorf("expected registry %q, got %q", "docker.io", ref.Registry)
		}
		if ref.Repository != "library/nginx" {
			t.Errorf("expected repository %q, got %q", "library/nginx", ref.Repository)
		}
		if ref.Tag != "1.25" {
			t.Errorf("expected tag %q, got %q", "1.25", ref.Tag)
		}
		if ref.Digest != "sha256:abc123" {
			t.Errorf("expected digest %q, got %q", "sha256:abc123", ref.Digest)
		}
	})
}

func TestToImageInput(t *testing.T) {
	t.Run("nil info", func(t *testing.T) {
		input := toImageInput(nil)
		if input != nil {
			t.Errorf("expected nil input, got %v", input)
		}
	})

	t.Run("basic config", func(t *testing.T) {
		info := &image.Info{
			Config: image.Config{
				User:       "nobody",
				Env:        []string{"PATH=/usr/bin"},
				Entrypoint: []string{"/app"},
				Cmd:        []string{"serve"},
				WorkingDir: "/app",
			},
			Metadata: image.Metadata{
				LayerCount: 5,
			},
			History: []image.HistoryEntry{
				{CreatedBy: "RUN apt-get update", EmptyLayer: false},
			},
		}

		input := toImageInput(info)
		if input == nil {
			t.Fatal("expected non-nil input")
		}
		if input.Config.User != "nobody" {
			t.Errorf("expected user %q, got %q", "nobody", input.Config.User)
		}
		if len(input.Config.Env) != 1 || input.Config.Env[0] != "PATH=/usr/bin" {
			t.Errorf("unexpected env: %v", input.Config.Env)
		}
		if input.Metadata.LayerCount != 5 {
			t.Errorf("expected 5 layers, got %d", input.Metadata.LayerCount)
		}
		if len(input.History) != 1 {
			t.Errorf("expected 1 history entry, got %d", len(input.History))
		}
	})
}

func TestCompareImageVulnerabilities(t *testing.T) {
	t.Run("nil results", func(t *testing.T) {
		changes := compareImageVulnerabilities(nil, nil)
		if len(changes) != 0 {
			t.Errorf("expected no changes, got %d", len(changes))
		}
	})

	t.Run("added vulnerability", func(t *testing.T) {
		base := &Result{
			Findings:   []vulnerability.Finding{},
			Advisories: map[string]*vulnerabilityv1.Advisory{},
		}
		target := &Result{
			Findings: []vulnerability.Finding{
				{
					AdvisoryID: "CVE-2024-1234",
					Dependency: dependency.ID{Name: "openssl"},
					Version:    "1.1.1",
				},
			},
			Advisories: map[string]*vulnerabilityv1.Advisory{
				"CVE-2024-1234": {
					Id:       "CVE-2024-1234",
					Severity: &vulnerabilityv1.Severity{Level: vulnerability.SeverityHigh},
					Summary:  "Test vulnerability",
				},
			},
		}

		changes := compareImageVulnerabilities(base, target)
		if len(changes) != 1 {
			t.Fatalf("expected 1 change, got %d", len(changes))
		}
		if changes[0].ChangeType != compare.VulnAdded {
			t.Errorf("expected VulnAdded, got %v", changes[0].ChangeType)
		}
		if changes[0].ID != "CVE-2024-1234" {
			t.Errorf("expected ID %q, got %q", "CVE-2024-1234", changes[0].ID)
		}
		if changes[0].PackageName != "openssl" {
			t.Errorf("expected package %q, got %q", "openssl", changes[0].PackageName)
		}
	})

	t.Run("removed vulnerability", func(t *testing.T) {
		base := &Result{
			Findings: []vulnerability.Finding{
				{
					AdvisoryID: "CVE-2024-1234",
					Dependency: dependency.ID{Name: "openssl"},
					Version:    "1.1.1",
				},
			},
			Advisories: map[string]*vulnerabilityv1.Advisory{
				"CVE-2024-1234": {
					Id:       "CVE-2024-1234",
					Severity: &vulnerabilityv1.Severity{Level: vulnerability.SeverityCritical},
					Summary:  "Test vulnerability",
				},
			},
			Inventory: Inventory{},
		}
		target := &Result{
			Findings:   []vulnerability.Finding{},
			Advisories: map[string]*vulnerabilityv1.Advisory{},
			Inventory:  Inventory{},
		}

		changes := compareImageVulnerabilities(base, target)
		if len(changes) != 1 {
			t.Fatalf("expected 1 change, got %d", len(changes))
		}
		if changes[0].ChangeType != compare.VulnRemoved {
			t.Errorf("expected VulnRemoved, got %v", changes[0].ChangeType)
		}
	})
}

func TestWasFixedByUpgrade(t *testing.T) {
	t.Run("package upgraded in target", func(t *testing.T) {
		// Vulnerability was in openssl 1.1.1, target has 1.1.2 -> fixed by upgrade
		finding := vulnerability.Finding{
			Dependency: dependency.ID{Name: "openssl"},
			Version:    "1.1.1",
		}
		target := &Result{
			Inventory: Inventory{
				Packages: []*extractor.Package{{Name: "openssl", Version: "1.1.2"}},
			},
		}
		if !wasFixedByUpgrade(finding, target) {
			t.Error("expected true when package was upgraded")
		}
	})

	t.Run("package same version in target", func(t *testing.T) {
		// Same version - not fixed by upgrade (vuln gone for other reason)
		finding := vulnerability.Finding{
			Dependency: dependency.ID{Name: "openssl"},
			Version:    "1.1.1",
		}
		target := &Result{
			Inventory: Inventory{
				Packages: []*extractor.Package{{Name: "openssl", Version: "1.1.1"}},
			},
		}
		if wasFixedByUpgrade(finding, target) {
			t.Error("expected false when version unchanged")
		}
	})

	t.Run("package removed from target", func(t *testing.T) {
		finding := vulnerability.Finding{
			Dependency: dependency.ID{Name: "openssl"},
			Version:    "1.1.1",
		}
		target := &Result{
			Inventory: Inventory{
				Packages: []*extractor.Package{{Name: "curl", Version: "7.0"}},
			},
		}
		if wasFixedByUpgrade(finding, target) {
			t.Error("expected false when package not in target")
		}
	})
}

func TestConvertLayerDetails(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		result := convertLayerDetails(nil)
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("with details", func(t *testing.T) {
		ld := &containerv1.LayerDetails{
			Index:       2,
			DiffId:      "sha256:abc",
			ChainId:     "sha256:def",
			Command:     "RUN apt-get install",
			InBaseImage: true,
		}
		result := convertLayerDetails(ld)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Index != 2 {
			t.Errorf("expected index 2, got %d", result.Index)
		}
		if result.DiffId != "sha256:abc" {
			t.Errorf("expected DiffId %q, got %q", "sha256:abc", result.DiffId)
		}
		if result.ChainId != "sha256:def" {
			t.Errorf("expected ChainId %q, got %q", "sha256:def", result.ChainId)
		}
		if result.Command != "RUN apt-get install" {
			t.Errorf("expected command %q, got %q", "RUN apt-get install", result.Command)
		}
		if !result.InBaseImage {
			t.Error("expected InBaseImage to be true")
		}
	})
}

func TestBuildContainerDiffPayload(t *testing.T) {
	t.Run("basic payload", func(t *testing.T) {
		report := &compare.ImageDiffReport{
			BaseImage: compare.ImageRef{
				Registry:   "docker.io",
				Repository: "library/nginx",
				Tag:        "1.24",
			},
			TargetImage: compare.ImageRef{
				Registry:   "docker.io",
				Repository: "library/nginx",
				Tag:        "1.25",
			},
			Summary: compare.ImageDiffSummary{
				PackagesAdded:   5,
				PackagesRemoved: 2,
			},
		}

		payload := BuildContainerDiffPayload(report)

		baseImage, ok := payload["base_image"].(map[string]any)
		if !ok {
			t.Fatal("expected base_image map")
		}
		if baseImage["tag"] != "1.24" {
			t.Errorf("expected base tag %q, got %v", "1.24", baseImage["tag"])
		}

		targetImage, ok := payload["target_image"].(map[string]any)
		if !ok {
			t.Fatal("expected target_image map")
		}
		if targetImage["tag"] != "1.25" {
			t.Errorf("expected target tag %q, got %v", "1.25", targetImage["tag"])
		}

		summary, ok := payload["summary"].(map[string]any)
		if !ok {
			t.Fatal("expected summary map")
		}
		if summary["packages_added"] != 5 {
			t.Errorf("expected packages_added 5, got %v", summary["packages_added"])
		}
	})

	t.Run("with package changes", func(t *testing.T) {
		report := &compare.ImageDiffReport{
			PackageChanges: []compare.ImagePackageChange{
				{
					Change: compare.Change{
						Name:          "openssl",
						ChangeType:    compare.Upgraded,
						BaseVersion:   "1.1.1",
						TargetVersion: "3.0.0",
					},
				},
			},
			Summary: compare.ImageDiffSummary{},
		}

		payload := BuildContainerDiffPayload(report)
		changes, ok := payload["package_changes"].([]map[string]any)
		if !ok {
			t.Fatal("expected package_changes array")
		}
		if len(changes) != 1 {
			t.Fatalf("expected 1 change, got %d", len(changes))
		}
		if changes[0]["name"] != "openssl" {
			t.Errorf("expected name %q, got %v", "openssl", changes[0]["name"])
		}
	})

	t.Run("with vulnerability changes", func(t *testing.T) {
		report := &compare.ImageDiffReport{
			VulnerabilityChanges: []compare.VulnerabilityChange{
				{
					ID:          "CVE-2024-1234",
					ChangeType:  compare.VulnAdded,
					Severity:    "HIGH",
					PackageName: "openssl",
				},
			},
			Summary: compare.ImageDiffSummary{},
		}

		payload := BuildContainerDiffPayload(report)
		vulns, ok := payload["vulnerability_changes"].([]map[string]any)
		if !ok {
			t.Fatal("expected vulnerability_changes array")
		}
		if len(vulns) != 1 {
			t.Fatalf("expected 1 vuln, got %d", len(vulns))
		}
		if vulns[0]["id"] != "CVE-2024-1234" {
			t.Errorf("expected id %q, got %v", "CVE-2024-1234", vulns[0]["id"])
		}
		if vulns[0]["severity"] != "HIGH" {
			t.Errorf("expected severity %q, got %v", "HIGH", vulns[0]["severity"])
		}
	})
}
