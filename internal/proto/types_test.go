package proto

import (
	"testing"

	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	targetv1 "github.com/picatz/deputy/gen/deputy/target/v1"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/targets"
)

func TestTargetKindAlias(t *testing.T) {
	// Verify that targets.Kind is an alias for targetv1.TargetKind
	// This means no conversion is needed - they're the same type.
	tests := []struct {
		name string
		kind targets.Kind
		want targetv1.TargetKind
	}{
		{"dir", targets.KindDir, targetv1.TargetKind_TARGET_KIND_DIR},
		{"file", targets.KindFile, targetv1.TargetKind_TARGET_KIND_FILE},
		{"binary", targets.KindBinary, targetv1.TargetKind_TARGET_KIND_BINARY},
		{"git", targets.KindGit, targetv1.TargetKind_TARGET_KIND_GIT},
		{"container-image", targets.KindContainerImage, targetv1.TargetKind_TARGET_KIND_CONTAINER_IMAGE},
		{"container-instance", targets.KindContainerInstance, targetv1.TargetKind_TARGET_KIND_CONTAINER_INSTANCE},
		{"vm-image", targets.KindVMImage, targetv1.TargetKind_TARGET_KIND_VM_IMAGE},
		{"extension", targets.KindExtension, targetv1.TargetKind_TARGET_KIND_EXTENSION},
		{"sbom", targets.KindSBOM, targetv1.TargetKind_TARGET_KIND_SBOM},
		{"purl", targets.KindPURL, targetv1.TargetKind_TARGET_KIND_PURL},
		{"dockerfile", targets.KindDockerfile, targetv1.TargetKind_TARGET_KIND_DOCKERFILE},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Since Kind is a type alias, direct assignment should work
			var protoKind targetv1.TargetKind = tt.kind
			if protoKind != tt.want {
				t.Errorf("kind mismatch: got %v, want %v", protoKind, tt.want)
			}
		})
	}
}

func TestAdvisoryFields(t *testing.T) {
	// Advisory is already a proto type (vulnerabilityv1.Advisory).
	// Test that the proto fields work correctly.
	advisory := &vulnerabilityv1.Advisory{
		Id:        "CVE-2021-44228",
		Aliases:   []string{"GHSA-jfh8-c2jp-5v3q"},
		Summary:   "Log4j RCE vulnerability",
		Details:   "A remote code execution vulnerability in Apache Log4j",
		Cve:       "CVE-2021-44228",
		Severity: &vulnerabilityv1.Severity{
			Type:  vulnerabilityv1.SeverityType_SEVERITY_TYPE_CVSS_V3,
			Score: 10.0,
		},
		References:    []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
		FixedVersions: []string{"2.15.0", "2.16.0"},
		DatabaseSpecific: map[string]string{
			"severity": "CRITICAL",
		},
		Cwes: []string{"CWE-77", "CWE-94"},
	}

	if advisory.Id != "CVE-2021-44228" {
		t.Errorf("Id: got %v, want CVE-2021-44228", advisory.Id)
	}
	if len(advisory.Aliases) != 1 {
		t.Errorf("Aliases: got %d, want 1", len(advisory.Aliases))
	}
	if advisory.Severity.Type != vulnerabilityv1.SeverityType_SEVERITY_TYPE_CVSS_V3 {
		t.Errorf("Severity.Type: got %v, want CVSS_V3", advisory.Severity.Type)
	}
	if advisory.Severity.Score != 10.0 {
		t.Errorf("Severity.Score: got %v, want 10.0", advisory.Severity.Score)
	}
	if len(advisory.FixedVersions) != 2 {
		t.Errorf("FixedVersions: got %d, want 2", len(advisory.FixedVersions))
	}
	if len(advisory.Cwes) != 2 {
		t.Errorf("Cwes: got %d, want 2", len(advisory.Cwes))
	}
}

func TestStatsFields(t *testing.T) {
	// Stats is already a proto type (vulnerabilityv1.Stats).
	// Test that the proto fields work correctly.
	stats := &vulnerabilityv1.Stats{
		Total:    100,
		Critical: 5,
		High:     20,
		Medium:   30,
		Low:      40,
		Unknown:  5,
	}

	if stats.Total != 100 {
		t.Errorf("Total: got %v, want 100", stats.Total)
	}
	if stats.Critical != 5 {
		t.Errorf("Critical: got %v, want 5", stats.Critical)
	}
	if stats.High != 20 {
		t.Errorf("High: got %v, want 20", stats.High)
	}
	if stats.Medium != 30 {
		t.Errorf("Medium: got %v, want 30", stats.Medium)
	}
	if stats.Low != 40 {
		t.Errorf("Low: got %v, want 40", stats.Low)
	}
	if stats.Unknown != 5 {
		t.Errorf("Unknown: got %v, want 5", stats.Unknown)
	}
}

func TestNilProtoHandling(t *testing.T) {
	// Test that nil pointers to proto types have zero values
	t.Run("nil Advisory", func(t *testing.T) {
		var advisory *vulnerabilityv1.Advisory
		if advisory != nil {
			t.Error("expected nil Advisory")
		}
	})

	t.Run("nil Stats", func(t *testing.T) {
		var stats *vulnerabilityv1.Stats
		if stats != nil {
			t.Error("expected nil Stats")
		}
	})
}

func TestEmptySlices(t *testing.T) {
	t.Run("ManifestRefsToProto", func(t *testing.T) {
		result := ManifestRefsToProto(nil)
		if result != nil {
			t.Error("expected nil for empty slice")
		}
		result = ManifestRefsToProto([]dependencyv1.ManifestRef{})
		if result != nil {
			t.Error("expected nil for empty slice")
		}
	})

	t.Run("AffectedImportsToProto", func(t *testing.T) {
		result := AffectedImportsToProto(nil)
		if result != nil {
			t.Error("expected nil for empty slice")
		}
	})
}

func TestProtoEnumValues(t *testing.T) {
	// Verify proto enum values match expected constants
	if targetv1.TargetKind_TARGET_KIND_DIR != 1 {
		t.Error("TARGET_KIND_DIR should be 1")
	}
	if vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL != 4 {
		t.Error("SEVERITY_LEVEL_CRITICAL should be 4")
	}
	if vulnerabilityv1.SeverityType_SEVERITY_TYPE_CVSS_V3 != 2 {
		t.Error("SEVERITY_TYPE_CVSS_V3 should be 2")
	}
}

func TestManifestRefsToProto(t *testing.T) {
	tests := []struct {
		name string
		refs []dependencyv1.ManifestRef
		want []*dependencyv1.ManifestRef
	}{
		{
			name: "nil refs",
			refs: nil,
			want: nil,
		},
		{
			name: "empty refs",
			refs: []dependencyv1.ManifestRef{},
			want: nil,
		},
		{
			name: "single ref",
			refs: []dependencyv1.ManifestRef{
				{Path: "package.json", Manager: "npm"},
			},
			want: []*dependencyv1.ManifestRef{
				{Path: "package.json", Manager: "npm"},
			},
		},
		{
			name: "multiple refs with groups",
			refs: []dependencyv1.ManifestRef{
				{Path: "package.json", Manager: "npm", Groups: []string{"dependencies"}},
				{Path: "go.mod", Manager: "go", Groups: []string{"require"}},
			},
			want: []*dependencyv1.ManifestRef{
				{Path: "package.json", Manager: "npm", Groups: []string{"dependencies"}},
				{Path: "go.mod", Manager: "go", Groups: []string{"require"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ManifestRefsToProto(tt.refs)
			if len(got) != len(tt.want) {
				t.Errorf("ManifestRefsToProto() length = %d, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i].Path != tt.want[i].Path {
					t.Errorf("[%d] Path = %q, want %q", i, got[i].Path, tt.want[i].Path)
				}
				if got[i].Manager != tt.want[i].Manager {
					t.Errorf("[%d] Manager = %q, want %q", i, got[i].Manager, tt.want[i].Manager)
				}
			}
		})
	}
}

func TestManifestRefsFromProto(t *testing.T) {
	tests := []struct {
		name string
		refs []*dependencyv1.ManifestRef
		want []dependencyv1.ManifestRef
	}{
		{
			name: "nil refs",
			refs: nil,
			want: nil,
		},
		{
			name: "empty refs",
			refs: []*dependencyv1.ManifestRef{},
			want: nil,
		},
		{
			name: "single ref",
			refs: []*dependencyv1.ManifestRef{
				{Path: "package.json", Manager: "npm"},
			},
			want: []dependencyv1.ManifestRef{
				{Path: "package.json", Manager: "npm"},
			},
		},
		{
			name: "refs with nil element",
			refs: []*dependencyv1.ManifestRef{
				{Path: "package.json", Manager: "npm"},
				nil,
				{Path: "go.mod", Manager: "go"},
			},
			want: []dependencyv1.ManifestRef{
				{Path: "package.json", Manager: "npm"},
				{}, // nil becomes zero value
				{Path: "go.mod", Manager: "go"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ManifestRefsFromProto(tt.refs)
			if len(got) != len(tt.want) {
				t.Errorf("ManifestRefsFromProto() length = %d, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i].Path != tt.want[i].Path {
					t.Errorf("[%d] Path = %q, want %q", i, got[i].Path, tt.want[i].Path)
				}
			}
		})
	}
}

func TestManifestRefsRoundTrip(t *testing.T) {
	original := []dependencyv1.ManifestRef{
		{Path: "package.json", Manager: "npm", Groups: []string{"dependencies", "devDependencies"}},
		{Path: "go.mod", Manager: "go", Groups: []string{"require"}},
	}

	proto := ManifestRefsToProto(original)
	roundTripped := ManifestRefsFromProto(proto)

	if len(roundTripped) != len(original) {
		t.Fatalf("length mismatch: got %d, want %d", len(roundTripped), len(original))
	}

	for i := range original {
		if roundTripped[i].Path != original[i].Path {
			t.Errorf("[%d] Path: got %q, want %q", i, roundTripped[i].Path, original[i].Path)
		}
		if roundTripped[i].Manager != original[i].Manager {
			t.Errorf("[%d] Manager: got %q, want %q", i, roundTripped[i].Manager, original[i].Manager)
		}
		if len(roundTripped[i].Groups) != len(original[i].Groups) {
			t.Errorf("[%d] Groups length: got %d, want %d", i, len(roundTripped[i].Groups), len(original[i].Groups))
		}
	}
}

func TestAffectedImportsToProto(t *testing.T) {
	tests := []struct {
		name    string
		imports []vulnerabilityv1.AffectedImport
		wantLen int
	}{
		{
			name:    "nil imports",
			imports: nil,
			wantLen: 0,
		},
		{
			name:    "empty imports",
			imports: []vulnerabilityv1.AffectedImport{},
			wantLen: 0,
		},
		{
			name: "single import",
			imports: []vulnerabilityv1.AffectedImport{
				{Path: "net/http", Symbols: []string{"Get", "Post"}},
			},
			wantLen: 1,
		},
		{
			name: "multiple imports",
			imports: []vulnerabilityv1.AffectedImport{
				{Path: "net/http", Symbols: []string{"Get"}},
				{Path: "crypto/tls", Symbols: []string{"Dial"}},
			},
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AffectedImportsToProto(tt.imports)
			if tt.wantLen == 0 && got != nil {
				t.Error("expected nil for empty/nil imports")
				return
			}
			if len(got) != tt.wantLen {
				t.Errorf("AffectedImportsToProto() length = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestAffectedImportsFromProto(t *testing.T) {
	tests := []struct {
		name    string
		imports []*vulnerabilityv1.AffectedImport
		wantLen int
	}{
		{
			name:    "nil imports",
			imports: nil,
			wantLen: 0,
		},
		{
			name:    "empty imports",
			imports: []*vulnerabilityv1.AffectedImport{},
			wantLen: 0,
		},
		{
			name: "single import",
			imports: []*vulnerabilityv1.AffectedImport{
				{Path: "net/http", Symbols: []string{"Get", "Post"}},
			},
			wantLen: 1,
		},
		{
			name: "imports with nil element",
			imports: []*vulnerabilityv1.AffectedImport{
				{Path: "net/http", Symbols: []string{"Get"}},
				nil,
			},
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AffectedImportsFromProto(tt.imports)
			if tt.wantLen == 0 && got != nil {
				t.Error("expected nil for empty/nil imports")
				return
			}
			if len(got) != tt.wantLen {
				t.Errorf("AffectedImportsFromProto() length = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestAffectedImportsRoundTrip(t *testing.T) {
	original := []vulnerabilityv1.AffectedImport{
		{Path: "net/http", Symbols: []string{"Get", "Post", "Client"}},
		{Path: "crypto/tls", Symbols: []string{"Dial", "Client"}},
	}

	proto := AffectedImportsToProto(original)
	roundTripped := AffectedImportsFromProto(proto)

	if len(roundTripped) != len(original) {
		t.Fatalf("length mismatch: got %d, want %d", len(roundTripped), len(original))
	}

	for i := range original {
		if roundTripped[i].Path != original[i].Path {
			t.Errorf("[%d] Path: got %q, want %q", i, roundTripped[i].Path, original[i].Path)
		}
		if len(roundTripped[i].Symbols) != len(original[i].Symbols) {
			t.Errorf("[%d] Symbols length: got %d, want %d", i, len(roundTripped[i].Symbols), len(original[i].Symbols))
		}
	}
}
