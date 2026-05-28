package proto

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"

	containerv1 "github.com/temporalio/deputy/gen/deputy/container/v1"
	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	targetv1 "github.com/temporalio/deputy/gen/deputy/target/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/container/image"
	"github.com/temporalio/deputy/internal/dependency"
	"github.com/temporalio/deputy/internal/dockerfile"
	"github.com/temporalio/deputy/internal/inventory"
	"github.com/temporalio/deputy/internal/policy"
	"github.com/temporalio/deputy/internal/scanning"
	"github.com/temporalio/deputy/internal/targets"
	"github.com/temporalio/deputy/internal/vulnerability"
)

func TestPackageToProto(t *testing.T) {
	tests := []struct {
		name    string
		finding vulnerability.Finding
		want    *dependencyv1.Package
	}{
		{
			name:    "empty finding",
			finding: vulnerability.Finding{},
			want: &dependencyv1.Package{
				Name:      "",
				Ecosystem: "",
				Purl:      "",
				Version:   "",
				Direct:    false,
			},
		},
		{
			name: "full finding with all fields",
			finding: vulnerability.Finding{
				Dependency: dependency.ID{
					Name:      "lodash",
					Ecosystem: "npm",
					PURL:      "pkg:npm/lodash@4.17.21",
				},
				Version:   "4.17.21",
				Direct:    true,
				Locations: []string{"package-lock.json"},
				ManifestRefs: []dependencyv1.ManifestRef{
					{Path: "package.json", Manager: "npm"},
				},
				LayerDetails: &containerv1.LayerDetails{
					Index:   1,
					DiffId:  "sha256:abc123",
					ChainId: "sha256:def456",
					Command: "RUN npm install",
				},
			},
			want: &dependencyv1.Package{
				Name:      "lodash",
				Ecosystem: "npm",
				Purl:      "pkg:npm/lodash@4.17.21",
				Version:   "4.17.21",
				Direct:    true,
				Locations: []string{"package-lock.json"},
				ManifestRefs: []*dependencyv1.ManifestRef{
					{Path: "package.json", Manager: "npm"},
				},
				LayerDetails: &containerv1.LayerDetails{
					Index:   1,
					DiffId:  "sha256:abc123",
					ChainId: "sha256:def456",
					Command: "RUN npm install",
				},
			},
		},
		{
			name: "go package",
			finding: vulnerability.Finding{
				Dependency: dependency.ID{
					Name:      "golang.org/x/crypto",
					Ecosystem: "Go",
					PURL:      "pkg:golang/golang.org/x/crypto@v0.17.0",
				},
				Version: "v0.17.0",
				Direct:  false,
			},
			want: &dependencyv1.Package{
				Name:      "golang.org/x/crypto",
				Ecosystem: "Go",
				Purl:      "pkg:golang/golang.org/x/crypto@v0.17.0",
				Version:   "v0.17.0",
				Direct:    false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PackageToProto(tt.finding)
			if diff := cmp.Diff(tt.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("PackageToProto() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFindingToProto(t *testing.T) {
	epss := 0.75
	epssPercentile := 0.95
	inKEV := true

	tests := []struct {
		name     string
		finding  vulnerability.Finding
		advisory *vulnerabilityv1.Advisory
		want     *vulnerabilityv1.Finding
	}{
		{
			name:     "nil advisory",
			finding:  vulnerability.Finding{AdvisoryID: "CVE-2021-44228"},
			advisory: nil,
			want: &vulnerabilityv1.Finding{
				AdvisoryId: "CVE-2021-44228",
				Package:    &dependencyv1.Package{},
			},
		},
		{
			name: "with advisory",
			finding: vulnerability.Finding{
				AdvisoryID: "CVE-2021-44228",
				Affected:   true,
			},
			advisory: &vulnerabilityv1.Advisory{
				Id:      "CVE-2021-44228",
				Summary: "Log4Shell",
			},
			want: &vulnerabilityv1.Finding{
				AdvisoryId: "CVE-2021-44228",
				Package:    &dependencyv1.Package{},
				Affected:   true,
				Advisory: &vulnerabilityv1.Advisory{
					Id:      "CVE-2021-44228",
					Summary: "Log4Shell",
				},
			},
		},
		{
			name: "with enrichment fields",
			finding: vulnerability.Finding{
				AdvisoryID:     "CVE-2021-44228",
				EPSS:           &epss,
				EPSSPercentile: &epssPercentile,
				InKEV:          &inKEV,
			},
			advisory: nil,
			want: &vulnerabilityv1.Finding{
				AdvisoryId:     "CVE-2021-44228",
				Package:        &dependencyv1.Package{},
				Epss:           &epss,
				EpssPercentile: &epssPercentile,
				InKev:          &inKEV,
			},
		},
		{
			name: "with affected imports",
			finding: vulnerability.Finding{
				AdvisoryID: "GO-2024-2687",
				AffectedImports: []vulnerabilityv1.AffectedImport{
					{Path: "net/http", Symbols: []string{"Get", "Post"}},
				},
			},
			advisory: nil,
			want: &vulnerabilityv1.Finding{
				AdvisoryId: "GO-2024-2687",
				Package:    &dependencyv1.Package{},
				AffectedImports: []*vulnerabilityv1.AffectedImport{
					{Path: "net/http", Symbols: []string{"Get", "Post"}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FindingToProto(tt.finding, tt.advisory)
			if diff := cmp.Diff(tt.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("FindingToProto() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFindingFromProto(t *testing.T) {
	epss := 0.75
	epssPercentile := 0.95
	inKEV := true

	tests := []struct {
		name  string
		proto *vulnerabilityv1.Finding
		want  vulnerability.Finding
	}{
		{
			name:  "nil proto",
			proto: nil,
			want:  vulnerability.Finding{},
		},
		{
			name: "empty proto",
			proto: &vulnerabilityv1.Finding{
				AdvisoryId: "",
			},
			want: vulnerability.Finding{},
		},
		{
			name: "full proto",
			proto: &vulnerabilityv1.Finding{
				AdvisoryId: "CVE-2021-44228",
				Package: &dependencyv1.Package{
					Name:      "log4j",
					Ecosystem: "Maven",
					Purl:      "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
					Version:   "2.14.0",
					Direct:    true,
					Locations: []string{"pom.xml"},
					ManifestRefs: []*dependencyv1.ManifestRef{
						{Path: "pom.xml", Manager: "maven"},
					},
					LayerDetails: &containerv1.LayerDetails{
						Index:       2,
						DiffId:      "sha256:abc",
						ChainId:     "sha256:def",
						Command:     "COPY target/app.jar /app/",
						InBaseImage: false,
					},
				},
				Affected: true,
				AffectedImports: []*vulnerabilityv1.AffectedImport{
					{Path: "org.apache.logging.log4j.core.lookup.JndiLookup", Symbols: []string{"lookup"}},
				},
				Epss:           &epss,
				EpssPercentile: &epssPercentile,
				InKev:          &inKEV,
			},
			want: vulnerability.Finding{
				AdvisoryID: "CVE-2021-44228",
				Dependency: dependency.ID{
					Name:      "log4j",
					Ecosystem: "Maven",
					PURL:      "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
				},
				Version:   "2.14.0",
				Direct:    true,
				Locations: []string{"pom.xml"},
				ManifestRefs: []dependencyv1.ManifestRef{
					{Path: "pom.xml", Manager: "maven"},
				},
				LayerDetails: &containerv1.LayerDetails{
					Index:       2,
					DiffId:      "sha256:abc",
					ChainId:     "sha256:def",
					Command:     "COPY target/app.jar /app/",
					InBaseImage: false,
				},
				Affected: true,
				AffectedImports: []vulnerabilityv1.AffectedImport{
					{Path: "org.apache.logging.log4j.core.lookup.JndiLookup", Symbols: []string{"lookup"}},
				},
				EPSS:           &epss,
				EPSSPercentile: &epssPercentile,
				InKEV:          &inKEV,
			},
		},
		{
			name: "nil package",
			proto: &vulnerabilityv1.Finding{
				AdvisoryId: "CVE-2021-44228",
				Package:    nil,
			},
			want: vulnerability.Finding{
				AdvisoryID: "CVE-2021-44228",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FindingFromProto(tt.proto)
			if diff := cmp.Diff(tt.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("FindingFromProto() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFindingRoundTrip(t *testing.T) {
	epss := 0.85
	epssPercentile := 0.99
	inKEV := true

	original := vulnerability.Finding{
		AdvisoryID: "CVE-2021-44228",
		Dependency: dependency.ID{
			Name:      "lodash",
			Ecosystem: "npm",
			PURL:      "pkg:npm/lodash@4.17.20",
		},
		Version:   "4.17.20",
		Direct:    true,
		Locations: []string{"package-lock.json", "yarn.lock"},
		ManifestRefs: []dependencyv1.ManifestRef{
			{Path: "package.json", Manager: "npm", Groups: []string{"dependencies"}},
		},
		LayerDetails: &containerv1.LayerDetails{
			Index:       1,
			DiffId:      "sha256:abc123",
			ChainId:     "sha256:def456",
			Command:     "RUN npm install",
			InBaseImage: true,
		},
		Affected: true,
		AffectedImports: []vulnerabilityv1.AffectedImport{
			{Path: "lodash/template", Symbols: []string{"template"}},
		},
		EPSS:           &epss,
		EPSSPercentile: &epssPercentile,
		InKEV:          &inKEV,
	}

	// Convert to proto
	proto := FindingToProto(original, nil)

	// Convert back
	roundTripped := FindingFromProto(proto)

	// Compare - note that some fields are expected to match
	if roundTripped.AdvisoryID != original.AdvisoryID {
		t.Errorf("AdvisoryID: got %q, want %q", roundTripped.AdvisoryID, original.AdvisoryID)
	}
	if roundTripped.Dependency.Name != original.Dependency.Name {
		t.Errorf("Dependency.Name: got %q, want %q", roundTripped.Dependency.Name, original.Dependency.Name)
	}
	if roundTripped.Dependency.Ecosystem != original.Dependency.Ecosystem {
		t.Errorf("Dependency.Ecosystem: got %q, want %q", roundTripped.Dependency.Ecosystem, original.Dependency.Ecosystem)
	}
	if roundTripped.Version != original.Version {
		t.Errorf("Version: got %q, want %q", roundTripped.Version, original.Version)
	}
	if roundTripped.Direct != original.Direct {
		t.Errorf("Direct: got %v, want %v", roundTripped.Direct, original.Direct)
	}
	if roundTripped.Affected != original.Affected {
		t.Errorf("Affected: got %v, want %v", roundTripped.Affected, original.Affected)
	}
	if *roundTripped.EPSS != *original.EPSS {
		t.Errorf("EPSS: got %v, want %v", *roundTripped.EPSS, *original.EPSS)
	}
	if *roundTripped.InKEV != *original.InKEV {
		t.Errorf("InKEV: got %v, want %v", *roundTripped.InKEV, *original.InKEV)
	}
	if len(roundTripped.Locations) != len(original.Locations) {
		t.Errorf("Locations length: got %d, want %d", len(roundTripped.Locations), len(original.Locations))
	}
	if len(roundTripped.ManifestRefs) != len(original.ManifestRefs) {
		t.Errorf("ManifestRefs length: got %d, want %d", len(roundTripped.ManifestRefs), len(original.ManifestRefs))
	}
	if roundTripped.LayerDetails == nil {
		t.Error("LayerDetails: expected non-nil")
	} else if roundTripped.LayerDetails.Index != original.LayerDetails.Index {
		t.Errorf("LayerDetails.Index: got %d, want %d", roundTripped.LayerDetails.Index, original.LayerDetails.Index)
	}
}

func TestFindingsToProto(t *testing.T) {
	tests := []struct {
		name       string
		findings   []vulnerability.Finding
		advisories map[string]*vulnerabilityv1.Advisory
		wantLen    int
	}{
		{
			name:       "nil findings",
			findings:   nil,
			advisories: nil,
			wantLen:    0,
		},
		{
			name:       "empty findings",
			findings:   []vulnerability.Finding{},
			advisories: nil,
			wantLen:    0,
		},
		{
			name: "single finding",
			findings: []vulnerability.Finding{
				{AdvisoryID: "CVE-2021-44228"},
			},
			advisories: map[string]*vulnerabilityv1.Advisory{
				"CVE-2021-44228": {Id: "CVE-2021-44228", Summary: "Log4Shell"},
			},
			wantLen: 1,
		},
		{
			name: "multiple findings",
			findings: []vulnerability.Finding{
				{AdvisoryID: "CVE-2021-44228"},
				{AdvisoryID: "CVE-2022-22965"},
				{AdvisoryID: "CVE-2021-45046"},
			},
			advisories: map[string]*vulnerabilityv1.Advisory{
				"CVE-2021-44228": {Id: "CVE-2021-44228"},
			},
			wantLen: 3,
		},
		{
			name: "findings with missing advisories",
			findings: []vulnerability.Finding{
				{AdvisoryID: "CVE-2021-44228"},
				{AdvisoryID: "CVE-MISSING"},
			},
			advisories: map[string]*vulnerabilityv1.Advisory{
				"CVE-2021-44228": {Id: "CVE-2021-44228"},
			},
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FindingsToProto(tt.findings, tt.advisories)
			if len(got) != tt.wantLen {
				t.Errorf("FindingsToProto() length = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestFindingsFromProto(t *testing.T) {
	tests := []struct {
		name     string
		findings []*vulnerabilityv1.Finding
		wantLen  int
	}{
		{
			name:     "nil findings",
			findings: nil,
			wantLen:  0,
		},
		{
			name:     "empty findings",
			findings: []*vulnerabilityv1.Finding{},
			wantLen:  0,
		},
		{
			name: "single finding",
			findings: []*vulnerabilityv1.Finding{
				{AdvisoryId: "CVE-2021-44228"},
			},
			wantLen: 1,
		},
		{
			name: "multiple findings including nil",
			findings: []*vulnerabilityv1.Finding{
				{AdvisoryId: "CVE-2021-44228"},
				nil,
				{AdvisoryId: "CVE-2022-22965"},
			},
			wantLen: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FindingsFromProto(tt.findings)
			if len(got) != tt.wantLen {
				t.Errorf("FindingsFromProto() length = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestFindingsRoundTrip(t *testing.T) {
	original := []vulnerability.Finding{
		{
			AdvisoryID: "CVE-2021-44228",
			Dependency: dependency.ID{Name: "log4j", Ecosystem: "Maven"},
			Version:    "2.14.0",
			Direct:     true,
		},
		{
			AdvisoryID: "CVE-2022-22965",
			Dependency: dependency.ID{Name: "spring-core", Ecosystem: "Maven"},
			Version:    "5.3.17",
			Direct:     false,
		},
	}
	advisories := map[string]*vulnerabilityv1.Advisory{
		"CVE-2021-44228": {Id: "CVE-2021-44228", Summary: "Log4Shell"},
		"CVE-2022-22965": {Id: "CVE-2022-22965", Summary: "Spring4Shell"},
	}

	proto := FindingsToProto(original, advisories)
	roundTripped := FindingsFromProto(proto)

	if len(roundTripped) != len(original) {
		t.Fatalf("length mismatch: got %d, want %d", len(roundTripped), len(original))
	}

	for i := range original {
		if roundTripped[i].AdvisoryID != original[i].AdvisoryID {
			t.Errorf("[%d] AdvisoryID: got %q, want %q", i, roundTripped[i].AdvisoryID, original[i].AdvisoryID)
		}
		if roundTripped[i].Dependency.Name != original[i].Dependency.Name {
			t.Errorf("[%d] Dependency.Name: got %q, want %q", i, roundTripped[i].Dependency.Name, original[i].Dependency.Name)
		}
	}
}

func TestAdvisoriesToProto(t *testing.T) {
	tests := []struct {
		name       string
		advisories map[string]*vulnerabilityv1.Advisory
	}{
		{
			name:       "nil advisories",
			advisories: nil,
		},
		{
			name:       "empty advisories",
			advisories: map[string]*vulnerabilityv1.Advisory{},
		},
		{
			name: "single advisory",
			advisories: map[string]*vulnerabilityv1.Advisory{
				"CVE-2021-44228": {Id: "CVE-2021-44228"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AdvisoriesToProto(tt.advisories)
			if diff := cmp.Diff(tt.advisories, got, protocmp.Transform()); diff != "" {
				t.Errorf("AdvisoriesToProto() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAdvisoriesFromProto(t *testing.T) {
	tests := []struct {
		name       string
		advisories map[string]*vulnerabilityv1.Advisory
	}{
		{
			name:       "nil advisories",
			advisories: nil,
		},
		{
			name:       "empty advisories",
			advisories: map[string]*vulnerabilityv1.Advisory{},
		},
		{
			name: "single advisory",
			advisories: map[string]*vulnerabilityv1.Advisory{
				"CVE-2021-44228": {Id: "CVE-2021-44228"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AdvisoriesFromProto(tt.advisories)
			if diff := cmp.Diff(tt.advisories, got, protocmp.Transform()); diff != "" {
				t.Errorf("AdvisoriesFromProto() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestStatsToProto(t *testing.T) {
	tests := []struct {
		name  string
		stats vulnerabilityv1.Stats
		want  *vulnerabilityv1.Stats
	}{
		{
			name:  "zero stats",
			stats: vulnerabilityv1.Stats{},
			want:  &vulnerabilityv1.Stats{},
		},
		{
			name: "full stats",
			stats: vulnerabilityv1.Stats{
				Total:        100,
				Unique:       75,
				Critical:     5,
				High:         20,
				Medium:       30,
				Low:          15,
				Unknown:      5,
				FixAvailable: 60,
				DirectDeps:   25,
				IndirectDeps: 50,
			},
			want: &vulnerabilityv1.Stats{
				Total:        100,
				Unique:       75,
				Critical:     5,
				High:         20,
				Medium:       30,
				Low:          15,
				Unknown:      5,
				FixAvailable: 60,
				DirectDeps:   25,
				IndirectDeps: 50,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StatsToProto(tt.stats)
			if diff := cmp.Diff(tt.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("StatsToProto() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestStatsFromProto(t *testing.T) {
	tests := []struct {
		name  string
		stats *vulnerabilityv1.Stats
		want  vulnerabilityv1.Stats
	}{
		{
			name:  "nil stats",
			stats: nil,
			want:  vulnerabilityv1.Stats{},
		},
		{
			name:  "empty stats",
			stats: &vulnerabilityv1.Stats{},
			want:  vulnerabilityv1.Stats{},
		},
		{
			name: "full stats",
			stats: &vulnerabilityv1.Stats{
				Total:        100,
				Unique:       75,
				Critical:     5,
				High:         20,
				Medium:       30,
				Low:          15,
				Unknown:      5,
				FixAvailable: 60,
				DirectDeps:   25,
				IndirectDeps: 50,
			},
			want: vulnerabilityv1.Stats{
				Total:        100,
				Unique:       75,
				Critical:     5,
				High:         20,
				Medium:       30,
				Low:          15,
				Unknown:      5,
				FixAvailable: 60,
				DirectDeps:   25,
				IndirectDeps: 50,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StatsFromProto(tt.stats)
			if diff := cmp.Diff(tt.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("StatsFromProto() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestStatsRoundTrip(t *testing.T) {
	original := vulnerabilityv1.Stats{
		Total:        100,
		Unique:       75,
		Critical:     5,
		High:         20,
		Medium:       30,
		Low:          15,
		Unknown:      5,
		FixAvailable: 60,
		DirectDeps:   25,
		IndirectDeps: 50,
	}

	proto := StatsToProto(original)
	roundTripped := StatsFromProto(proto)

	if diff := cmp.Diff(original, roundTripped, protocmp.Transform()); diff != "" {
		t.Errorf("Stats round trip mismatch (-want +got):\n%s", diff)
	}
}

func TestScanningResultToProto(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	tests := []struct {
		name   string
		result *scanning.Result
		check  func(*testing.T, *scanv1.ScanResponse)
	}{
		{
			name:   "nil result",
			result: nil,
			check: func(t *testing.T, got *scanv1.ScanResponse) {
				if got != nil {
					t.Error("expected nil response for nil result")
				}
			},
		},
		{
			name: "empty result",
			result: &scanning.Result{
				GeneratedAt: now,
			},
			check: func(t *testing.T, got *scanv1.ScanResponse) {
				if got == nil {
					t.Fatal("expected non-nil response")
				}
				if got.PackagesScanned != 0 {
					t.Errorf("PackagesScanned: got %d, want 0", got.PackagesScanned)
				}
			},
		},
		{
			name: "result with target",
			result: &scanning.Result{
				Target: inventory.Target{
					Kind:        targets.KindGit,
					DisplayPath: "github.com/example/repo",
					LocalPath:   "/tmp/repo",
					Ref:         "main",
					CommitHash:  "abc123",
				},
				PackagesScanned: 50,
				GeneratedAt:     now,
			},
			check: func(t *testing.T, got *scanv1.ScanResponse) {
				if got.Target == nil {
					t.Fatal("expected non-nil target")
				}
				if got.Target.Kind != targetv1.TargetKind_TARGET_KIND_GIT {
					t.Errorf("Target.Kind: got %v, want GIT", got.Target.Kind)
				}
				if got.Target.DisplayPath != "github.com/example/repo" {
					t.Errorf("Target.DisplayPath: got %q", got.Target.DisplayPath)
				}
				if got.PackagesScanned != 50 {
					t.Errorf("PackagesScanned: got %d, want 50", got.PackagesScanned)
				}
			},
		},
		{
			name: "result with findings",
			result: &scanning.Result{
				Findings: []vulnerability.Finding{
					{AdvisoryID: "CVE-2021-44228", Dependency: dependency.ID{Name: "log4j"}},
				},
				Advisories: map[string]*vulnerabilityv1.Advisory{
					"CVE-2021-44228": {
						Id: "CVE-2021-44228",
						Severity: &vulnerabilityv1.Severity{
							Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL,
						},
					},
				},
				GeneratedAt: now,
			},
			check: func(t *testing.T, got *scanv1.ScanResponse) {
				if len(got.Findings) != 1 {
					t.Errorf("Findings length: got %d, want 1", len(got.Findings))
				}
				if got.Stats == nil {
					t.Error("expected non-nil stats")
				}
			},
		},
		{
			name: "result with image info",
			result: &scanning.Result{
				ImageInfo: &image.Info{
					Config: image.Config{
						User:       "nobody",
						Entrypoint: []string{"/app"},
					},
					Metadata: image.Metadata{
						Architecture: "amd64",
						OS:           "linux",
						LayerCount:   5,
					},
				},
				GeneratedAt: now,
			},
			check: func(t *testing.T, got *scanv1.ScanResponse) {
				if got.ImageInfo == nil {
					t.Fatal("expected non-nil ImageInfo")
				}
				if got.ImageInfo.Config == nil {
					t.Fatal("expected non-nil ImageInfo.Config")
				}
				if got.ImageInfo.Config.User != "nobody" {
					t.Errorf("ImageInfo.Config.User: got %q", got.ImageInfo.Config.User)
				}
			},
		},
		{
			name: "result with dockerfile info",
			result: &scanning.Result{
				DockerfileInfo: &dockerfile.Info{
					Path: "/app/Dockerfile",
					Stages: []dockerfile.Stage{
						{Index: 0, Name: "builder", BaseImage: "golang:1.21"},
					},
				},
				DockerfileAnalysis: &dockerfile.Analysis{
					StageCount:    2,
					HasMultiStage: true,
				},
				GeneratedAt: now,
			},
			check: func(t *testing.T, got *scanv1.ScanResponse) {
				if got.DockerfileInfo == nil {
					t.Fatal("expected non-nil DockerfileInfo")
				}
				if got.DockerfileInfo.Path != "/app/Dockerfile" {
					t.Errorf("DockerfileInfo.Path: got %q", got.DockerfileInfo.Path)
				}
				if got.DockerfileInfo.Analysis == nil {
					t.Error("expected non-nil DockerfileInfo.Analysis")
				}
			},
		},
		{
			name: "result with warnings",
			result: &scanning.Result{
				Warnings:    []string{"warning1", "warning2"},
				GeneratedAt: now,
			},
			check: func(t *testing.T, got *scanv1.ScanResponse) {
				if len(got.Warnings) != 2 {
					t.Errorf("Warnings length: got %d, want 2", len(got.Warnings))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ScanningResultToProto(tt.result)
			tt.check(t, got)
		})
	}
}

func TestScanningResultFromProto(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	tests := []struct {
		name  string
		proto *scanv1.ScanResponse
		check func(*testing.T, *scanning.Result)
	}{
		{
			name:  "nil response",
			proto: nil,
			check: func(t *testing.T, got *scanning.Result) {
				if got != nil {
					t.Error("expected nil result for nil response")
				}
			},
		},
		{
			name:  "empty response",
			proto: &scanv1.ScanResponse{},
			check: func(t *testing.T, got *scanning.Result) {
				if got == nil {
					t.Fatal("expected non-nil result")
				}
				if got.PackagesScanned != 0 {
					t.Errorf("PackagesScanned: got %d, want 0", got.PackagesScanned)
				}
			},
		},
		{
			name: "response with target",
			proto: &scanv1.ScanResponse{
				Target: &targetv1.Target{
					Kind:        targetv1.TargetKind_TARGET_KIND_GIT,
					DisplayPath: "github.com/example/repo",
					LocalPath:   "/tmp/repo",
					Ref:         "main",
					CommitHash:  "abc123",
				},
				PackagesScanned: 50,
				GeneratedAt:     timestamppb.New(now),
			},
			check: func(t *testing.T, got *scanning.Result) {
				if got.Target.Kind != targets.KindGit {
					t.Errorf("Target.Kind: got %v, want Git", got.Target.Kind)
				}
				if got.Target.DisplayPath != "github.com/example/repo" {
					t.Errorf("Target.DisplayPath: got %q", got.Target.DisplayPath)
				}
				if got.PackagesScanned != 50 {
					t.Errorf("PackagesScanned: got %d, want 50", got.PackagesScanned)
				}
			},
		},
		{
			name: "response with findings",
			proto: &scanv1.ScanResponse{
				Findings: []*vulnerabilityv1.Finding{
					{
						AdvisoryId: "CVE-2021-44228",
						Package:    &dependencyv1.Package{Name: "log4j"},
					},
				},
				Advisories: map[string]*vulnerabilityv1.Advisory{
					"CVE-2021-44228": {Id: "CVE-2021-44228"},
				},
				Stats: &vulnerabilityv1.Stats{
					Total:    1,
					Critical: 1,
				},
			},
			check: func(t *testing.T, got *scanning.Result) {
				if len(got.Findings) != 1 {
					t.Errorf("Findings length: got %d, want 1", len(got.Findings))
				}
				if got.Stats.Total != 1 {
					t.Errorf("Stats.Total: got %d, want 1", got.Stats.Total)
				}
			},
		},
		{
			name: "response with image info",
			proto: &scanv1.ScanResponse{
				ImageInfo: &scanv1.ImageInfo{
					Config: &scanv1.ImageConfig{
						User: "nobody",
					},
					Metadata: &scanv1.ImageMetadata{
						Architecture: "amd64",
						Os:           "linux",
					},
				},
			},
			check: func(t *testing.T, got *scanning.Result) {
				if got.ImageInfo == nil {
					t.Fatal("expected non-nil ImageInfo")
				}
				if got.ImageInfo.Config.User != "nobody" {
					t.Errorf("ImageInfo.Config.User: got %q", got.ImageInfo.Config.User)
				}
			},
		},
		{
			name: "response with warnings",
			proto: &scanv1.ScanResponse{
				Warnings: []string{"warning1", "warning2"},
			},
			check: func(t *testing.T, got *scanning.Result) {
				if len(got.Warnings) != 2 {
					t.Errorf("Warnings length: got %d, want 2", len(got.Warnings))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ScanningResultFromProto(tt.proto)
			tt.check(t, got)
		})
	}
}

func TestScanningResultRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	original := &scanning.Result{
		Target: inventory.Target{
			Kind:        targets.KindGit,
			DisplayPath: "github.com/example/repo",
			LocalPath:   "/tmp/repo",
			Ref:         "v1.0.0",
			CommitHash:  "abc123def456",
			OriginURL:   "https://github.com/example/repo.git",
			Cloned:      true,
		},
		PackagesScanned: 100,
		Findings: []vulnerability.Finding{
			{
				AdvisoryID: "CVE-2021-44228",
				Dependency: dependency.ID{Name: "log4j", Ecosystem: "Maven"},
				Version:    "2.14.0",
				Direct:     true,
			},
		},
		Advisories: map[string]*vulnerabilityv1.Advisory{
			"CVE-2021-44228": {
				Id:      "CVE-2021-44228",
				Summary: "Log4Shell",
				Severity: &vulnerabilityv1.Severity{
					Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL,
				},
			},
		},
		Warnings:    []string{"some warning"},
		GeneratedAt: now,
	}

	proto := ScanningResultToProto(original)
	roundTripped := ScanningResultFromProto(proto)

	// Verify key fields survived the round trip
	if roundTripped.Target.DisplayPath != original.Target.DisplayPath {
		t.Errorf("Target.DisplayPath: got %q, want %q", roundTripped.Target.DisplayPath, original.Target.DisplayPath)
	}
	if roundTripped.PackagesScanned != original.PackagesScanned {
		t.Errorf("PackagesScanned: got %d, want %d", roundTripped.PackagesScanned, original.PackagesScanned)
	}
	if len(roundTripped.Findings) != len(original.Findings) {
		t.Errorf("Findings length: got %d, want %d", len(roundTripped.Findings), len(original.Findings))
	}
	if len(roundTripped.Advisories) != len(original.Advisories) {
		t.Errorf("Advisories length: got %d, want %d", len(roundTripped.Advisories), len(original.Advisories))
	}
	if len(roundTripped.Warnings) != len(original.Warnings) {
		t.Errorf("Warnings length: got %d, want %d", len(roundTripped.Warnings), len(original.Warnings))
	}
}

func TestPolicyActionsToProto(t *testing.T) {
	tests := []struct {
		name    string
		actions []policy.Action
		wantLen int
	}{
		{
			name:    "nil actions",
			actions: nil,
			wantLen: 0,
		},
		{
			name:    "empty actions",
			actions: []policy.Action{},
			wantLen: 0,
		},
		{
			name: "single deny action",
			actions: []policy.Action{
				{
					Type:        "deny",
					Source:      "security-policy",
					Reason:      "Critical vulnerability",
					Remediation: "Upgrade to 2.15.0",
				},
			},
			wantLen: 1,
		},
		{
			name: "multiple actions",
			actions: []policy.Action{
				{Type: "deny", Source: "policy1"},
				{Type: "warn", Source: "policy2"},
				{Type: "allow", Source: "policy3"},
			},
			wantLen: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PolicyActionsToProto(tt.actions)
			if tt.wantLen == 0 {
				if got != nil {
					t.Error("expected nil for empty/nil actions")
				}
				return
			}
			if len(got) != tt.wantLen {
				t.Errorf("length: got %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestPolicyActionTypeToProto(t *testing.T) {
	tests := []struct {
		input string
		want  policyv1.ActionType
	}{
		{"deny", policyv1.ActionType_ACTION_TYPE_DENY},
		{"DENY", policyv1.ActionType_ACTION_TYPE_DENY},
		{"Deny", policyv1.ActionType_ACTION_TYPE_DENY},
		{"warn", policyv1.ActionType_ACTION_TYPE_WARN},
		{"WARN", policyv1.ActionType_ACTION_TYPE_WARN},
		{"Warn", policyv1.ActionType_ACTION_TYPE_WARN},
		{"allow", policyv1.ActionType_ACTION_TYPE_ALLOW},
		{"ALLOW", policyv1.ActionType_ACTION_TYPE_ALLOW},
		{"Allow", policyv1.ActionType_ACTION_TYPE_ALLOW},
		{"unknown", policyv1.ActionType_ACTION_TYPE_UNSPECIFIED},
		{"", policyv1.ActionType_ACTION_TYPE_UNSPECIFIED},
		{"invalid", policyv1.ActionType_ACTION_TYPE_UNSPECIFIED},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := policyActionTypeToProto(tt.input)
			if got != tt.want {
				t.Errorf("policyActionTypeToProto(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestPolicyActionsToProtoFields(t *testing.T) {
	actions := []policy.Action{
		{
			Type:        "deny",
			Source:      "security-policy",
			Reason:      "Critical vulnerability found",
			Remediation: "Upgrade to version 2.15.0",
		},
	}

	got := PolicyActionsToProto(actions)
	if len(got) != 1 {
		t.Fatalf("expected 1 action, got %d", len(got))
	}

	action := got[0]
	if action.Type != policyv1.ActionType_ACTION_TYPE_DENY {
		t.Errorf("Type: got %v, want DENY", action.Type)
	}
	if action.PolicyName != "security-policy" {
		t.Errorf("PolicyName: got %q, want %q", action.PolicyName, "security-policy")
	}
	if action.Reason != "Critical vulnerability found" {
		t.Errorf("Reason: got %q", action.Reason)
	}
	if action.Remediation != "Upgrade to version 2.15.0" {
		t.Errorf("Remediation: got %q", action.Remediation)
	}
}
