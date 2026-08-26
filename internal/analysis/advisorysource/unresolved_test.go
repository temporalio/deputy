package advisorysource

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"osv.dev/bindings/go/api"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/analysis/osv"
	"github.com/temporalio/deputy/internal/cache/disk"
)

// withdrawnAdvisoryClient reports one advisory for every queried package and
// then refuses to expand it the way OSV refuses a withdrawn record: a 404 whose
// body names the aliases that do exist.
type withdrawnAdvisoryClient struct {
	// advisoryID is the ID the batch query attributes to each package.
	advisoryID string
	// aliases are the IDs the 404 body names, if any.
	aliases []string
	// records are the alias records the client will serve.
	records map[string]*osvschema.Vulnerability
}

func (c *withdrawnAdvisoryClient) QueryBatch(_ context.Context, queries []*api.Query) (*api.BatchVulnerabilityList, error) {
	results := make([]*api.VulnerabilityList, 0, len(queries))
	for range queries {
		results = append(results, &api.VulnerabilityList{
			Vulns: []*osvschema.Vulnerability{{Id: c.advisoryID}},
		})
	}
	return &api.BatchVulnerabilityList{Results: results}, nil
}

func (c *withdrawnAdvisoryClient) GetVulnByID(_ context.Context, id string) (*osvschema.Vulnerability, error) {
	if rec, ok := c.records[id]; ok {
		return rec, nil
	}
	if id != c.advisoryID || len(c.aliases) == 0 {
		return nil, errors.New(`client error: status="404 Not Found" body={"code":5,"message":"Bug not found."}`)
	}
	return nil, errors.New(`client error: status="404 Not Found" body={"code":5,` +
		`"message":"Vulnerability not found, but the following aliases were: ` + strings.Join(c.aliases, " ") + `"}`)
}

// TestOSVSourceReportsUnresolvedAdvisories checks the seam that turns a
// per-advisory failure into something the scan report can show. Before the fix
// the query returned an error here and the registry discarded every source's
// results, so the scan produced no report at all.
func TestOSVSourceReportsUnresolvedAdvisories(t *testing.T) {
	const (
		buildkit  = "github.com/moby/buildkit"
		withdrawn = "GO-2026-6255"
		ghsaAlias = "GHSA-7236-3392-c5c6"
	)

	buildkitRecord := &osvschema.Vulnerability{
		Id: ghsaAlias,
		Affected: []*osvschema.Affected{{
			Package: &osvschema.Package{Name: buildkit, Ecosystem: "Go"},
			Ranges: []*osvschema.Range{{
				Type:   osvschema.Range_SEMVER,
				Events: []*osvschema.Event{{Introduced: "0"}},
			}},
		}},
	}

	tests := []struct {
		name         string
		client       *withdrawnAdvisoryClient
		wantFindings []string
		wantWarnings []string
	}{
		{
			name:   "withdrawn advisory becomes a warning, not an error",
			client: &withdrawnAdvisoryClient{advisoryID: withdrawn},
			wantWarnings: []string{
				"osv: advisory GO-2026-6255 reported for github.com/moby/buildkit@v0.30.0 is absent from osv's findings: " +
					"OSV returned not found for the record, and no alias it named resolved",
			},
		},
		{
			name: "recovered advisory needs no warning",
			client: &withdrawnAdvisoryClient{
				advisoryID: withdrawn,
				aliases:    []string{ghsaAlias},
				records:    map[string]*osvschema.Vulnerability{ghsaAlias: buildkitRecord},
			},
			wantFindings: []string{ghsaAlias},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(disk.SetBaseDirForTest(t.TempDir()))

			pkgs := []*dependencyv1.Package{{
				Name:      buildkit,
				Version:   "v0.30.0",
				Ecosystem: "go",
				Purl:      "pkg:golang/" + buildkit + "@v0.30.0",
			}}

			agg, err := NewRegistry(NewOSVSource(tt.client)).Query(t.Context(), pkgs)
			if err != nil {
				t.Fatalf("Registry.Query() error = %v, want nil: one unexpandable advisory must not fail the scan", err)
			}

			gotFindings := make([]string, 0, len(agg.Findings))
			for _, f := range agg.Findings {
				gotFindings = append(gotFindings, f.GetAdvisoryId())
			}
			slices.Sort(gotFindings)
			want := slices.Clone(tt.wantFindings)
			slices.Sort(want)
			if !slices.Equal(gotFindings, want) {
				t.Errorf("findings = %v, want %v", gotFindings, want)
			}
			if !slices.Equal(agg.Warnings, tt.wantWarnings) {
				t.Errorf("warnings = %q, want %q", agg.Warnings, tt.wantWarnings)
			}
		})
	}
}

// TestRegistryCollectsSourceWarnings checks that a warning from one source
// reaches the aggregate result even when another source answers cleanly, and
// that two sources naming the same gap say it once.
func TestRegistryCollectsSourceWarnings(t *testing.T) {
	warned := &fakeSource{
		name:       "osv",
		ecosystems: []string{"go"},
		artifacts:  onlyPackage(),
		findings:   []*vulnerabilityv1.Finding{goFinding("CVE-1", "osv", "github.com/foo/bar", "1.0.0")},
		advisories: map[string]*vulnerabilityv1.Advisory{"CVE-1": {Id: "CVE-1"}},
		warnings:   []string{"osv: advisory GO-1 is missing"},
	}
	echo := &fakeSource{
		name:       "echo",
		ecosystems: []string{"go"},
		artifacts:  onlyPackage(),
		warnings:   []string{"osv: advisory GO-1 is missing"},
	}
	quiet := &fakeSource{
		name:       "quiet",
		ecosystems: []string{"go"},
		artifacts:  onlyPackage(),
	}

	agg, err := NewRegistry(warned, echo, quiet).Query(t.Context(), []*dependencyv1.Package{goPkg("github.com/foo/bar", "1.0.0")})
	if err != nil {
		t.Fatalf("Registry.Query() error = %v", err)
	}
	if want := []string{"osv: advisory GO-1 is missing"}; !slices.Equal(agg.Warnings, want) {
		t.Errorf("warnings = %q, want %q", agg.Warnings, want)
	}
	if len(agg.Findings) != 1 {
		t.Errorf("findings = %d, want 1: a warning must not cost the findings", len(agg.Findings))
	}
}

// TestRegistryWarningIsHonestWhenAnotherSourceCovers pins the multi-source case
// the warning's wording has to survive. Warnings union across sources
// independently of the findings merge, so OSV's warning about an advisory it
// could not expand rides along even when another configured source reported that
// same advisory and package. The aggregate therefore holds the finding and the
// warning at once, which is only truthful because the warning speaks about
// OSV's own findings rather than about the report. NewDefaultRegistry pairs OSV
// with plugin sources, so this is the shipped configuration, not a contrivance.
func TestRegistryWarningIsHonestWhenAnotherSourceCovers(t *testing.T) {
	const (
		advisoryID = "CVE-2026-61711"
		pkgName    = "github.com/moby/buildkit"
		pkgVersion = "v0.30.0"
	)

	// The exact sentence the OSV source emits, built by the same code that
	// builds it in production so this test cannot drift from it.
	osvWarning := osv.UnresolvedAdvisory{
		ID:      advisoryID,
		Package: pkgName + "@" + pkgVersion,
		Reason:  "OSV returned not found for the record, and no alias it named resolved",
	}.Warning()

	// OSV named the advisory and then could not expand it, so it contributes
	// the warning and no finding.
	osvSource := &fakeSource{
		name:       "osv",
		ecosystems: []string{"go"},
		artifacts:  onlyPackage(),
		warnings:   []string{osvWarning},
	}
	// A second source has the record OSV could not serve.
	vendor := &fakeSource{
		name:       "vendor-feed",
		ecosystems: []string{"go"},
		artifacts:  onlyPackage(),
		findings:   []*vulnerabilityv1.Finding{goFinding(advisoryID, "vendor-feed", pkgName, pkgVersion)},
		advisories: map[string]*vulnerabilityv1.Advisory{advisoryID: {Id: advisoryID}},
	}

	agg, err := NewRegistry(osvSource, vendor).Query(t.Context(), []*dependencyv1.Package{goPkg(pkgName, pkgVersion)})
	if err != nil {
		t.Fatalf("Registry.Query() error = %v, want nil", err)
	}

	// The finding is in the report, supplied by the source that could serve it.
	if len(agg.Findings) != 1 || agg.Findings[0].GetAdvisoryId() != advisoryID {
		t.Fatalf("findings = %+v, want one for %s", agg.Findings, advisoryID)
	}
	if got, want := agg.Findings[0].GetSources(), []string{"vendor-feed"}; !slices.Equal(got, want) {
		t.Errorf("finding sources = %q, want %q", got, want)
	}
	// And OSV's warning still rides along, which is why it must not describe
	// the report: here the report is not missing anything.
	if want := []string{osvWarning}; !slices.Equal(agg.Warnings, want) {
		t.Fatalf("warnings = %q, want %q", agg.Warnings, want)
	}
	if !strings.Contains(osvWarning, "absent from osv's findings") {
		t.Errorf("warning = %q, want it scoped to osv's findings rather than to the report", osvWarning)
	}
}
