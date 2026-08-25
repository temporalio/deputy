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
				"osv: advisory GO-2026-6255 reported for github.com/moby/buildkit@v0.30.0 is missing from this report: " +
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
