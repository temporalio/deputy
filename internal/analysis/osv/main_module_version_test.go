package osv

import (
	"context"
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"osv.dev/bindings/go/api"
)

// overMatchingServerAdvisoryClient returns a server advisory for every query,
// as a matcher that over-reports would, with ranges shaped like the published
// record for the server module (one open-from-zero range plus release-branch
// ranges whose introduced bounds are pre-release versions).
type overMatchingServerAdvisoryClient struct{}

func (overMatchingServerAdvisoryClient) QueryBatch(_ context.Context, queries []*api.Query) (*api.BatchVulnerabilityList, error) {
	res := make([]*api.VulnerabilityList, len(queries))
	for i := range res {
		res[i] = &api.VulnerabilityList{Vulns: []*osvschema.Vulnerability{{Id: "GHSA-q98v-9f9w-f49q"}}}
	}
	return &api.BatchVulnerabilityList{Results: res}, nil
}

func (overMatchingServerAdvisoryClient) GetVulnByID(_ context.Context, id string) (*osvschema.Vulnerability, error) {
	rng := func(intro, fixed string) *osvschema.Range {
		return &osvschema.Range{Type: osvschema.Range_SEMVER, Events: []*osvschema.Event{{Introduced: intro}, {Fixed: fixed}}}
	}
	pkg := &osvschema.Package{Name: "go.temporal.io/server", Ecosystem: "Go"}
	return &osvschema.Vulnerability{
		Id: id,
		Affected: []*osvschema.Affected{
			{Package: pkg, Ranges: []*osvschema.Range{rng("0", "1.28.4")}},
			{Package: pkg, Ranges: []*osvschema.Range{rng("1.29.0-135.0", "1.29.6")}},
			{Package: pkg, Ranges: []*osvschema.Range{rng("1.30.0-143.0", "1.30.4")}},
		},
	}, nil
}

// TestQueryRawMainModuleDevVersionAboveFix guards against reporting a
// module's own advisories against a development build of it. A binary built
// from an untagged commit records its main module as a pseudo-version based on
// the next release (v1.33.0-0.<timestamp>-<commit>), which orders after every
// fixed version; even when a matcher over-reports, the local range check must
// drop the advisory. The affected release keeps reporting so the test cannot
// pass by dropping everything.
func TestQueryRawMainModuleDevVersionAboveFix(t *testing.T) {
	tests := []struct {
		version  string
		affected bool
	}{
		{"1.33.0-0.20261020120000-abcdefabcdef", false},
		{"v1.33.0-0.20261020120000-abcdefabcdef", false},
		{"1.32.0", false},
		{"1.30.5-0.20261001000000-abcdefabcdef", false},
		{"1.30.3", true},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			resetDiskCache(t)
			vulns, _, err := QueryRaw(t.Context(), overMatchingServerAdvisoryClient{}, []PkgInput{{
				QueryKey:       QueryKey{Name: "go.temporal.io/server", Version: tt.version, Ecosystem: "Go"},
				PackageContext: PackageContext{IsDirect: true},
			}})
			if err != nil {
				t.Fatalf("QueryRaw: %v", err)
			}
			if got := len(vulns) > 0; got != tt.affected {
				t.Fatalf("affected = %v (%d findings), want %v", got, len(vulns), tt.affected)
			}
		})
	}
}
