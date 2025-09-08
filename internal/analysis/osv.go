package analysis

import (
	"context"
	"fmt"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"osv.dev/bindings/go/osvdev"
)

// OSVClient abstracts the subset of osv.dev client functionality required for
// batch querying and vulnerability expansion. It is satisfied by
// osvdev.DefaultClient enabling dependency injection in tests.
type OSVClient interface {
	QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error)
	GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error)
}

// PkgInput represents a single package@version query along with whether the
// dependency is direct (appears explicitly in go.mod). Directness influences
// downstream prioritization but not query mechanics.
type PkgInput struct {
	Name     string
	Version  string
	IsDirect bool
}

// QueryOSVBatch performs a batched OSV vulnerability lookup for the provided
// packages. For each minimal vulnerability match it expands full vulnerability
// details via GetVulnByID to populate rich fields (aliases, severity, ranges).
// The function is resilient: individual GetVulnByID failures are skipped so a
// single retrieval error does not abort the entire batch.
func QueryOSVBatch(ctx context.Context, client OSVClient, pkgs []PkgInput) ([]Vulnerability, error) {
	if len(pkgs) == 0 {
		return nil, nil
	}
	queries := make([]*osvdev.Query, 0, len(pkgs))
	meta := make([]PkgInput, 0, len(pkgs))
	for _, p := range pkgs {
		v := p.Version
		if v == "" {
			continue
		}
		if !strings.HasPrefix(v, "v") {
			v = "v" + v
		}
		queries = append(queries, &osvdev.Query{Package: osvdev.Package{Name: p.Name, Ecosystem: "Go"}, Version: v})
		meta = append(meta, p)
	}
	if len(queries) == 0 {
		return nil, nil
	}
	resp, err := client.QueryBatch(ctx, queries)
	if err != nil {
		return nil, fmt.Errorf("failed to query OSV API: %w", err)
	}
	var out []Vulnerability
	for i, res := range resp.Results {
		if i >= len(queries) || i >= len(meta) {
			break
		}
		pkgName := queries[i].Package.Name
		ver := queries[i].Version
		isDirect := meta[i].IsDirect
		for _, mv := range res.Vulns {
			full, err := client.GetVulnByID(ctx, mv.ID)
			if err != nil {
				continue
			}
			out = append(out, ProcessOSVVulnerability(*full, pkgName, ver, isDirect))
		}
	}
	return out, nil
}
