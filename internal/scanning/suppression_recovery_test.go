package scanning

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"osv.dev/bindings/go/api"

	"github.com/temporalio/deputy/internal/analysis/osv"
	"github.com/temporalio/deputy/internal/cache/disk"
	"github.com/temporalio/deputy/internal/ignore"
)

// recoveringOSVClient reports one withdrawn advisory for the queried package and
// answers the expansion the way OSV answers a merged record: a 404 whose body
// names the live alias, which then resolves. This is the sequence that used to
// hand the finding back under the alias's ID.
type recoveringOSVClient struct {
	withdrawnID string
	aliasID     string
	pkgName     string
}

func (c *recoveringOSVClient) QueryBatch(_ context.Context, queries []*api.Query) (*api.BatchVulnerabilityList, error) {
	results := make([]*api.VulnerabilityList, 0, len(queries))
	for range queries {
		results = append(results, &api.VulnerabilityList{
			Vulns: []*osvschema.Vulnerability{{Id: c.withdrawnID}},
		})
	}
	return &api.BatchVulnerabilityList{Results: results}, nil
}

func (c *recoveringOSVClient) GetVulnByID(_ context.Context, id string) (*osvschema.Vulnerability, error) {
	if id == c.aliasID {
		return &osvschema.Vulnerability{
			Id:      c.aliasID,
			Summary: "Recovered under the live alias",
			Affected: []*osvschema.Affected{{
				Package: &osvschema.Package{Name: c.pkgName, Ecosystem: "Go"},
				Ranges: []*osvschema.Range{{
					Type:   osvschema.Range_SEMVER,
					Events: []*osvschema.Event{{Introduced: "0"}},
				}},
			}},
		}, nil
	}
	return nil, errors.New(`client error: status="404 Not Found" body={"code":5,` +
		`"message":"Vulnerability not found, but the following aliases were: ` + c.aliasID + `"}`)
}

// TestIgnoreRuleSurvivesAliasRecovery is the user-visible point of preserving
// the superseded advisory ID. Someone puts the ID OSV reported into
// .deputyignore.yaml; later OSV merges that record into an alias, so Deputy
// recovers the finding through the alias. If the finding came back under the
// alias's ID, the suppression would quietly stop matching and a vulnerability
// the user had triaged and accepted would reappear with no explanation.
//
// This drives the real recovery path and the real FilterIgnored, which matches
// on the finding's advisory ID alone, so it fails if identity is not preserved.
func TestIgnoreRuleSurvivesAliasRecovery(t *testing.T) {
	const (
		pkgName     = "github.com/moby/buildkit"
		pkgVersion  = "v0.30.0"
		withdrawnID = "GO-2026-6255"
		aliasID     = "GHSA-7236-3392-c5c6"
	)

	tests := []struct {
		name string
		// ignoreID is the advisory the user suppressed.
		ignoreID string
		// wantIgnored is whether the rule should suppress the finding.
		wantIgnored bool
	}{
		{
			// The regression this guards: the ID the user actually saw and
			// suppressed is the one OSV reported, not the one we recovered.
			name:        "rule naming the superseded ID still matches",
			ignoreID:    withdrawnID,
			wantIgnored: true,
		},
		{
			// A rule for an unrelated advisory must not start matching.
			name:     "rule naming an unrelated advisory does not match",
			ignoreID: "CVE-2020-00000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(disk.SetBaseDirForTest(t.TempDir()))

			client := &recoveringOSVClient{withdrawnID: withdrawnID, aliasID: aliasID, pkgName: pkgName}
			findings, advisories, unresolved, err := osv.Query(t.Context(), client, []osv.PkgInput{{
				QueryKey: osv.QueryKey{Name: pkgName, Version: pkgVersion, Ecosystem: "Go"},
			}})
			if err != nil {
				t.Fatalf("osv.Query() error = %v, want nil", err)
			}
			if len(unresolved) != 0 {
				t.Fatalf("unresolved = %+v, want none: the alias recovered the record", unresolved)
			}
			if len(findings) != 1 {
				t.Fatalf("findings = %d, want 1", len(findings))
			}
			if got := findings[0].AdvisoryID; got != withdrawnID {
				t.Fatalf("finding advisory ID = %q, want %q: recovery must not change the reported identity", got, withdrawnID)
			}

			rules, err := ignore.LoadFromBytes([]byte(strings.Join([]string{
				"ignore:",
				"  - id: " + tt.ignoreID,
				"    reason: Accepted during triage",
			}, "\n")))
			if err != nil {
				t.Fatalf("ignore.LoadFromBytes() error = %v", err)
			}

			filtered, ignored := FilterIgnored(Result{Findings: findings, Advisories: advisories}, rules)
			if tt.wantIgnored {
				if ignored != 1 {
					t.Errorf("ignored = %d, want 1: the suppression for %s stopped matching after recovery", ignored, tt.ignoreID)
				}
				if len(filtered.Findings) != 0 {
					t.Errorf("findings after filtering = %d, want 0", len(filtered.Findings))
				}
				return
			}
			if ignored != 0 {
				t.Errorf("ignored = %d, want 0", ignored)
			}
			if len(filtered.Findings) != 1 {
				t.Errorf("findings after filtering = %d, want 1", len(filtered.Findings))
			}
		})
	}
}
