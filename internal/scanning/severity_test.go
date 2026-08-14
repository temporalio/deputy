package scanning

import (
	"context"
	"fmt"
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"osv.dev/bindings/go/api"

	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// severityAliasClient serves canned OSV records for alias lookups.
type severityAliasClient struct {
	vulns map[string]*osvschema.Vulnerability
}

func (c *severityAliasClient) QueryBatch(context.Context, []*api.Query) (*api.BatchVulnerabilityList, error) {
	return nil, fmt.Errorf("unexpected QueryBatch")
}

func (c *severityAliasClient) GetVulnByID(_ context.Context, id string) (*osvschema.Vulnerability, error) {
	return c.vulns[id], nil
}

// TestResolveUnratedSeverities pins the opt-in severity resolution contract:
// advisories whose matched record carries no rating gain one from their alias
// records with provenance preserved, already-rated advisories are untouched,
// and advisories no alias rates stay UNKNOWN because absence of a rating
// anywhere is itself the answer.
func TestResolveUnratedSeverities(t *testing.T) {
	client := &severityAliasClient{
		vulns: map[string]*osvschema.Vulnerability{
			"GHSA-g9pc-8g42-g6vq": {
				Id:       "GHSA-g9pc-8g42-g6vq",
				Severity: []*osvschema.Severity{{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}},
			},
		},
	}
	unrated := &vulnerabilityv1.Advisory{
		Id:      "CVE-2025-22871",
		Aliases: []string{"GO-2025-3563", "GHSA-g9pc-8g42-g6vq"},
	}
	rated := &vulnerabilityv1.Advisory{
		Id:       "CVE-2020-0001",
		Aliases:  []string{"GHSA-g9pc-8g42-g6vq"},
		Severity: vulnerability.NewSeverity("LOW", "GHSA"),
	}
	hopeless := &vulnerabilityv1.Advisory{
		Id:      "GO-2026-0001",
		Aliases: []string{"CVE-2026-0001"},
	}

	resolveUnratedSeverities(t.Context(), client, map[string]*vulnerabilityv1.Advisory{
		unrated.Id:  unrated,
		rated.Id:    rated,
		hopeless.Id: hopeless,
	})

	if got := unrated.GetSeverity().GetLevel(); got != vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL {
		t.Errorf("unrated advisory level = %v, want CRITICAL from the GHSA alias", got)
	}
	if got := unrated.GetSeverity().GetType(); got != vulnerabilityv1.SeverityType_SEVERITY_TYPE_CVSS_V3 {
		t.Errorf("resolved severity type = %v, want CVSS_V3 provenance", got)
	}
	if got := rated.GetSeverity().GetLevel(); got != vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_LOW {
		t.Errorf("rated advisory level = %v, want untouched LOW", got)
	}
	if got := hopeless.GetSeverity().GetLevel(); got != vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_UNSPECIFIED {
		t.Errorf("hopeless advisory level = %v, want UNKNOWN preserved", got)
	}
}
