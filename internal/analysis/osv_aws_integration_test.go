package analysis

import (
	"context"
	"testing"

	"osv.dev/bindings/go/osvdev"
)

// TestAWSV1Integration ensures real OSV data marks fixed versions correctly.
func TestAWSV1Integration(t *testing.T) {
	t.Skip("network access required")
	ctx := context.Background()
	client := osvdev.DefaultClient()
	vulns, err := QueryOSVBatch(ctx, client, []PkgInput{{Name: "github.com/aws/aws-sdk-go", Version: "1.55.6", Ecosystem: "Go", IsDirect: true}})
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(vulns) != 0 {
		t.Fatalf("expected no vulns for fixed version, got %d", len(vulns))
	}

	vulns, err = QueryOSVBatch(ctx, client, []PkgInput{{Name: "github.com/aws/aws-sdk-go", Version: "1.33.0", Ecosystem: "Go", IsDirect: true}})
	if err != nil {
		t.Fatalf("query2 failed: %v", err)
	}
	cons := ConsolidateVulnerabilities(vulns)
	if len(cons) == 0 {
		t.Fatalf("expected vulns for old version")
	}
	found := false
	for _, v := range cons {
		if FindBestFixedVersion(v.FixedVersions, "1.33.0") == "v1.34.0" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected fix v1.34.0 present")
	}
}
