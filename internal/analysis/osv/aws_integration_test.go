package osv

import (
	"slices"
	"testing"

	"github.com/temporalio/deputy/internal/vulnerability"
	"osv.dev/bindings/go/osvdev"
)

// TestAWSV1Integration ensures real OSV data marks fixed versions correctly.
func TestAWSV1Integration(t *testing.T) {
	t.Skip("network access required")
	ctx := t.Context()
	client := osvdev.DefaultClient()
	vulns, _, err := QueryRaw(ctx, client, []PkgInput{{QueryKey: QueryKey{Name: "github.com/aws/aws-sdk-go", Version: "1.55.6", Ecosystem: "Go"}, PackageContext: PackageContext{IsDirect: true}}})
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(vulns) != 0 {
		t.Fatalf("expected no vulns for fixed version, got %d", len(vulns))
	}

	vulns, _, err = QueryRaw(ctx, client, []PkgInput{{QueryKey: QueryKey{Name: "github.com/aws/aws-sdk-go", Version: "1.33.0", Ecosystem: "Go"}, PackageContext: PackageContext{IsDirect: true}}})
	if err != nil {
		t.Fatalf("query2 failed: %v", err)
	}
	if len(vulns) == 0 {
		t.Fatalf("expected vulns for old version")
	}
	if !slices.ContainsFunc(vulns, func(v Vulnerability) bool {
		return vulnerability.FindBestFixedVersion(v.FixedVersions, "1.33.0") == "v1.34.0"
	}) {
		t.Fatalf("expected fix v1.34.0 present")
	}
}
