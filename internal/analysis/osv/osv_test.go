package osv

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/picatz/deputy/internal/cache/disk"
	"github.com/picatz/deputy/internal/vulnerability"
	"osv.dev/bindings/go/osvdev"
)

// fakeClient mocks the OSV client for testing purposes.
// It returns a fixed set of vulnerabilities regardless of the input query.
type fakeClient struct{}

func (f *fakeClient) QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
	return &osvdev.BatchedResponse{Results: []osvdev.MinimalResponse{{Vulns: []osvdev.MinimalVulnerability{{ID: "V-1"}}}}}, nil
}
func (f *fakeClient) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
	v := &osvschema.Vulnerability{
		ID:      id,
		Summary: "sum",
		Details: "det",
		Aliases: []string{"CVE-1"},
		Affected: []osvschema.Affected{{
			Package: osvschema.Package{Name: "github.com/example/pkg"},
			Ranges:  []osvschema.Range{{Type: "SEMVER", Events: []osvschema.Event{{Introduced: "0"}}}},
		}},
	}
	return v, nil
}

func resetDiskCache(t *testing.T) {
	t.Helper()
	restore := disk.SetBaseDirForTest(t.TempDir())
	t.Cleanup(restore)
}

func Test_QueryRaw_ok(t *testing.T) {
	resetDiskCache(t)
	client := &fakeClient{}
	vulns, err := QueryRaw(context.Background(), client, []PkgInput{{QueryKey: QueryKey{Name: "github.com/example/pkg", Version: "1.2.3", Ecosystem: "Go"}, PackageContext: PackageContext{IsDirect: true}}})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("want 1, got %d", len(vulns))
	}
	if vulns[0].CVE != "CVE-1" {
		t.Fatalf("want CVE-1, got %q", vulns[0].CVE)
	}
}

type fakeClientQueryErr struct{}

func (f *fakeClientQueryErr) QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
	return nil, errors.New("query-failed")
}
func (f *fakeClientQueryErr) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
	return nil, nil
}

func Test_QueryRaw_query_error(t *testing.T) {
	resetDiskCache(t)
	client := &fakeClientQueryErr{}
	_, err := QueryRaw(context.Background(), client, []PkgInput{{QueryKey: QueryKey{Name: "n", Version: "1", Ecosystem: "Go"}, PackageContext: PackageContext{IsDirect: true}}})
	if err == nil {
		t.Fatalf("expected error")
	}
}

type fakeClientGetErr struct{}

func (f *fakeClientGetErr) QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
	return &osvdev.BatchedResponse{Results: []osvdev.MinimalResponse{{Vulns: []osvdev.MinimalVulnerability{{ID: "V-2"}}}}}, nil
}
func (f *fakeClientGetErr) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
	return nil, errors.New("get-failed")
}

func Test_QueryRaw_getvuln_error(t *testing.T) {
	resetDiskCache(t)
	client := &fakeClientGetErr{}
	_, err := QueryRaw(context.Background(), client, []PkgInput{{QueryKey: QueryKey{Name: "n", Version: "1", Ecosystem: "Go"}, PackageContext: PackageContext{IsDirect: true}}})
	if err == nil {
		t.Fatalf("expected error when GetVulnByID fails")
	}
}

type fakeClientFixed struct{}

func (f *fakeClientFixed) QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
	return &osvdev.BatchedResponse{Results: []osvdev.MinimalResponse{{Vulns: []osvdev.MinimalVulnerability{{ID: "V-fixed"}}}}}, nil
}

func (f *fakeClientFixed) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
	return &osvschema.Vulnerability{
		ID: id,
		Affected: []osvschema.Affected{{
			Package: osvschema.Package{Name: "github.com/example/pkg"},
			Ranges: []osvschema.Range{{
				Type:   "SEMVER",
				Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "1.34.0"}},
			}},
		}},
	}, nil
}

func Test_QueryRaw_skips_fixed_version(t *testing.T) {
	resetDiskCache(t)
	client := &fakeClientFixed{}
	vulns, err := QueryRaw(context.Background(), client, []PkgInput{{QueryKey: QueryKey{Name: "github.com/example/pkg", Version: "1.55.6", Ecosystem: "Go"}, PackageContext: PackageContext{IsDirect: true}}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 0 {
		t.Fatalf("expected no vulns for fixed version, got %d", len(vulns))
	}
}

type fakeClientAWS struct{}

func (f *fakeClientAWS) QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
	return &osvdev.BatchedResponse{Results: []osvdev.MinimalResponse{{Vulns: []osvdev.MinimalVulnerability{{ID: "GHSA-7f33-f4f5-xwgw"}, {ID: "GO-2022-0635"}, {ID: "GHSA-f5pg-7wfw-84q9"}, {ID: "GO-2022-0646"}}}}}, nil
}

func (f *fakeClientAWS) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
	base := osvschema.Vulnerability{ID: id, Affected: []osvschema.Affected{{Package: osvschema.Package{Name: "github.com/aws/aws-sdk-go"}}}}
	switch id {
	case "GHSA-7f33-f4f5-xwgw":
		base.Aliases = []string{"CVE-2020-8912"}
		base.Severity = []osvschema.Severity{{Type: osvschema.SeverityCVSSV3, Score: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N"}}
		base.DatabaseSpecific = map[string]any{"severity": "LOW"}
		base.Affected[0].Ranges = []osvschema.Range{{Type: osvschema.RangeSemVer, Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "1.34.0"}}}}
	case "GO-2022-0635":
		base.Aliases = []string{"CVE-2020-8912", "GHSA-7f33-f4f5-xwgw"}
		base.Affected[0].Ranges = []osvschema.Range{{Type: osvschema.RangeSemVer, Events: []osvschema.Event{{Introduced: "0"}}}}
	case "GHSA-f5pg-7wfw-84q9":
		base.Aliases = []string{"CVE-2020-8911"}
		base.Severity = []osvschema.Severity{{Type: osvschema.SeverityCVSSV3, Score: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N"}}
		base.DatabaseSpecific = map[string]any{"severity": "LOW"}
		base.Affected[0].Ranges = []osvschema.Range{{Type: osvschema.RangeSemVer, Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "1.34.0"}}}}
	case "GO-2022-0646":
		base.Aliases = []string{"CVE-2020-8911", "GHSA-f5pg-7wfw-84q9"}
		base.Affected[0].Ranges = []osvschema.Range{{Type: osvschema.RangeSemVer, Events: []osvschema.Event{{Introduced: "0"}}}}
	default:
		return nil, fmt.Errorf("unknown id %s", id)
	}
	return &base, nil
}

func Test_QueryRaw_awssdkv1(t *testing.T) {
	resetDiskCache(t)
	client := &fakeClientAWS{}
	vulns, err := QueryRaw(context.Background(), client, []PkgInput{{QueryKey: QueryKey{Name: "github.com/aws/aws-sdk-go", Version: "1.55.6", Ecosystem: "Go"}, PackageContext: PackageContext{IsDirect: true}}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 0 {
		t.Fatalf("expected no vulns for fixed version, got %d", len(vulns))
	}

	vulns, err = QueryRaw(context.Background(), client, []PkgInput{{QueryKey: QueryKey{Name: "github.com/aws/aws-sdk-go", Version: "1.33.0", Ecosystem: "Go"}, PackageContext: PackageContext{IsDirect: true}}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The query returns 4 raw vulns (GHSA-7f33-f4f5-xwgw, GO-2022-0635, GHSA-f5pg-7wfw-84q9, GO-2022-0646).
	// Consolidation to 2 CVEs happens at a higher layer (scan/report).
	if len(vulns) == 0 {
		t.Fatalf("expected vulns for vulnerable version, got 0")
	}
	// Verify at least one has a fix version
	hasFixV1340 := false
	for _, v := range vulns {
		if fix := vulnerability.FindBestFixedVersion(v.FixedVersions, "1.33.0"); fix == "v1.34.0" {
			hasFixV1340 = true
			break
		}
	}
	if !hasFixV1340 {
		t.Fatalf("expected at least one vuln with fix v1.34.0")
	}
}

type fakeClientAlias struct{}

func (f *fakeClientAlias) QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
	return &osvdev.BatchedResponse{Results: []osvdev.MinimalResponse{{Vulns: []osvdev.MinimalVulnerability{{ID: "GHSA-base"}}}}}, nil
}

func (f *fakeClientAlias) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
	switch id {
	case "GHSA-base":
		return &osvschema.Vulnerability{
			ID:      id,
			Aliases: []string{"CVE-TEST"},
			Affected: []osvschema.Affected{{
				Package: osvschema.Package{Name: "github.com/example/pkg"},
				Ranges:  []osvschema.Range{{Type: osvschema.RangeSemVer, Events: []osvschema.Event{{Introduced: "0"}}}},
			}},
		}, nil
	case "CVE-TEST":
		// alias record missing affected info
		return &osvschema.Vulnerability{ID: id}, nil
	default:
		return nil, fmt.Errorf("unknown id %s", id)
	}
}

func Test_QueryRaw_aliasWithoutRange(t *testing.T) {
	resetDiskCache(t)
	client := &fakeClientAlias{}
	vulns, err := QueryRaw(context.Background(), client, []PkgInput{{QueryKey: QueryKey{Name: "github.com/example/pkg", Version: "1.2.3", Ecosystem: "Go"}, PackageContext: PackageContext{IsDirect: true}}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}
}

type fakeClientAliasUnmatchedPackage struct{}

func (f *fakeClientAliasUnmatchedPackage) QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
	return &osvdev.BatchedResponse{Results: []osvdev.MinimalResponse{{Vulns: []osvdev.MinimalVulnerability{{ID: "GHSA-base"}}}}}, nil
}

func (f *fakeClientAliasUnmatchedPackage) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
	switch id {
	case "GHSA-base":
		return &osvschema.Vulnerability{
			ID:      id,
			Aliases: []string{"CVE-ALIAS"},
			Affected: []osvschema.Affected{{
				Package: osvschema.Package{Name: "github.com/example/pkg", Ecosystem: "Go"},
				Ranges:  []osvschema.Range{{Type: osvschema.RangeSemVer, Events: []osvschema.Event{{Introduced: "0"}}}},
			}},
		}, nil
	case "CVE-ALIAS":
		return &osvschema.Vulnerability{
			ID: id,
			Affected: []osvschema.Affected{{
				// Alias record does not identify the package; it should not influence results.
				Package: osvschema.Package{},
				Ranges:  []osvschema.Range{{Type: osvschema.RangeSemVer, Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "v9.9.9"}}}},
			}},
		}, nil
	default:
		return nil, fmt.Errorf("unknown id %s", id)
	}
}

func Test_QueryRaw_ignoresAliasWithoutPackageIdentity(t *testing.T) {
	resetDiskCache(t)
	client := &fakeClientAliasUnmatchedPackage{}
	vulns, err := QueryRaw(context.Background(), client, []PkgInput{{QueryKey: QueryKey{Name: "github.com/example/pkg", Version: "1.2.3", Ecosystem: "Go"}, PackageContext: PackageContext{IsDirect: true}}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}
	if slices.Contains(vulns[0].FixedVersions, "v9.9.9") {
		t.Fatalf("unexpected fixed version from unmatched alias: %+v", vulns[0].FixedVersions)
	}
}

type countingClient struct{ calls int }

func (c *countingClient) QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
	return &osvdev.BatchedResponse{Results: []osvdev.MinimalResponse{{Vulns: []osvdev.MinimalVulnerability{{ID: "V-cache"}}}}}, nil
}

func (c *countingClient) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
	c.calls++
	return &osvschema.Vulnerability{
		ID: id,
		Affected: []osvschema.Affected{{
			Package: osvschema.Package{Name: "github.com/example/pkg"},
			Ranges:  []osvschema.Range{{Type: osvschema.RangeSemVer, Events: []osvschema.Event{{Introduced: "0"}}}},
		}},
	}, nil
}

func Test_QueryRaw_cache(t *testing.T) {
	resetDiskCache(t)
	client := &countingClient{}
	pkgs := []PkgInput{{QueryKey: QueryKey{Name: "github.com/example/pkg", Version: "1.0.0", Ecosystem: "Go"}}}
	if _, err := QueryRaw(context.Background(), client, pkgs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := QueryRaw(context.Background(), client, pkgs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.calls != 1 {
		t.Fatalf("expected 1 GetVulnByID call, got %d", client.calls)
	}
}
