package analysis

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"osv.dev/bindings/go/osvdev"
)

// fakeOSVClient mocks the OSV client for testing purposes.
// It returns a fixed set of vulnerabilities regardless of the input query.
// fakeOSVClient mocks the OSV client for testing purposes.
// It returns a fixed set of vulnerabilities regardless of the input query.
// fakeOSVClient mocks the OSV client for testing purposes.
// It returns a fixed set of vulnerabilities regardless of the input query.
type fakeOSVClient struct{}

func (f *fakeOSVClient) QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
	return &osvdev.BatchedResponse{Results: []osvdev.MinimalResponse{{Vulns: []osvdev.MinimalVulnerability{{ID: "V-1"}}}}}, nil
}
func (f *fakeOSVClient) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
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

func Test_QueryOSVBatch_ok(t *testing.T) {
	cacheDirOnce = sync.Once{}
	cacheDirPath = ""
	t.Setenv("DEPUTY_CACHE_DIR", t.TempDir())
	client := &fakeOSVClient{}
	vulns, err := QueryOSVBatch(context.Background(), client, []PkgInput{{Name: "github.com/example/pkg", Version: "1.2.3", Ecosystem: "Go", IsDirect: true}})
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

type fakeOSVClientQueryErr struct{}

func (f *fakeOSVClientQueryErr) QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
	return nil, errors.New("query-failed")
}
func (f *fakeOSVClientQueryErr) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
	return nil, nil
}

func Test_QueryOSVBatch_query_error(t *testing.T) {
	cacheDirOnce = sync.Once{}
	cacheDirPath = ""
	t.Setenv("DEPUTY_CACHE_DIR", t.TempDir())
	client := &fakeOSVClientQueryErr{}
	_, err := QueryOSVBatch(context.Background(), client, []PkgInput{{Name: "n", Version: "1", Ecosystem: "Go", IsDirect: true}})
	if err == nil {
		t.Fatalf("expected error")
	}
}

type fakeOSVClientGetErr struct{}

func (f *fakeOSVClientGetErr) QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
	return &osvdev.BatchedResponse{Results: []osvdev.MinimalResponse{{Vulns: []osvdev.MinimalVulnerability{{ID: "V-2"}}}}}, nil
}
func (f *fakeOSVClientGetErr) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
	return nil, errors.New("get-failed")
}

func Test_QueryOSVBatch_getvuln_error(t *testing.T) {
	cacheDirOnce = sync.Once{}
	cacheDirPath = ""
	t.Setenv("DEPUTY_CACHE_DIR", t.TempDir())
	client := &fakeOSVClientGetErr{}
	_, err := QueryOSVBatch(context.Background(), client, []PkgInput{{Name: "n", Version: "1", Ecosystem: "Go", IsDirect: true}})
	if err == nil {
		t.Fatalf("expected error when GetVulnByID fails")
	}
}

type fakeOSVClientFixed struct{}

func (f *fakeOSVClientFixed) QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
	return &osvdev.BatchedResponse{Results: []osvdev.MinimalResponse{{Vulns: []osvdev.MinimalVulnerability{{ID: "V-fixed"}}}}}, nil
}

func (f *fakeOSVClientFixed) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
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

func Test_QueryOSVBatch_skips_fixed_version(t *testing.T) {
	cacheDirOnce = sync.Once{}
	cacheDirPath = ""
	t.Setenv("DEPUTY_CACHE_DIR", t.TempDir())
	client := &fakeOSVClientFixed{}
	vulns, err := QueryOSVBatch(context.Background(), client, []PkgInput{{Name: "github.com/example/pkg", Version: "1.55.6", Ecosystem: "Go", IsDirect: true}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cons := ConsolidateVulnerabilities(vulns); len(cons) != 0 {
		t.Fatalf("expected no vulns for fixed version, got %d", len(cons))
	}
}

type fakeOSVClientAWS struct{}

func (f *fakeOSVClientAWS) QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
	return &osvdev.BatchedResponse{Results: []osvdev.MinimalResponse{{Vulns: []osvdev.MinimalVulnerability{{ID: "GHSA-7f33-f4f5-xwgw"}, {ID: "GO-2022-0635"}, {ID: "GHSA-f5pg-7wfw-84q9"}, {ID: "GO-2022-0646"}}}}}, nil
}

func (f *fakeOSVClientAWS) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
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

func Test_QueryOSVBatch_awssdkv1(t *testing.T) {
	client := &fakeOSVClientAWS{}
	vulns, err := QueryOSVBatch(context.Background(), client, []PkgInput{{Name: "github.com/aws/aws-sdk-go", Version: "1.55.6", Ecosystem: "Go", IsDirect: true}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cons := ConsolidateVulnerabilities(vulns); len(cons) != 0 {
		t.Fatalf("expected no vulns for fixed version, got %d", len(cons))
	}

	vulns, err = QueryOSVBatch(context.Background(), client, []PkgInput{{Name: "github.com/aws/aws-sdk-go", Version: "1.33.0", Ecosystem: "Go", IsDirect: true}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cons := ConsolidateVulnerabilities(vulns)
	if len(cons) != 2 {
		t.Fatalf("expected 2 vulns for vulnerable version, got %d", len(cons))
	}
	for _, v := range cons {
		if !strings.HasPrefix(v.PrimaryID, "CVE-") {
			t.Errorf("missing CVE primary ID: %s", v.PrimaryID)
		}
		score := ParseCVSSScore(v.Severity)
		if score < 2.4 || score > 2.6 {
			t.Fatalf("expected severity around 2.5, got %v", score)
		}
		if fix := FindBestFixedVersion(v.FixedVersions, "1.33.0"); fix != "v1.34.0" {
			t.Fatalf("expected fix v1.34.0, got %s", fix)
		}
	}
}

type fakeOSVClientAlias struct{}

func (f *fakeOSVClientAlias) QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
	return &osvdev.BatchedResponse{Results: []osvdev.MinimalResponse{{Vulns: []osvdev.MinimalVulnerability{{ID: "GHSA-base"}}}}}, nil
}

func (f *fakeOSVClientAlias) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
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

func Test_QueryOSVBatch_aliasWithoutRange(t *testing.T) {
	cacheDirOnce = sync.Once{}
	cacheDirPath = ""
	t.Setenv("DEPUTY_CACHE_DIR", t.TempDir())
	client := &fakeOSVClientAlias{}
	vulns, err := QueryOSVBatch(context.Background(), client, []PkgInput{{Name: "github.com/example/pkg", Version: "1.2.3", Ecosystem: "Go", IsDirect: true}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}
}

type fakeOSVClientAliasUnmatchedPackage struct{}

func (f *fakeOSVClientAliasUnmatchedPackage) QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
	return &osvdev.BatchedResponse{Results: []osvdev.MinimalResponse{{Vulns: []osvdev.MinimalVulnerability{{ID: "GHSA-base"}}}}}, nil
}

func (f *fakeOSVClientAliasUnmatchedPackage) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
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

func Test_QueryOSVBatch_ignoresAliasWithoutPackageIdentity(t *testing.T) {
	cacheDirOnce = sync.Once{}
	cacheDirPath = ""
	t.Setenv("DEPUTY_CACHE_DIR", t.TempDir())
	client := &fakeOSVClientAliasUnmatchedPackage{}
	vulns, err := QueryOSVBatch(context.Background(), client, []PkgInput{{Name: "github.com/example/pkg", Version: "1.2.3", Ecosystem: "Go", IsDirect: true}})
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

type countingOSVClient struct{ calls int }

func (c *countingOSVClient) QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
	return &osvdev.BatchedResponse{Results: []osvdev.MinimalResponse{{Vulns: []osvdev.MinimalVulnerability{{ID: "V-cache"}}}}}, nil
}

func (c *countingOSVClient) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
	c.calls++
	return &osvschema.Vulnerability{
		ID: id,
		Affected: []osvschema.Affected{{
			Package: osvschema.Package{Name: "github.com/example/pkg"},
			Ranges:  []osvschema.Range{{Type: osvschema.RangeSemVer, Events: []osvschema.Event{{Introduced: "0"}}}},
		}},
	}, nil
}

func Test_QueryOSVBatch_cache(t *testing.T) {
	cacheDirOnce = sync.Once{}
	cacheDirPath = ""
	tmp := t.TempDir()
	t.Setenv("DEPUTY_CACHE_DIR", tmp)
	client := &countingOSVClient{}
	pkgs := []PkgInput{{Name: "github.com/example/pkg", Version: "1.0.0", Ecosystem: "Go"}}
	if _, err := QueryOSVBatch(context.Background(), client, pkgs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := QueryOSVBatch(context.Background(), client, pkgs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.calls != 1 {
		t.Fatalf("expected 1 GetVulnByID call, got %d", client.calls)
	}
}
