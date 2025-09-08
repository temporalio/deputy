package analysis

import (
    "context"
    "errors"
    "testing"

    "github.com/ossf/osv-schema/bindings/go/osvschema"
    "osv.dev/bindings/go/osvdev"
)

type fakeOSVClient struct{}

func (f *fakeOSVClient) QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
    return &osvdev.BatchedResponse{Results: []osvdev.MinimalResponse{{Vulns: []osvdev.MinimalVulnerability{{ID: "V-1"}}}}}, nil
}
func (f *fakeOSVClient) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
    v := &osvschema.Vulnerability{ID: id, Summary: "sum", Details: "det", Aliases: []string{"CVE-1"}}
    return v, nil
}

func Test_QueryOSVBatch_ok(t *testing.T) {
    client := &fakeOSVClient{}
    vulns, err := QueryOSVBatch(context.Background(), client, []PkgInput{{Name: "github.com/example/pkg", Version: "1.2.3", IsDirect: true}})
    if err != nil { t.Fatalf("err: %v", err) }
    if len(vulns) != 1 { t.Fatalf("want 1, got %d", len(vulns)) }
    if vulns[0].CVE != "CVE-1" { t.Fatalf("want CVE-1, got %q", vulns[0].CVE) }
}

type fakeOSVClientQueryErr struct{}
func (f *fakeOSVClientQueryErr) QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) { return nil, errors.New("query-failed") }
func (f *fakeOSVClientQueryErr) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) { return nil, nil }

func Test_QueryOSVBatch_query_error(t *testing.T) {
    client := &fakeOSVClientQueryErr{}
    _, err := QueryOSVBatch(context.Background(), client, []PkgInput{{Name: "n", Version: "1", IsDirect: true}})
    if err == nil { t.Fatalf("expected error") }
}

type fakeOSVClientGetErr struct{}
func (f *fakeOSVClientGetErr) QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
    return &osvdev.BatchedResponse{Results: []osvdev.MinimalResponse{{Vulns: []osvdev.MinimalVulnerability{{ID: "V-2"}}}}}, nil
}
func (f *fakeOSVClientGetErr) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) { return nil, errors.New("get-failed") }

func Test_QueryOSVBatch_getvuln_error(t *testing.T) {
    client := &fakeOSVClientGetErr{}
    vulns, err := QueryOSVBatch(context.Background(), client, []PkgInput{{Name: "n", Version: "1", IsDirect: true}})
    if err != nil { t.Fatalf("unexpected error: %v", err) }
    if len(vulns) != 0 { t.Fatalf("expected 0 vulns, got %d", len(vulns)) }
}

