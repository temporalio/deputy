package main

import (
    "bytes"
    "context"
    "encoding/json"
    "testing"

    "github.com/google/osv-scalibr/extractor"
    "github.com/ossf/osv-schema/bindings/go/osvschema"
    "osv.dev/bindings/go/osvdev"
)

// fake OSV client for tests
type fakeScanOSVClient struct{}

func (f *fakeScanOSVClient) QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
    // Return one vulnerability for the first package only
    res := &osvdev.BatchedResponse{Results: make([]osvdev.MinimalResponse, len(queries))}
    if len(queries) > 0 {
        res.Results[0] = osvdev.MinimalResponse{Vulns: []osvdev.MinimalVulnerability{{ID: "GHSA-TEST-1"}}}
    }
    return res, nil
}

func (f *fakeScanOSVClient) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
    v := &osvschema.Vulnerability{ID: id, Summary: "sum", Details: "det", Aliases: []string{"CVE-TEST-1"}}
    return v, nil
}

func Test_buildScanReport_JSON(t *testing.T) {
    // Stub inventory
    orig := collectInventoryForScan
    collectInventoryForScan = func(ctx context.Context, repoPath, gitRef string, ecos []string) ([]*extractor.Package, error) {
        return []*extractor.Package{
            {Name: "github.com/acme/lib", Version: "1.2.3"},
            {Name: "leftpad", Version: "0.1.0"},
        }, nil
    }
    defer func() { collectInventoryForScan = orig }()

    // Build changes, query OSV via fake, and produce JSON
    changes := []PackageChange{
        {Name: "github.com/acme/lib", TargetVersion: "1.2.3", ChangeType: Added},
        {Name: "leftpad", TargetVersion: "0.1.0", ChangeType: Added},
    }
    vulns, err := queryOSVBatch(context.Background(), &fakeScanOSVClient{}, changes)
    if err != nil {
        t.Fatalf("osv batch: %v", err)
    }
    rep := buildScanReport("/repo", "refs/tags/v1.0.0", "deadbee", vulns, 2)
    var buf bytes.Buffer
    if err := json.NewEncoder(&buf).Encode(rep); err != nil {
        t.Fatalf("encode: %v", err)
    }
    s := buf.String()
    if !bytes.Contains([]byte(s), []byte("\"vulnerabilities\"")) {
        t.Fatalf("missing vulnerabilities field: %s", s)
    }
    if !bytes.Contains([]byte(s), []byte("GHSA-TEST-1")) {
        t.Fatalf("missing GHSA id in output: %s", s)
    }
}
