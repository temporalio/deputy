package main

import (
	"context"
	"errors"
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"osv.dev/bindings/go/osvdev"
)

type fakeOSVClient struct{}

func (f *fakeOSVClient) QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
	// Return a single result with one minimal vuln
	resp := &osvdev.BatchedResponse{
		Results: []osvdev.MinimalResponse{{Vulns: []osvdev.MinimalVulnerability{{ID: "V-1"}}}},
	}
	return resp, nil
}

func (f *fakeOSVClient) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
	v := &osvschema.Vulnerability{ID: id, Summary: "sum", Details: "det", Aliases: []string{"CVE-1"}}
	return v, nil
}

func Test_queryOSVBatch_with_fake_client(t *testing.T) {
	client := &fakeOSVClient{}

	pkgs := []PackageChange{{Name: "github.com/example/pkg", TargetVersion: "1.2.3", ChangeType: Updated, IsDirect: true}}

	vulns, err := queryOSVBatch(t.Context(), client, pkgs)
	if err != nil {
		t.Fatalf("queryOSVBatch error: %v", err)
	}

	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}
	if vulns[0].CVE != "CVE-1" {
		t.Fatalf("expected CVE-1, got %q", vulns[0].CVE)
	}
}

// Negative tests
type fakeOSVClientQueryErr struct{}

func (f *fakeOSVClientQueryErr) QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
	return nil, errors.New("query-failed")
}

func (f *fakeOSVClientQueryErr) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
	return nil, nil
}

func Test_queryOSVBatch_query_error(t *testing.T) {
	client := &fakeOSVClientQueryErr{}
	pkgs := []PackageChange{{Name: "github.com/example/pkg", TargetVersion: "1.2.3", ChangeType: Updated, IsDirect: true}}
	_, err := queryOSVBatch(t.Context(), client, pkgs)
	if err == nil {
		t.Fatalf("expected error from QueryBatch, got nil")
	}
}

type fakeOSVClientGetErr struct{}

func (f *fakeOSVClientGetErr) QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
	return &osvdev.BatchedResponse{Results: []osvdev.MinimalResponse{{Vulns: []osvdev.MinimalVulnerability{{ID: "V-2"}}}}}, nil
}

func (f *fakeOSVClientGetErr) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
	return nil, errors.New("get-failed")
}

func Test_queryOSVBatch_getvuln_error_is_logged_but_continues(t *testing.T) {
	client := &fakeOSVClientGetErr{}
	pkgs := []PackageChange{{Name: "github.com/example/pkg", TargetVersion: "1.2.3", ChangeType: Updated, IsDirect: true}}
	vulns, err := queryOSVBatch(t.Context(), client, pkgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// since GetVulnByID failed, we expect zero processed vulnerabilities
	if len(vulns) != 0 {
		t.Fatalf("expected 0 vulns, got %d", len(vulns))
	}
}

type fakeOSVClientEmpty struct{}

func (f *fakeOSVClientEmpty) QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
	return &osvdev.BatchedResponse{Results: []osvdev.MinimalResponse{{Vulns: nil}}}, nil
}

func (f *fakeOSVClientEmpty) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
	return nil, nil
}

func Test_queryOSVBatch_empty_results(t *testing.T) {
	client := &fakeOSVClientEmpty{}
	pkgs := []PackageChange{{Name: "github.com/example/pkg", TargetVersion: "1.2.3", ChangeType: Updated, IsDirect: true}}
	vulns, err := queryOSVBatch(t.Context(), client, pkgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 0 {
		t.Fatalf("expected 0 vulns, got %d", len(vulns))
	}
}
