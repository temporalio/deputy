package osv

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"osv.dev/bindings/go/osvdev"
)

type hydrateAliasClient struct {
	vulns map[string]*osvschema.Vulnerability
	calls []string
}

func (c *hydrateAliasClient) QueryBatch(context.Context, []*osvdev.Query) (*osvdev.BatchedResponse, error) {
	return nil, fmt.Errorf("unexpected QueryBatch")
}

func (c *hydrateAliasClient) GetVulnByID(_ context.Context, id string) (*osvschema.Vulnerability, error) {
	c.calls = append(c.calls, id)
	return c.vulns[id], nil
}

func TestHydrateSparseVulnerabilityAliases(t *testing.T) {
	publishedBase := time.Date(2024, 7, 2, 0, 0, 0, 0, time.UTC)
	modifiedAlias := time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC)
	client := &hydrateAliasClient{
		vulns: map[string]*osvschema.Vulnerability{
			"GO-2024-2961": {
				ID:        "GO-2024-2961",
				Aliases:   []string{"CVE-2022-30636"},
				Summary:   "Limited directory traversal vulnerability on Windows in golang.org/x/crypto",
				Details:   "Alias details",
				Modified:  modifiedAlias,
				Published: publishedBase.Add(-24 * time.Hour),
				Affected: []osvschema.Affected{
					{
						Package: osvschema.Package{
							Ecosystem: "Go",
							Name:      "golang.org/x/crypto",
						},
						Ranges: []osvschema.Range{
							{
								Type: osvschema.RangeSemVer,
								Events: []osvschema.Event{
									{Introduced: "0"},
									{Fixed: "0.0.0-20220525230936-793ad666bf5e"},
								},
							},
						},
					},
				},
				References: []osvschema.Reference{
					{Type: osvschema.ReferenceReport, URL: "https://go.dev/issue/53082"},
					{Type: osvschema.ReferenceWeb, URL: "https://pkg.go.dev/vuln/GO-2024-2961"},
				},
			},
		},
	}
	base := &osvschema.Vulnerability{
		ID:        "CVE-2022-30636",
		Aliases:   []string{"GO-2024-2961"},
		Details:   "CVE details",
		Published: publishedBase,
		References: []osvschema.Reference{
			{Type: osvschema.ReferenceWeb, URL: "https://go.dev/issue/53082"},
		},
	}

	got := HydrateSparseVulnerabilityAliases(t.Context(), client, base)
	if got == base {
		t.Fatal("expected hydrated vulnerability copy, got original pointer")
	}
	if got.ID != "CVE-2022-30636" {
		t.Fatalf("ID = %q, want CVE-2022-30636", got.ID)
	}
	if got.Summary == "" {
		t.Fatal("expected summary to be filled from alias")
	}
	if got.Details != "CVE details" {
		t.Fatalf("details = %q, want base details preserved", got.Details)
	}
	if got.Published != publishedBase.Add(-24*time.Hour) {
		t.Fatalf("published = %s, want earliest alias publication", got.Published)
	}
	if got.Modified != modifiedAlias {
		t.Fatalf("modified = %s, want latest alias modification", got.Modified)
	}
	if !slices.Equal(got.Aliases, []string{"GO-2024-2961"}) {
		t.Fatalf("aliases = %v, want GO alias without self-alias", got.Aliases)
	}
	if len(got.Affected) != 1 {
		t.Fatalf("affected = %d, want 1", len(got.Affected))
	}
	if got.Affected[0].Package.Name != "golang.org/x/crypto" {
		t.Fatalf("affected package = %q, want golang.org/x/crypto", got.Affected[0].Package.Name)
	}
	if got.Affected[0].Ranges[0].Events[1].Fixed != "0.0.0-20220525230936-793ad666bf5e" {
		t.Fatalf("fixed version = %q", got.Affected[0].Ranges[0].Events[1].Fixed)
	}
	if len(got.References) != 2 ||
		got.References[0].URL != "https://go.dev/issue/53082" ||
		got.References[1].URL != "https://pkg.go.dev/vuln/GO-2024-2961" {
		t.Fatalf("references = %#v, want base then alias references", got.References)
	}
	if !slices.Equal(client.calls, []string{"GO-2024-2961"}) {
		t.Fatalf("alias calls = %v, want GO lookup", client.calls)
	}
}

func TestHydrateSparseVulnerabilityAliasesSkipsCompleteRecords(t *testing.T) {
	client := &hydrateAliasClient{}
	base := &osvschema.Vulnerability{
		ID:      "GO-2024-2961",
		Summary: "complete",
		Affected: []osvschema.Affected{
			{Package: osvschema.Package{Name: "golang.org/x/crypto"}},
		},
		Aliases: []string{"CVE-2022-30636"},
	}

	got := HydrateSparseVulnerabilityAliases(t.Context(), client, base)
	if got != base {
		t.Fatal("complete vulnerability should be returned unchanged")
	}
	if len(client.calls) != 0 {
		t.Fatalf("alias calls = %v, want none", client.calls)
	}
}
