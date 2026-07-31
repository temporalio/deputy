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

// TestHydrateDoesNotCopyAliasWithdrawal guards against hydration marking a
// live advisory withdrawn: GHSAs are commonly withdrawn as duplicates while
// the CVE they alias remains active, so an alias's Withdrawn timestamp must
// never fill onto the base record.
func TestHydrateDoesNotCopyAliasWithdrawal(t *testing.T) {
	withdrawn := time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)
	client := &hydrateAliasClient{
		vulns: map[string]*osvschema.Vulnerability{
			"GHSA-with-draw-n1": {
				ID:        "GHSA-with-draw-n1",
				Summary:   "Withdrawn duplicate advisory",
				Withdrawn: withdrawn,
			},
		},
	}
	base := &osvschema.Vulnerability{
		ID:      "CVE-2025-0001",
		Aliases: []string{"GHSA-with-draw-n1"},
	}

	got := HydrateSparseVulnerabilityAliases(t.Context(), client, base)
	if !got.Withdrawn.IsZero() {
		t.Fatalf("withdrawn = %s, want zero: alias withdrawal must not mark the base record withdrawn", got.Withdrawn)
	}
	if got.Summary == "" {
		t.Fatal("expected summary still filled from alias")
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
		Severity: []osvschema.Severity{
			{Type: "CVSS_V3", Score: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"},
		},
	}

	got := HydrateSparseVulnerabilityAliases(t.Context(), client, base)
	if got != base {
		t.Fatal("complete vulnerability should be returned unchanged")
	}
	if len(client.calls) != 0 {
		t.Fatalf("alias calls = %v, want none", client.calls)
	}
}

// TestNeedsVulnerabilityAliasHydrationOnMissingSeverity pins the trigger that
// makes single-advisory lookups severity-complete: a record with summary and
// affected packages but no rating still hydrates, because alias records (a GO
// advisory's GHSA alias) commonly carry the rating.
func TestNeedsVulnerabilityAliasHydrationOnMissingSeverity(t *testing.T) {
	unrated := &osvschema.Vulnerability{
		ID:      "GO-2025-3563",
		Summary: "Request smuggling in net/http",
		Affected: []osvschema.Affected{
			{Package: osvschema.Package{Name: "stdlib"}},
		},
	}
	if !NeedsVulnerabilityAliasHydration(unrated) {
		t.Error("unrated record should hydrate")
	}
	unrated.DatabaseSpecific = map[string]any{"severity": "CRITICAL"}
	if NeedsVulnerabilityAliasHydration(unrated) {
		t.Error("database_specific severity counts as a rating")
	}
}

// TestSeverityAliasOrder pins the deterministic consult order for severity
// resolution: GHSA first, then CVE, then the rest, alphabetical within class.
func TestSeverityAliasOrder(t *testing.T) {
	got := SeverityAliasOrder([]string{
		"BIT-golang-2025-22871", "CVE-2025-22871", "GHSA-g9pc-8g42-g6vq", "cve-2020-0001", "GHSA-a", "GHSA-a",
	})
	want := []string{"GHSA-a", "GHSA-g9pc-8g42-g6vq", "CVE-2025-22871", "cve-2020-0001", "BIT-golang-2025-22871"}
	if !slices.Equal(got, want) {
		t.Errorf("SeverityAliasOrder = %v, want %v", got, want)
	}
}

// TestResolveSeverityFromAliases verifies the first rated alias record wins
// and unrated alias sets resolve to nothing.
func TestResolveSeverityFromAliases(t *testing.T) {
	client := &hydrateAliasClient{
		vulns: map[string]*osvschema.Vulnerability{
			"CVE-2025-22871": {ID: "CVE-2025-22871"},
			"GHSA-g9pc-8g42-g6vq": {
				ID:       "GHSA-g9pc-8g42-g6vq",
				Severity: []osvschema.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}},
			},
		},
	}

	raw, rawType := ResolveSeverityFromAliases(t.Context(), client, []string{"CVE-2025-22871", "GHSA-g9pc-8g42-g6vq"})
	if raw == "" || rawType != "CVSS_V3" {
		t.Fatalf("resolved (%q, %q), want the GHSA record's CVSS_V3 rating", raw, rawType)
	}
	if len(client.calls) == 0 || client.calls[0] != "GHSA-g9pc-8g42-g6vq" {
		t.Fatalf("consult order %v, want GHSA first", client.calls)
	}

	raw, rawType = ResolveSeverityFromAliases(t.Context(), &hydrateAliasClient{
		vulns: map[string]*osvschema.Vulnerability{"CVE-1": {ID: "CVE-1"}},
	}, []string{"CVE-1"})
	if raw != "" || rawType != "" {
		t.Fatalf("unrated aliases resolved (%q, %q), want empty", raw, rawType)
	}
}
