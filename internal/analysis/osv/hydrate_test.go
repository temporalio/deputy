package osv

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"osv.dev/bindings/go/api"
)

type hydrateAliasClient struct {
	vulns map[string]*osvschema.Vulnerability
	calls []string
}

func (c *hydrateAliasClient) QueryBatch(context.Context, []*api.Query) (*api.BatchVulnerabilityList, error) {
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
				Id:        "GO-2024-2961",
				Aliases:   []string{"CVE-2022-30636"},
				Summary:   "Limited directory traversal vulnerability on Windows in golang.org/x/crypto",
				Details:   "Alias details",
				Modified:  timestamppb.New(modifiedAlias),
				Published: timestamppb.New(publishedBase.Add(-24 * time.Hour)),
				Affected: []*osvschema.Affected{
					{
						Package: &osvschema.Package{
							Ecosystem: "Go",
							Name:      "golang.org/x/crypto",
						},
						Ranges: []*osvschema.Range{
							{
								Type: osvschema.Range_SEMVER,
								Events: []*osvschema.Event{
									{Introduced: "0"},
									{Fixed: "0.0.0-20220525230936-793ad666bf5e"},
								},
							},
						},
					},
				},
				References: []*osvschema.Reference{
					{Type: osvschema.Reference_REPORT, Url: "https://go.dev/issue/53082"},
					{Type: osvschema.Reference_WEB, Url: "https://pkg.go.dev/vuln/GO-2024-2961"},
				},
			},
		},
	}
	base := &osvschema.Vulnerability{
		Id:        "CVE-2022-30636",
		Aliases:   []string{"GO-2024-2961"},
		Details:   "CVE details",
		Published: timestamppb.New(publishedBase),
		References: []*osvschema.Reference{
			{Type: osvschema.Reference_WEB, Url: "https://go.dev/issue/53082"},
		},
	}

	got := HydrateSparseVulnerabilityAliases(t.Context(), client, base)
	if got == base {
		t.Fatal("expected hydrated vulnerability copy, got original pointer")
	}
	if got.GetId() != "CVE-2022-30636" {
		t.Fatalf("ID = %q, want CVE-2022-30636", got.GetId())
	}
	if got.Summary == "" {
		t.Fatal("expected summary to be filled from alias")
	}
	if got.Details != "CVE details" {
		t.Fatalf("details = %q, want base details preserved", got.Details)
	}
	if !got.GetPublished().AsTime().Equal(publishedBase.Add(-24 * time.Hour)) {
		t.Fatalf("published = %s, want earliest alias publication", got.GetPublished().AsTime())
	}
	if !got.GetModified().AsTime().Equal(modifiedAlias) {
		t.Fatalf("modified = %s, want latest alias modification", got.GetModified().AsTime())
	}
	if !slices.Equal(got.Aliases, []string{"GO-2024-2961"}) {
		t.Fatalf("aliases = %v, want GO alias without self-alias", got.Aliases)
	}
	if len(got.Affected) != 1 {
		t.Fatalf("affected = %d, want 1", len(got.Affected))
	}
	if got.GetAffected()[0].GetPackage().GetName() != "golang.org/x/crypto" {
		t.Fatalf("affected package = %q, want golang.org/x/crypto", got.GetAffected()[0].GetPackage().GetName())
	}
	if got.GetAffected()[0].GetRanges()[0].GetEvents()[1].GetFixed() != "0.0.0-20220525230936-793ad666bf5e" {
		t.Fatalf("fixed version = %q", got.GetAffected()[0].GetRanges()[0].GetEvents()[1].GetFixed())
	}
	if len(got.GetReferences()) != 2 ||
		got.GetReferences()[0].GetUrl() != "https://go.dev/issue/53082" ||
		got.GetReferences()[1].GetUrl() != "https://pkg.go.dev/vuln/GO-2024-2961" {
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
				Id:        "GHSA-with-draw-n1",
				Summary:   "Withdrawn duplicate advisory",
				Withdrawn: timestamppb.New(withdrawn),
			},
		},
	}
	base := &osvschema.Vulnerability{
		Id:      "CVE-2025-0001",
		Aliases: []string{"GHSA-with-draw-n1"},
	}

	got := HydrateSparseVulnerabilityAliases(t.Context(), client, base)
	if got.GetWithdrawn() != nil {
		t.Fatalf("withdrawn = %s, want absent: alias withdrawal must not mark the base record withdrawn", got.GetWithdrawn().AsTime())
	}
	if got.Summary == "" {
		t.Fatal("expected summary still filled from alias")
	}
}

func TestHydrateSparseVulnerabilityAliasesSkipsCompleteRecords(t *testing.T) {
	client := &hydrateAliasClient{}
	base := &osvschema.Vulnerability{
		Id:      "GO-2024-2961",
		Summary: "complete",
		Affected: []*osvschema.Affected{
			{Package: &osvschema.Package{Name: "golang.org/x/crypto"}},
		},
		Aliases: []string{"CVE-2022-30636"},
		Severity: []*osvschema.Severity{
			{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"},
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
		Id:      "GO-2025-3563",
		Summary: "Request smuggling in net/http",
		Affected: []*osvschema.Affected{
			{Package: &osvschema.Package{Name: "stdlib"}},
		},
	}
	if !NeedsVulnerabilityAliasHydration(unrated) {
		t.Error("unrated record should hydrate")
	}
	unrated.DatabaseSpecific = osvStruct(map[string]any{"severity": "CRITICAL"})
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
			"CVE-2025-22871": {Id: "CVE-2025-22871"},
			"GHSA-g9pc-8g42-g6vq": {
				Id:       "GHSA-g9pc-8g42-g6vq",
				Severity: []*osvschema.Severity{{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}},
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
		vulns: map[string]*osvschema.Vulnerability{"CVE-1": {Id: "CVE-1"}},
	}, []string{"CVE-1"})
	if raw != "" || rawType != "" {
		t.Fatalf("unrated aliases resolved (%q, %q), want empty", raw, rawType)
	}
}

// TestMergeOSVVulnerabilityAbsentDates pins how hydration treats an undated
// record. An absent timestamp is nil, so it must neither overwrite a dated base
// nor be scored as the Unix epoch, which would always win the
// earliest-published comparison and backdate the merged advisory.
func TestMergeOSVVulnerabilityAbsentDates(t *testing.T) {
	basePublished := timestamppb.New(time.Date(2024, 7, 2, 0, 0, 0, 0, time.UTC))
	baseModified := timestamppb.New(time.Date(2024, 8, 2, 0, 0, 0, 0, time.UTC))

	t.Run("undated alias leaves base dates alone", func(t *testing.T) {
		base := &osvschema.Vulnerability{Id: "CVE-1", Published: basePublished, Modified: baseModified}
		mergeOSVVulnerability(base, &osvschema.Vulnerability{Id: "GHSA-1"})
		if !base.GetPublished().AsTime().Equal(basePublished.AsTime()) {
			t.Errorf("published = %s, want %s", base.GetPublished().AsTime(), basePublished.AsTime())
		}
		if !base.GetModified().AsTime().Equal(baseModified.AsTime()) {
			t.Errorf("modified = %s, want %s", base.GetModified().AsTime(), baseModified.AsTime())
		}
	})

	t.Run("dated alias fills an undated base", func(t *testing.T) {
		base := &osvschema.Vulnerability{Id: "CVE-1"}
		mergeOSVVulnerability(base, &osvschema.Vulnerability{Id: "GHSA-1", Published: basePublished, Modified: baseModified})
		if !base.GetPublished().AsTime().Equal(basePublished.AsTime()) {
			t.Errorf("published = %s, want %s", base.GetPublished().AsTime(), basePublished.AsTime())
		}
		if !base.GetModified().AsTime().Equal(baseModified.AsTime()) {
			t.Errorf("modified = %s, want %s", base.GetModified().AsTime(), baseModified.AsTime())
		}
	})
}

// TestHydrateDoesNotMutateAliasSource pins the ownership invariant the pointer
// migration made newly breakable: alias records come from a shared cache, so
// hydration must clone every message it keeps rather than splicing the donor's
// pointers into the merged advisory. Otherwise a second, unrelated hydration of
// the same alias would observe the first one's edits.
func TestHydrateDoesNotMutateAliasSource(t *testing.T) {
	alias := &osvschema.Vulnerability{
		Id:      "GO-2024-2961",
		Summary: "Alias summary",
		Affected: []*osvschema.Affected{
			{Package: &osvschema.Package{Ecosystem: "Go", Name: "golang.org/x/crypto"}},
		},
		References:       []*osvschema.Reference{{Type: osvschema.Reference_WEB, Url: "https://example.test/a"}},
		DatabaseSpecific: osvStruct(map[string]any{"severity": "HIGH"}),
	}
	want := proto.CloneOf(alias)
	client := &hydrateAliasClient{vulns: map[string]*osvschema.Vulnerability{"GO-2024-2961": alias}}

	got := HydrateSparseVulnerabilityAliases(t.Context(), client, &osvschema.Vulnerability{
		Id:      "CVE-2022-30636",
		Aliases: []string{"GO-2024-2961"},
	})

	// Mutating the merged record must not reach back into the cached alias.
	got.GetAffected()[0].GetPackage().Name = "mutated"
	got.GetReferences()[0].Url = "https://example.test/mutated"
	got.GetDatabaseSpecific().GetFields()["severity"] = structpb.NewStringValue("LOW")

	if !proto.Equal(want, alias) {
		t.Errorf("alias record was mutated by hydration:\n got: %v\nwant: %v", alias, want)
	}
}
