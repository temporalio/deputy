package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/temporalio/deputy/internal/explain"
)

func TestExplainRenderer_Text(t *testing.T) {
	ctx := t.Context()

	t.Run("renders basic vulnerability", func(t *testing.T) {
		out := &bytes.Buffer{}
		vuln := &osvschema.Vulnerability{
			ID:      "CVE-2021-44228",
			Summary: "Log4j remote code execution",
			Aliases: []string{"GHSA-jfh8-c2jp-5v3q"},
		}

		renderer := explain.NewRenderer(explain.Config{})
		if err := renderer.Render(ctx, out, vuln); err != nil {
			t.Fatalf("Render failed: %v", err)
		}
		output := out.String()

		if !strings.Contains(output, "CVE-2021-44228") {
			t.Error("output should contain vulnerability ID")
		}
		if !strings.Contains(output, "Log4j remote code execution") {
			t.Error("output should contain summary")
		}
		if !strings.Contains(output, "GHSA-jfh8-c2jp-5v3q") {
			t.Error("output should contain alias")
		}
	})

	t.Run("renders affected packages", func(t *testing.T) {
		out := &bytes.Buffer{}
		vuln := &osvschema.Vulnerability{
			ID:      "TEST-001",
			Summary: "Test vulnerability",
			Affected: []osvschema.Affected{
				{
					Package: osvschema.Package{
						Name:      "lodash",
						Ecosystem: "npm",
					},
					Ranges: []osvschema.Range{
						{
							Events: []osvschema.Event{
								{Introduced: "0"},
								{Fixed: "4.17.21"},
							},
						},
					},
				},
			},
		}

		renderer := explain.NewRenderer(explain.Config{})
		if err := renderer.Render(ctx, out, vuln); err != nil {
			t.Fatalf("Render failed: %v", err)
		}
		output := out.String()

		if !strings.Contains(output, "lodash") {
			t.Error("output should contain package name")
		}
		if !strings.Contains(output, "npm") {
			t.Error("output should contain ecosystem")
		}
		if !strings.Contains(output, "4.17.21") {
			t.Error("output should contain fixed version")
		}
	})

	t.Run("handles nil vulnerability", func(t *testing.T) {
		out := &bytes.Buffer{}
		renderer := explain.NewRenderer(explain.Config{})
		if err := renderer.Render(ctx, out, nil); err != nil {
			t.Fatalf("Render failed: %v", err)
		}
		if out.Len() != 0 {
			t.Error("expected no output for nil vulnerability")
		}
	})

	t.Run("includes details and references", func(t *testing.T) {
		out := &bytes.Buffer{}
		vuln := &osvschema.Vulnerability{
			ID:      "TEST-002",
			Summary: "Test vulnerability",
			Details: "This is a detailed description of the vulnerability.",
			References: []osvschema.Reference{
				{URL: "https://example.com/advisory"},
			},
		}

		renderer := explain.NewRenderer(explain.Config{})
		if err := renderer.Render(ctx, out, vuln); err != nil {
			t.Fatalf("Render failed: %v", err)
		}
		output := out.String()

		if !strings.Contains(output, "detailed description") {
			t.Error("output should contain details")
		}
		if !strings.Contains(output, "https://example.com/advisory") {
			t.Error("output should contain references")
		}
	})

	t.Run("renders dates when provided", func(t *testing.T) {
		out := &bytes.Buffer{}
		published := time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC)
		modified := time.Date(2022, 1, 15, 0, 0, 0, 0, time.UTC)

		vuln := &osvschema.Vulnerability{
			ID:        "TEST-003",
			Summary:   "Test vulnerability",
			Published: published,
			Modified:  modified,
		}

		renderer := explain.NewRenderer(explain.Config{})
		if err := renderer.Render(ctx, out, vuln); err != nil {
			t.Fatalf("Render failed: %v", err)
		}
		output := out.String()

		if !strings.Contains(output, "2021-12-10") {
			t.Error("output should contain published date")
		}
		if !strings.Contains(output, "2022-01-15") {
			t.Error("output should contain modified date")
		}
	})

	t.Run("renders quick links for CVE", func(t *testing.T) {
		out := &bytes.Buffer{}
		vuln := &osvschema.Vulnerability{
			ID:      "CVE-2021-44228",
			Summary: "Test vulnerability",
		}

		renderer := explain.NewRenderer(explain.Config{})
		if err := renderer.Render(ctx, out, vuln); err != nil {
			t.Fatalf("Render failed: %v", err)
		}
		output := out.String()

		if !strings.Contains(output, "Quick Links") {
			t.Error("output should contain Quick Links section")
		}
		if !strings.Contains(output, "osv.dev/vulnerability/CVE-2021-44228") {
			t.Error("output should contain OSV link")
		}
		if !strings.Contains(output, "nvd.nist.gov/vuln/detail/CVE-2021-44228") {
			t.Error("output should contain NVD link")
		}
	})

	t.Run("renders quick links for Go vulnerability", func(t *testing.T) {
		out := &bytes.Buffer{}
		vuln := &osvschema.Vulnerability{
			ID:      "GO-2024-2687",
			Summary: "Test Go vulnerability",
			Aliases: []string{"CVE-2023-45288"},
		}

		renderer := explain.NewRenderer(explain.Config{})
		if err := renderer.Render(ctx, out, vuln); err != nil {
			t.Fatalf("Render failed: %v", err)
		}
		output := out.String()

		if !strings.Contains(output, "pkg.go.dev/vuln/GO-2024-2687") {
			t.Error("output should contain Go vulnerability database link")
		}
		if !strings.Contains(output, "nvd.nist.gov/vuln/detail/CVE-2023-45288") {
			t.Error("output should contain NVD link for aliased CVE")
		}
	})
}

func TestExplainRenderer_JSON(t *testing.T) {
	ctx := t.Context()

	t.Run("renders valid JSON with core fields", func(t *testing.T) {
		out := &bytes.Buffer{}
		vuln := &osvschema.Vulnerability{
			ID:      "CVE-2021-44228",
			Summary: "Log4j remote code execution",
			Aliases: []string{"GHSA-jfh8-c2jp-5v3q"},
			Affected: []osvschema.Affected{
				{
					Package: osvschema.Package{
						Name:      "org.apache.logging.log4j:log4j-core",
						Ecosystem: "Maven",
					},
					Ranges: []osvschema.Range{
						{
							Events: []osvschema.Event{
								{Fixed: "2.15.0"},
							},
						},
					},
				},
			},
		}

		renderer := explain.NewRenderer(explain.Config{})
		if err := renderer.RenderJSON(ctx, out, vuln); err != nil {
			t.Fatalf("RenderJSON failed: %v", err)
		}
		output := out.String()

		// Check JSON contains expected fields
		if !strings.Contains(output, `"id": "CVE-2021-44228"`) {
			t.Error("JSON should contain id")
		}
		if !strings.Contains(output, `"summary": "Log4j remote code execution"`) {
			t.Error("JSON should contain summary")
		}
		if !strings.Contains(output, `"aliases"`) {
			t.Error("JSON should contain aliases")
		}
		if !strings.Contains(output, `"affected"`) {
			t.Error("JSON should contain affected")
		}
	})

	t.Run("includes remediation info for affected packages", func(t *testing.T) {
		out := &bytes.Buffer{}
		vuln := &osvschema.Vulnerability{
			ID:      "TEST-JSON-001",
			Summary: "Test vulnerability",
			Affected: []osvschema.Affected{
				{
					Package: osvschema.Package{
						Name:      "lodash",
						Ecosystem: "npm",
					},
					Ranges: []osvschema.Range{
						{
							Events: []osvschema.Event{
								{Introduced: "0"},
								{Fixed: "4.17.21"},
							},
						},
					},
				},
			},
		}

		renderer := explain.NewRenderer(explain.Config{})
		if err := renderer.RenderJSON(ctx, out, vuln); err != nil {
			t.Fatalf("RenderJSON failed: %v", err)
		}
		output := out.String()

		if !strings.Contains(output, `"fixed_versions"`) {
			t.Error("JSON should contain fixed_versions array")
		}
		if !strings.Contains(output, `"4.17.21"`) {
			t.Error("JSON should contain the fixed version")
		}
		if !strings.Contains(output, `"remediation"`) {
			t.Error("JSON should contain remediation guidance")
		}
		if !strings.Contains(output, `Upgrade to 4.17.21 or later`) {
			t.Error("JSON remediation should suggest upgrade")
		}
	})

	t.Run("includes links for CVE IDs", func(t *testing.T) {
		out := &bytes.Buffer{}
		vuln := &osvschema.Vulnerability{
			ID:      "CVE-2023-12345",
			Summary: "Test CVE",
		}

		renderer := explain.NewRenderer(explain.Config{})
		if err := renderer.RenderJSON(ctx, out, vuln); err != nil {
			t.Fatalf("RenderJSON failed: %v", err)
		}
		output := out.String()

		if !strings.Contains(output, `"links"`) {
			t.Error("JSON should contain links section")
		}
		if !strings.Contains(output, `"nvd"`) {
			t.Error("JSON should contain NVD link for CVE")
		}
		if !strings.Contains(output, `nvd.nist.gov`) {
			t.Error("JSON should contain NVD URL")
		}
	})

	t.Run("includes links for GHSA IDs", func(t *testing.T) {
		out := &bytes.Buffer{}
		vuln := &osvschema.Vulnerability{
			ID:      "GHSA-abcd-1234-efgh",
			Summary: "Test GHSA",
		}

		renderer := explain.NewRenderer(explain.Config{})
		if err := renderer.RenderJSON(ctx, out, vuln); err != nil {
			t.Fatalf("RenderJSON failed: %v", err)
		}
		output := out.String()

		if !strings.Contains(output, `"github_advisory"`) {
			t.Error("JSON should contain github_advisory link for GHSA")
		}
		if !strings.Contains(output, `github.com/advisories`) {
			t.Error("JSON should contain GitHub advisories URL")
		}
	})

	t.Run("includes links for Go vulnerability IDs", func(t *testing.T) {
		out := &bytes.Buffer{}
		vuln := &osvschema.Vulnerability{
			ID:      "GO-2023-1234",
			Summary: "Test Go vuln",
		}

		renderer := explain.NewRenderer(explain.Config{})
		if err := renderer.RenderJSON(ctx, out, vuln); err != nil {
			t.Fatalf("RenderJSON failed: %v", err)
		}
		output := out.String()

		if !strings.Contains(output, `"go_vuln"`) {
			t.Error("JSON should contain go_vuln link for GO- IDs")
		}
		if !strings.Contains(output, `pkg.go.dev/vuln`) {
			t.Error("JSON should contain Go vulnerability database URL")
		}
	})

	t.Run("includes timeline with human-readable age", func(t *testing.T) {
		out := &bytes.Buffer{}
		published := time.Now().Add(-365 * 24 * time.Hour) // 1 year ago

		vuln := &osvschema.Vulnerability{
			ID:        "TEST-JSON-002",
			Summary:   "Test vulnerability",
			Published: published,
		}

		renderer := explain.NewRenderer(explain.Config{})
		if err := renderer.RenderJSON(ctx, out, vuln); err != nil {
			t.Fatalf("RenderJSON failed: %v", err)
		}
		output := out.String()

		if !strings.Contains(output, `"age_human"`) {
			t.Error("JSON should contain age_human field")
		}
		if !strings.Contains(output, `"age_days"`) {
			t.Error("JSON should contain age_days field")
		}
	})

	t.Run("handles package without fix", func(t *testing.T) {
		out := &bytes.Buffer{}
		vuln := &osvschema.Vulnerability{
			ID:      "TEST-JSON-003",
			Summary: "No fix available",
			Affected: []osvschema.Affected{
				{
					Package: osvschema.Package{
						Name:      "vulnerable-pkg",
						Ecosystem: "npm",
					},
					Ranges: []osvschema.Range{
						{
							Events: []osvschema.Event{
								{Introduced: "0"},
							},
						},
					},
				},
			},
		}

		renderer := explain.NewRenderer(explain.Config{})
		if err := renderer.RenderJSON(ctx, out, vuln); err != nil {
			t.Fatalf("RenderJSON failed: %v", err)
		}
		output := out.String()

		if !strings.Contains(output, `"remediation"`) {
			t.Error("JSON should contain remediation even without fix")
		}
		if !strings.Contains(output, `No fix available`) {
			t.Error("JSON should indicate no fix is available")
		}
	})

	t.Run("includes attack characteristics for CVSS vector", func(t *testing.T) {
		out := &bytes.Buffer{}
		vuln := &osvschema.Vulnerability{
			ID:      "CVE-2021-44228",
			Summary: "Test vulnerability with CVSS",
			Severity: []osvschema.Severity{
				{
					Type:  osvschema.SeverityCVSSV3,
					Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
				},
			},
		}

		renderer := explain.NewRenderer(explain.Config{})
		if err := renderer.RenderJSON(ctx, out, vuln); err != nil {
			t.Fatalf("RenderJSON failed: %v", err)
		}
		output := out.String()

		if !strings.Contains(output, `"attack_surface"`) {
			t.Error("JSON should contain attack_surface")
		}
		if !strings.Contains(output, `"attack_characteristics"`) {
			t.Error("JSON should contain attack_characteristics")
		}
		if !strings.Contains(output, `"remote_exploitable"`) {
			t.Error("JSON should contain remote_exploitable field")
		}
		if !strings.Contains(output, `"authentication_required"`) {
			t.Error("JSON should contain authentication_required field")
		}
	})
}

func TestExplainHelpers(t *testing.T) {
	t.Run("FormatAge formats durations correctly", func(t *testing.T) {
		tests := []struct {
			duration time.Duration
			expected string
		}{
			{24 * time.Hour, "1 day"},
			{48 * time.Hour, "2 days"},
			{7 * 24 * time.Hour, "1 week"},
			{30 * 24 * time.Hour, "1 month"},
			{365 * 24 * time.Hour, "1 year"},
		}

		for _, tt := range tests {
			result := explain.FormatAge(tt.duration)
			if result != tt.expected {
				t.Errorf("FormatAge(%v) = %q, want %q", tt.duration, result, tt.expected)
			}
		}
	})

	t.Run("TemporalInfo provides age calculations", func(t *testing.T) {
		info := explain.TemporalInfo{
			Published: time.Now().Add(-30 * 24 * time.Hour),
			Modified:  time.Now().Add(-7 * 24 * time.Hour),
		}

		days := info.DaysSincePublished()
		if days < 29 || days > 31 {
			t.Errorf("DaysSincePublished() = %d, want ~30", days)
		}

		age := info.Age()
		if age < 29*24*time.Hour || age > 31*24*time.Hour {
			t.Errorf("Age() = %v, want ~30 days", age)
		}
	})
}
